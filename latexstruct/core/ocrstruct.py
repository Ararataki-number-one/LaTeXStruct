# -*- coding: utf-8 -*-
"""OCR 文档骨架元数据、规范化补丁与安全检查。

视觉模型只负责逐页转写。PDF 自带的书签属于可靠的版面元数据，因此在原始
OCR 书稿中以注释形式携带，结构化阶段再把它转换成可撤销的 LaTeX 补丁。
没有书签时保持保守：不会凭空臆造缺失标题。
"""

from __future__ import annotations

import base64
import difflib
import json
import math
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

from .parser import find_env_ranges, mask_comments, mask_inline_verb, mask_protected
from .patch import PendingOp

META_PREFIX = "% LaTeXStruct-OCR-Metadata: "
META_RE = re.compile(r"^% LaTeXStruct-OCR-Metadata:\s*([A-Za-z0-9_=-]+)\s*$", re.M)
EQUATION_TAG_LABEL_RE = re.compile(r"^[0-9]{1,4}[A-Za-z]?$")
EQUATION_TAG_EVIDENCE_STATUS = "source_geometry_and_active_match"
EQUATION_TAG_EVIDENCE_VERIFIER = "pdf_geometry_plus_full_page_visual_and_active_latex"
PAGE_RE = re.compile(r"^\s*%\s*Page\s+(\d+)\s*$", re.I)
PAGE_BREAK_RE = re.compile(r"^\s*%===\s*PAGE BREAK\s*===", re.I)
DOCUMENTCLASS_RE = re.compile(
    r"^\s*\\documentclass(?:\[[^\]]*\])?\s*\{([^{}]+)\}\s*$"
)
SECTION_RE = re.compile(
    r"^(?P<indent>\s*)\\(?P<cmd>chapter|section|subsection|subsubsection)"
    r"(?P<star>\*)?\s*\{"
)
STYLE_RE = re.compile(
    r"^(?P<indent>\s*)(?P<noindent>\\noindent\s*)?"
    r"\\(?P<style>textbf|textit|emph|textsc)\s*\{"
)
NUMBER_PREFIX_RE = re.compile(r"^\s*\d+(?:\.\d+)*\.?\s+")
CHAPTER_MARKER_RE = re.compile(r"^\s*chapter\s+(\d+)\s*$", re.I)
BARE_CHAPTER_MARKER_RE = re.compile(r"^\s*(\d+)\.?\s*$")
NUMBERED_CHAPTER_TITLE_RE = re.compile(
    r"^\s*(?P<number>\d+)\.?\s+(?P<title>\D\S*(?:\s+.*)?)\s*$"
)
PLAIN_NUMBERED_HEADING_RE = re.compile(
    r"^\s*(?P<title>\d+(?:\.\d+)+\.?\s+.+?[.!?])(?:\s+(?P<trailing>.+))?$"
)
FRONT_MATTER = {
    "abstract", "acknowledgements", "acknowledgments", "contents", "foreword",
    "introduction", "notation", "preface", "references", "bibliography",
}
OUTER_TEXT_ENVS = {
    "theorem", "theorem*", "lemma", "lemma*", "proposition", "proposition*",
    "corollary", "corollary*", "definition", "definition*", "remark", "remark*",
    "example", "example*", "exercise", "exercise*", "proof",
}
MATH_ENVS = {
    "equation", "equation*", "align", "align*", "gather", "gather*",
    "multline", "multline*", "flalign", "flalign*", "alignat", "alignat*",
    "eqnarray", "eqnarray*",
}
EXACT_ENV_LINE_RE = re.compile(
    r"^\s*\\(?P<kind>begin|end)\{(?P<name>[^{}\s]+)\}"
    r"(?:\s*\[[^\]\r\n]*\])?\s*$"
)
MATH_EVENT_RE = re.compile(
    r"\\(?P<delimiter>[\[\]])"
    r"|\\(?P<kind>begin|end)\{(?P<name>"
    + "|".join(re.escape(name) for name in sorted(MATH_ENVS, key=len, reverse=True))
    + r")\}"
)
ACTIVE_TOC_RE = re.compile(r"\\tableofcontents(?![A-Za-z@])")
LOCAL_TOC_MARKER = "% LaTeXStruct-Local-Contents"
RUNNING_HEADER_MAX_TOP_OFFSET = 3
RUNNING_HEADER_COMMAND_MAX_TOP_OFFSET = 8
MAX_OUTLINE_HEADING_SPAN_LINES = 3
GENERIC_OUTLINE_PLACEHOLDER_KEYS = frozenset({"heading", "bookmark"})
PRINTED_PAGE_MARKER_PREFIX = "% LaTeXStruct-Printed-Page: "
PRINTED_DOT_LEADER_RE = re.compile(r"(?:\.\s*){3,}")
EXERCISE_HEADING_RE = re.compile(
    r"^(?P<prefix>\s*(?:\\noindent\s*)?)(?P<title>Exercises?)\s*$",
    re.I,
)
FORMATTED_EXERCISE_HEADING_RE = re.compile(
    r"^\s*(?:\\noindent\s*)?"
    r"\\(?:textbf|section\*?|subsection\*?)\s*\{\s*Exercises?\s*\}\s*$",
    re.I,
)
EXERCISE_DIFFICULTY_PREFIX = (
    r"(?:(?:\\\(\s*\\(?:star|ast)\s*\\\)|\$\s*\\(?:star|ast)\s*\$|[★☆])\s*)?"
)
PLAIN_EXERCISE_LABEL_RE = re.compile(
    rf"^(?P<prefix>\s*(?:\\noindent\s*)?{EXERCISE_DIFFICULTY_PREFIX})"
    r"(?P<number>\d+\.\d+\.\d+)(?![\d.])(?P<suffix>.*)$"
)
FORMATTED_EXERCISE_LABEL_RE = re.compile(
    rf"^\s*(?:\\noindent\s*)?{EXERCISE_DIFFICULTY_PREFIX}"
    r"\\textbf\s*\{\s*(?P<number>\d+\.\d+\.\d+)\s*\}(?![\d.])"
)
BROKEN_EXERCISE_DIVIDER = r"\mathrel{))}"
CANONICAL_EXERCISE_DIVIDER = r"\mathrel{\wr\wr}"


@dataclass
class HeadingCandidate:
    line: int
    page: Optional[int]
    visible: str
    trailing: str
    kind: str
    command: str = ""
    starred: bool = False
    open_line: int = 0
    close_line: int = 0


def encode_ocr_metadata(
    outline: Iterable[dict] | None,
    document_kind: str,
    selected_pages: Iterable[int],
    source_has_toc: bool,
    *,
    equation_tag_evidence: Iterable[dict] | None = None,
) -> str:
    """生成单行、不会被 LaTeX 执行的 OCR 元数据注释。"""
    cleaned = []
    for item in list(outline or [])[:500]:
        try:
            level = max(0, min(5, int(item.get("level", 0))))
            page = max(1, int(item.get("page", 1)))
        except (TypeError, ValueError):
            continue
        title = str(item.get("title", "")).strip()[:300]
        if title:
            cleaned.append({"level": level, "title": title, "page": page})
    cleaned = _normalize_book_outline_levels(cleaned, document_kind)
    payload = {
        "version": 2 if equation_tag_evidence is not None else 1,
        "kind": "book" if document_kind == "book" else "article",
        "pages": sorted({int(p) for p in selected_pages if int(p) > 0})[:1000],
        "source_has_toc": bool(source_has_toc),
        "outline": cleaned,
    }
    if equation_tag_evidence is not None:
        payload["equation_tags"] = _clean_equation_tag_evidence(
            equation_tag_evidence,
            allowed_pages=set(payload["pages"]),
        )
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    token = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    return META_PREFIX + token


def _clean_equation_tag_evidence(
    values: Iterable[dict] | None,
    *,
    allowed_pages: set[int] | None = None,
) -> List[dict]:
    """Keep only bounded, independently verified PDF equation-tag evidence.

    A label alone is not source evidence.  Version-2 metadata therefore retains
    only records produced by the page-geometry plus full-page transcription
    integrity check, including a normalized source bounding box and a unique
    evidence id.  Invalid or duplicate records are discarded; the semantic
    stage treats any resulting inventory mismatch as a hard, no-edit failure.
    """
    cleaned: List[dict] = []
    seen_ids = set()
    for item in list(values or [])[:1000]:
        if not isinstance(item, dict):
            continue
        try:
            page = int(item.get("page", 0))
        except (TypeError, ValueError):
            continue
        if page <= 0 or (allowed_pages and page not in allowed_pages):
            continue
        label = re.sub(
            r"\s+", "", str(item.get("label") or item.get("label_hint") or "")
        )
        if label.startswith("(") and label.endswith(")"):
            label = label[1:-1]
        evidence_id = str(item.get("evidence_id") or "").strip()[:100]
        bbox = item.get("bbox_normalized")
        if (
            not EQUATION_TAG_LABEL_RE.fullmatch(label)
            or not evidence_id
            or evidence_id in seen_ids
            or item.get("status") != EQUATION_TAG_EVIDENCE_STATUS
            or item.get("verifier") != EQUATION_TAG_EVIDENCE_VERIFIER
            or not isinstance(bbox, (list, tuple))
            or len(bbox) != 4
        ):
            continue
        try:
            coords = [float(value) for value in bbox]
        except (TypeError, ValueError):
            continue
        x0, y0, x1, y1 = coords
        if (
            not all(math.isfinite(value) and 0.0 <= value <= 1.0 for value in coords)
            or not (x0 < x1 and y0 < y1)
        ):
            continue
        seen_ids.add(evidence_id)
        cleaned.append({
            "page": page,
            "label": label,
            "evidence_id": evidence_id,
            "bbox_normalized": [round(value, 6) for value in coords],
            "source": str(item.get("source") or "")[:80],
            "status": EQUATION_TAG_EVIDENCE_STATUS,
            "verifier": EQUATION_TAG_EVIDENCE_VERIFIER,
        })
    return cleaned


def _outline_title_key(value: str) -> str:
    """Return a conservative plain key for outline-only classification."""
    value = unicodedata.normalize("NFKC", str(value or "")).casefold().strip()
    value = re.sub(r"^\\(?:textbf|textit|emph|textsc)\s*\{(.*)\}$", r"\1", value)
    return "".join(character for character in value if character.isalnum())


def _outline_noise_reason(entry: dict, outline: Iterable[dict]) -> str:
    """Classify only publisher placeholder bookmarks with corroborating evidence.

    A literal chapter called ``Heading`` is unusual but possible, so the word
    alone is insufficient.  Rejection additionally requires a different,
    meaningful bookmark on the same PDF page.  The decision is surfaced in
    planning notes and the final structure report rather than silently dropped.
    """
    key = _outline_title_key(entry.get("title", ""))
    if key not in GENERIC_OUTLINE_PLACEHOLDER_KEYS:
        return ""
    try:
        page = int(entry.get("page", 0))
    except (TypeError, ValueError):
        return ""
    corroborated = any(
        other is not entry
        and int(other.get("page", 0) or 0) == page
        and _outline_title_key(other.get("title", ""))
        not in GENERIC_OUTLINE_PLACEHOLDER_KEYS | {""}
        for other in outline
    )
    if not corroborated:
        return ""
    return "PDF 大纲中的通用占位书签，且同页已有可验证的真实标题"


def _normalize_book_outline_levels(outline: List[dict], document_kind: str) -> List[dict]:
    """Promote explicitly numbered book chapters to the real book root.

    Some publisher PDFs put unnumbered front matter at bookmark level 1 and all
    numbered chapters at level 2, even though the chapters are the document's
    structural root.  Mapping those raw bookmark depths literally turns every
    chapter into ``\\section``.  At least two consecutive single-integer chapter
    titles such as ``1 Graphs`` and ``2 Subgraphs``, with increasing source
    pages, are required; every shallower bookmark before that run must be
    recognized front matter.  Descendants shift by the same amount, while later
    appendix/back-matter roots remain untouched.  Once promoted, a second pass
    is intentionally a no-op.
    """
    if document_kind != "book" or not outline:
        return outline
    front_keys = {_outline_title_key(item) for item in FRONT_MATTER}
    numbered_levels = sorted({
        int(item.get("level", 0))
        for item in outline
        if int(item.get("level", 0)) > 0
        and NUMBERED_CHAPTER_TITLE_RE.match(str(item.get("title", "")))
    })
    candidates = []
    for level in numbered_levels:
        first = next(
            index for index, item in enumerate(outline)
            if int(item.get("level", 0)) == level
            and NUMBERED_CHAPTER_TITLE_RE.match(str(item.get("title", "")))
        )
        # Only roots before the first numbered chapter constrain promotion.
        # A later Appendix/References root legitimately closes the numbered
        # chapter run and must neither veto nor be shifted with it.
        preceding_roots = [
            item for item in outline[:first]
            if int(item.get("level", 0)) < level
        ]
        if any(
            _outline_title_key(item.get("title", "")) not in front_keys
            for item in preceding_roots
        ):
            continue
        stop = next(
            (
                index for index in range(first + 1, len(outline))
                if int(outline[index].get("level", 0)) < level
            ),
            len(outline),
        )
        chapter_items = [
            (int(match.group("number")), int(item.get("page", 0)))
            for item in outline[first:stop]
            if int(item.get("level", 0)) == level
            and (match := NUMBERED_CHAPTER_TITLE_RE.match(str(item.get("title", ""))))
        ]
        numbers = [number for number, _page in chapter_items]
        chapter_pages = [page for _number, page in chapter_items]
        if len(numbers) < 2 or any(
            right != left + 1 for left, right in zip(numbers, numbers[1:])
        ) or any(
            right <= left for left, right in zip(chapter_pages, chapter_pages[1:])
        ):
            continue
        candidates.append((level, first, stop, len(numbers)))
    if not candidates:
        return outline
    chapter_level, start, stop, _count = max(
        candidates,
        key=lambda item: (item[3], -item[0], -item[1]),
    )
    normalized = []
    for index, item in enumerate(outline):
        copy = dict(item)
        level = int(copy.get("level", 0))
        if start <= index < stop and level >= chapter_level:
            copy["level"] = max(0, level - chapter_level)
        normalized.append(copy)
    return normalized


def parse_ocr_metadata(text: str) -> dict:
    match = META_RE.search(text)
    if not match:
        return {}
    token = match.group(1)
    try:
        raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
        payload = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict) or payload.get("version") not in (1, 2):
        return {}
    kind = payload.get("kind")
    if kind not in ("article", "book"):
        return {}
    outline = []
    for item in payload.get("outline", []):
        if not isinstance(item, dict):
            continue
        try:
            level = int(item.get("level", 0))
            page = int(item.get("page", 0))
        except (TypeError, ValueError):
            continue
        title = str(item.get("title", "")).strip()
        if 0 <= level <= 5 and page > 0 and title:
            outline.append({"level": level, "title": title[:300], "page": page})
    outline = _normalize_book_outline_levels(outline, kind)
    version = int(payload["version"])
    result = {
        "version": version,
        "kind": kind,
        "pages": [int(p) for p in payload.get("pages", []) if isinstance(p, int) and p > 0],
        "source_has_toc": bool(payload.get("source_has_toc")),
        "outline": outline,
    }
    result["equation_tags"] = (
        _clean_equation_tag_evidence(
            payload.get("equation_tags", []),
            allowed_pages=set(result["pages"]),
        )
        if version >= 2 else []
    )
    return result


def is_ocr_document(text: str) -> bool:
    if META_RE.search(text):
        return True
    # 兼容旧版 OCR 输出，但避免把普通 elegantbook 项目误判为 OCR。
    return bool(
        "\\documentclass[11pt]{elegantbook}" in text
        and PAGE_BREAK_RE.search(text)
        and len(PAGE_RE.findall(text)) >= 2
    )


def infer_document_kind(outline: Iterable[dict] | None, chunks: Iterable[str]) -> str:
    joined = "\n".join(chunks)
    if re.search(r"\\(?:chapter|section)\*?\s*\{\s*Chapter\s+\d+\s*\}", joined, re.I):
        return "book"
    if re.search(r"(?im)^\s*(?:\\(?:textbf|textit)\s*\{)?Chapter\s+\d+\b", joined):
        return "book"
    top = [str(x.get("title", "")) for x in (outline or []) if int(x.get("level", 0)) == 0]
    # 连续的显式 1., 2., ... 顶层标题通常是论文/综述的 section，而不是 chapter。
    numbered = sum(bool(NUMBER_PREFIX_RE.match(title)) for title in top)
    return "article" if numbered else "book" if len(top) >= 2 else "article"


def _balanced_close(line: str, opening_brace: int) -> int:
    depth = 0
    escaped = False
    for index in range(opening_brace, len(line)):
        char = line[index]
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
    return -1


def _candidate_from_line(line: str, line_no: int, page: Optional[int]) -> Optional[HeadingCandidate]:
    match = SECTION_RE.match(line)
    if match:
        opening = line.find("{", match.start())
        closing = _balanced_close(line, opening)
        if closing > opening:
            return HeadingCandidate(
                line=line_no,
                page=page,
                visible=line[opening + 1 : closing].strip(),
                trailing=line[closing + 1 :].strip(),
                kind="command",
                command=match.group("cmd"),
                starred=bool(match.group("star")),
            )
    match = STYLE_RE.match(line)
    if match:
        opening = line.find("{", match.start())
        closing = _balanced_close(line, opening)
        if closing > opening:
            return HeadingCandidate(
                line=line_no,
                page=page,
                visible=line[opening + 1 : closing].strip(),
                trailing=line[closing + 1 :].strip(),
                kind="styled",
            )
    stripped = line.strip()
    stripped = re.sub(r"^(?:\\(?:huge|Huge|LARGE|Large|large)\s*)+", "", stripped)
    stripped = re.sub(r"^\\noindent\s*", "", stripped)
    # OCR 有时把小节标题与首段正文拼在同一行，例如
    # ``3.2. A construction. The proof starts ...``。标题必须仍由 PDF 大纲和
    # 页码共同确认；这里仅拆出可供匹配的候选，不会凭编号自行创建章节。
    match = PLAIN_NUMBERED_HEADING_RE.match(stripped)
    if match:
        return HeadingCandidate(
            line=line_no,
            page=page,
            visible=match.group("title").strip(),
            trailing=(match.group("trailing") or "").strip(),
            kind="plain",
        )
    # 其余以反斜杠开头的内容是版面/分页/宏命令，不是普通标题候选。
    # 把 ``\clearpage`` 当成重复页眉会删掉真实换页，破坏目录布局。
    if stripped and len(stripped) <= 220 and not stripped.startswith(("%", "\\")):
        return HeadingCandidate(line_no, page, stripped, "", "plain")
    return None


def _candidate_bounds(hit: HeadingCandidate) -> Tuple[int, int]:
    start = hit.open_line or hit.line
    stop = hit.close_line or hit.line
    return start, max(start, stop)


def _outline_heading_span_candidates(
    lines: List[str],
    pages: Dict[int, Optional[int]],
    line_candidates: List[HeadingCandidate],
) -> List[HeadingCandidate]:
    """Build conservative same-page title candidates spanning 2--3 lines.

    OCR may split one visible publisher heading either across independent plain
    or styled LaTeX lines, or inside one multi-line heading command.  Spans are
    strictly adjacent and never cross an empty line, comment, or PDF page.  They
    are only candidates: the caller still requires an exact normalized outline
    title before consuming any continuation line.
    """
    by_line = {hit.line: hit for hit in line_candidates}
    spans: List[HeadingCandidate] = []
    seen: set[Tuple[int, int, str]] = set()

    def add_span(start: int, stop: int, visible: str) -> None:
        visible = visible.strip()
        key = (start, stop, visible)
        if not visible or key in seen:
            return
        seen.add(key)
        spans.append(HeadingCandidate(
            line=start,
            page=pages[start],
            visible=visible,
            trailing="",
            kind="span",
            open_line=start,
            close_line=stop,
        ))

    for start in range(1, len(lines) + 1):
        page = pages.get(start)
        if page is None:
            continue
        for width in range(2, MAX_OUTLINE_HEADING_SPAN_LINES + 1):
            stop = start + width - 1
            if stop > len(lines):
                break
            raw_lines = [lines[line_no - 1] for line_no in range(start, stop + 1)]
            if (
                any(pages.get(line_no) != page for line_no in range(start, stop + 1))
                or any(not line.strip() or line.lstrip().startswith("%") for line in raw_lines)
            ):
                break

            # First cover a command/style group whose braces themselves span
            # physical OCR lines, e.g. ``\\section*{Sharp`` + ``Bounds}``.
            joined_raw = " ".join(line.strip() for line in raw_lines)
            parsed = _candidate_from_line(joined_raw, start, page)
            if parsed is not None and not parsed.trailing:
                add_span(start, stop, parsed.visible)

            # Also cover independently wrapped or plain visual title lines,
            # e.g. ``\\textbf{Sharp}`` + ``\\textbf{Bounds}``.
            components = [by_line.get(line_no) for line_no in range(start, stop + 1)]
            if all(component is not None and not component.trailing for component in components):
                add_span(
                    start,
                    stop,
                    " ".join(component.visible for component in components if component),
                )
    return spans


def _plain_text(value: str) -> str:
    value = unicodedata.normalize("NFKD", value)
    value = re.sub(r"\\(?:'|`|\^|\"|~|c|v|H|u)\s*\{?([A-Za-z])\}?", r"\1", value)
    value = re.sub(r"\\(?:textbf|textit|emph|textsc|mathrm|operatorname|mathbb|mathcal)\s*", "", value)
    value = re.sub(r"\\(?:quad|qquad|,|;|!| )", " ", value)
    value = value.replace("$", " ").replace("\\(", " ").replace("\\)", " ")
    value = value.replace("{", " ").replace("}", " ")
    value = re.sub(r"^\s*chapter\s+\d+\s*", "", value, flags=re.I)
    value = NUMBER_PREFIX_RE.sub("", value)
    value = "".join(ch for ch in value.casefold() if ch.isalnum())
    return value


def _title_without_number(value: str) -> str:
    value = re.sub(r"^\s*Chapter\s+\d+\s*[:.\-]?\s*", "", value, flags=re.I)
    value = NUMBER_PREFIX_RE.sub("", value).strip()
    # 编号与标题之间的视觉空白命令不是标题内容。若保留在章节参数里，
    # ``\section{\quad Title}`` 会污染目录与 PDF 书签。
    return re.sub(r"^(?:\\(?:quad|qquad|,|;|!| )\s*)+", "", value).strip()


def _score_title(expected: str, candidate: str) -> float:
    left, right = _plain_text(expected), _plain_text(candidate)
    if not left or not right:
        return 0.0
    if left == right:
        return 1.0
    if right.startswith(left) and len(left) >= 8:
        return 0.97
    if left.startswith(right) and len(right) >= 8:
        return 0.94
    return difflib.SequenceMatcher(a=left, b=right, autojunk=False).ratio()


def _outline_title_is_exact(expected: str, candidate: str) -> bool:
    """Require the entire normalized bookmark title, never only a prefix/suffix."""
    left, right = _plain_text(expected), _plain_text(candidate)
    return bool(left) and left == right


def _command_for(level: int, kind: str) -> str:
    names = ("chapter", "section", "subsection", "subsubsection") if kind == "book" else (
        "section", "subsection", "subsubsection", "paragraph",
    )
    return names[min(max(level, 0), len(names) - 1)]


def _authoritative_page_markers(lines: List[str]) -> Dict[int, int]:
    """只采信每个合并页段的第一个 Page 标记。

    ``merge_book`` 已在段首写入真实 PDF 页码，但视觉模型偶尔又把印刷页码转成
    ``% Page N``。旧逻辑会被第二个注释覆盖，导致后续标题与 PDF 大纲错开数页。
    """
    has_breaks = any(PAGE_BREAK_RE.match(line) for line in lines)
    accept_next = True
    markers = {}
    for index, line in enumerate(lines, start=1):
        if PAGE_BREAK_RE.match(line):
            accept_next = True
            continue
        match = PAGE_RE.match(line)
        if not match:
            continue
        if not has_breaks or accept_next:
            markers[index] = int(match.group(1))
            accept_next = False
    return markers


def _page_map(lines: List[str]) -> Dict[int, Optional[int]]:
    current: Optional[int] = None
    out = {}
    markers = _authoritative_page_markers(lines)
    for index, line in enumerate(lines, start=1):
        if index in markers:
            current = markers[index]
        out[index] = current
    return out


def _page_line_positions(lines: List[str]) -> Dict[int, int]:
    """返回每行距当前 ``% Page`` 标记的行数，用于保守识别运行页眉。"""
    start = 0
    out = {}
    markers = _authoritative_page_markers(lines)
    for index, line in enumerate(lines, start=1):
        if index in markers:
            start = index
        out[index] = index - start if start else 10_000
    return out


def _active_latex(text: str) -> str:
    """等长屏蔽注释、保护环境与 inline verb，只保留会执行的 LaTeX。"""
    active = mask_comments(text)
    ranges, _, _ = find_env_ranges(active)
    return mask_inline_verb(mask_protected(active, ranges))


def _near_page_segment_end(lines: List[str], line_no: int, lookahead: int = 7) -> bool:
    """该行之后很快就是 OCR 页段边界；用于限定印刷页码清理范围。"""
    upper = min(len(lines), line_no + max(1, lookahead))
    return any(
        PAGE_RE.match(lines[index - 1])
        or PAGE_BREAK_RE.match(lines[index - 1])
        or lines[index - 1].strip() in {r"\clearpage", r"\newpage", r"\end{document}"}
        for index in range(line_no + 1, upper + 1)
    )


def _manual_toc_region_is_safe(lines: List[str], start: int, stop: int) -> bool:
    """目录区只有可证明的列表/点线/页码框架时才允许整体替换。"""
    entries = 0
    for line_no in range(start, stop):
        stripped = lines[line_no - 1].strip()
        if not stripped or stripped.startswith("%"):
            continue
        if _is_manual_toc_entry(stripped):
            entries += 1
            continue
        if re.fullmatch(r"\\(?:begin|end)\{(?:itemize|enumerate|center)\}", stripped):
            continue
        if re.match(r"^\\(?:vspace|vfill|smallskip|medskip|bigskip)\b", stripped):
            continue
        if stripped in {r"\clearpage", r"\newpage"}:
            continue
        visible = re.sub(r"\\textbf\s*\{([^{}]*)\}", r"\1", stripped).strip()
        if re.fullmatch(r"[ivxlcdm]+|\d+", visible, re.I):
            continue
        if re.fullmatch(
            r"\\(?:hbox|mbox|centerline)\s*\{\s*(?:[ivxlcdm]+|\d+)\s*\}",
            stripped,
            re.I,
        ):
            continue
        if re.fullmatch(r"\\hfill\s*(?:[ivxlcdm]+|\d+)", stripped, re.I):
            continue
        # 未知活动文本可能是真实正文；整段不改，交给最终目录门禁拦截。
        return False
    return entries >= 1


def _printed_folio_number(value: str) -> Optional[int]:
    """Decode only an inert positive decimal folio from a TOC row tail.

    OCR may retain visual spacing (``\\quad 12``) or a harmless text style
    wrapper (``\\textbf{12}``).  The wrapper grammar is deliberately closed and
    its payload must be digits only; arbitrary commands, nested braces, suffixes,
    and executable TeX are rejected rather than interpreted.
    """
    value = str(value or "").strip()
    edge_spacing = r"(?:\\(?:quad|qquad)\b|\\[,;! ])"
    value = re.sub(rf"^(?:{edge_spacing}\s*)+", "", value).strip()
    value = re.sub(rf"(?:\s*{edge_spacing})+$", "", value).strip()
    wrapper = re.fullmatch(
        r"\\(?:textbf|textit|textsc|emph)\s*\{\s*(?P<page>\d+)\s*\}",
        value,
    )
    digits = wrapper.group("page") if wrapper is not None else value
    if re.fullmatch(r"\d+", digits) is None:
        return None
    page = int(digits)
    return page if page > 0 else None


def _follows_display_math(lines: List[str], line_no: int) -> bool:
    """Protect a prose tail that completes the display immediately above it."""
    for previous in range(line_no - 1, max(0, line_no - 5), -1):
        stripped = lines[previous - 1].strip()
        if not stripped or stripped.startswith("%"):
            continue
        return bool(
            stripped == r"\]"
            or re.fullmatch(
                r"\\end\{(?:equation|equation\*|align|align\*|gather|gather\*|multline|multline\*)\}",
                stripped,
            )
        )
    return False


def _within_running_header_margin(hit: HeadingCandidate, position: int) -> bool:
    """Require page-margin placement plus syntax evidence for a wider band."""
    limit = RUNNING_HEADER_MAX_TOP_OFFSET
    # OCR engines commonly encode running heads as starred section commands.
    # That explicit non-body syntax is strong enough to tolerate a few other
    # page-furniture lines above it; plain/styled prose gets only the strict
    # three-line outer-margin allowance.
    if hit.kind == "command" and hit.starred:
        limit = RUNNING_HEADER_COMMAND_MAX_TOP_OFFSET
    return position <= limit


def _manual_toc_entry_parts(line: str) -> Optional[Tuple[str, int]]:
    """Return the inert title text and printed page from an unambiguous TOC row."""
    stripped = str(line or "").strip()
    if not stripped:
        return None
    if r"\dotfill" in stripped:
        left, right = stripped.rsplit(r"\dotfill", 1)
    else:
        leaders = list(PRINTED_DOT_LEADER_RE.finditer(stripped))
        if not leaders:
            return None
        marker = leaders[-1]
        left = stripped[: marker.start()].strip()
        right = stripped[marker.end() :].strip()
    page = _printed_folio_number(right)
    if not left or page is None:
        return None
    return left.strip(), page


def _is_manual_toc_entry(line: str) -> bool:
    """Recognize a printed TOC row without interpreting its title as code."""
    if _manual_toc_entry_parts(line) is not None:
        return True
    stripped = str(line or "").strip()
    if r"\dotfill" in stripped:
        left, right = stripped.rsplit(r"\dotfill", 1)
    else:
        leaders = list(PRINTED_DOT_LEADER_RE.finditer(stripped))
        if not leaders:
            return False
        marker = leaders[-1]
        left = stripped[: marker.start()].strip()
        right = stripped[marker.end() :].strip()
    return bool(left.strip()) and bool(
        re.fullmatch(r"[ivxlcdm]+", right.strip(), re.I)
    )


def _manual_toc_entry_heading(line: str) -> Optional[dict]:
    """Extract a chapter-local heading claim from an unambiguous printed row."""
    stripped = str(line or "").strip()
    if not _is_manual_toc_entry(stripped):
        return None
    parts = _manual_toc_entry_parts(stripped)
    if parts is None:
        return None
    left, _printed_page = parts
    left = re.sub(r"\\(?:quad|qquad)\b", " ", left).strip()
    left = re.sub(
        r"^\s*\\hspace\*?\s*\{[^{}\r\n]*\}\s*",
        "",
        left,
    )
    styled = _candidate_from_line(left, 1, None)
    if styled is not None and styled.kind == "styled" and styled.visible.strip():
        styled_numbered = re.match(r"^\s*\d+(?:\.\d+)+\.?\s+", styled.visible)
        if styled_numbered is None:
            return {
                "command": "subsection",
                "starred": True,
                "number": "",
                "title": styled.visible.strip(),
                "requires_styled_body": False,
            }
        # Bold is merely the visual style of a numbered section row here; the
        # dotted number still supplies its actual relative hierarchy.
        left = styled.visible.strip()
    numbered = re.match(
        r"^\s*(?P<number>\d+(?:\.\d+)+)\.?\s+(?P<title>\S.*)\s*$",
        left,
    )
    if numbered is None:
        # Some publisher local TOCs render their subordinate entries as plain
        # text.  The TOC row alone does not prove that arbitrary matching prose
        # is a heading, so the caller must require independent styled/command
        # evidence from the body before accepting this claim.
        if re.fullmatch(r"[^\\{}\r\n]*[A-Za-z][^\\{}\r\n]*", left):
            return {
                "command": "subsection",
                "starred": True,
                "number": "",
                "title": left.strip(),
                "requires_styled_body": True,
            }
        return None
    components = numbered.group("number").split(".")
    command_names = ("section", "subsection", "subsubsection")
    title = numbered.group("title").strip()
    styled_title = _candidate_from_line(title, 1, None)
    if (
        styled_title is not None
        and styled_title.kind == "styled"
        and not styled_title.trailing
    ):
        title = styled_title.visible.strip()
    return {
        "command": command_names[min(max(len(components) - 2, 0), 2)],
        "starred": False,
        "number": numbered.group("number"),
        "title": title,
        "requires_styled_body": False,
    }


def _center_bounds(lines: List[str], line_no: int) -> Tuple[int, int]:
    if line_no > 1 and line_no < len(lines):
        before, after = lines[line_no - 2].strip(), lines[line_no].strip()
        if before == "\\begin{center}" and after == "\\end{center}":
            return line_no - 1, line_no + 1
    return 0, 0


def _front_matter(title: str) -> bool:
    return _plain_text(title) in {_plain_text(item) for item in FRONT_MATTER}


def _update_math_stack(stack: List[str], line: str) -> None:
    active = line.split("%", 1)[0]
    for token in MATH_EVENT_RE.finditer(active):
        delimiter = token.group("delimiter")
        if delimiter == "[":
            stack.append("bracket-display")
        elif delimiter == "]":
            if stack and stack[-1] == "bracket-display":
                stack.pop()
        elif token.group("kind") == "begin":
            stack.append(token.group("name"))
        elif stack and stack[-1] == token.group("name"):
            stack.pop()


def _find_math_close(lines: List[str], start: int, initial: List[str]) -> int:
    stack = list(initial)
    # 只移动到附近可证明的闭合点，避免跨段猜测环境边界。
    for line_no in range(start, min(len(lines), start + 30) + 1):
        _update_math_stack(stack, lines[line_no - 1])
        if not stack:
            return line_no
    return 0


def _exercise_number_stem(number: str) -> str:
    """Return the chapter/section stem of a three-part exercise number."""
    return ".".join(str(number).split(".")[:2])


def _exercise_label_stem(line: str) -> str:
    """Return a proven exercise stem from one source line, if present."""
    formatted = FORMATTED_EXERCISE_LABEL_RE.match(line)
    if formatted is not None:
        return _exercise_number_stem(formatted.group("number"))
    plain = PLAIN_EXERCISE_LABEL_RE.match(line)
    if plain is not None:
        return _exercise_number_stem(plain.group("number"))
    return ""


def _is_exercise_body_heading(lines: List[str], line_no: int) -> bool:
    """Distinguish a real exercise heading from a repeated running header.

    A new exercise block is evidenced by the first following three-part label
    having a different stem from the last preceding exercise label.  A repeated
    ``Exercises`` at the top of a continuation page instead has the same stem.
    If OCR lost all following labels, preserve the line rather than guessing it
    is page furniture.
    """
    if not 1 <= line_no <= len(lines):
        return False
    line = lines[line_no - 1]
    if (
        EXERCISE_HEADING_RE.fullmatch(line) is None
        and FORMATTED_EXERCISE_HEADING_RE.fullmatch(line) is None
    ):
        return False

    next_stem = ""
    for following_no in range(line_no + 1, min(len(lines), line_no + 40) + 1):
        following = lines[following_no - 1]
        stripped = following.strip()
        if (
            PAGE_RE.match(following)
            or PAGE_BREAK_RE.match(following)
            or stripped in {r"\clearpage", r"\newpage"}
        ):
            break
        next_stem = _exercise_label_stem(following)
        if next_stem:
            break

    if not next_stem:
        return True

    previous_stem = ""
    for previous_no in range(line_no - 1, 0, -1):
        previous_stem = _exercise_label_stem(lines[previous_no - 1])
        if previous_stem:
            break
    return not previous_stem or previous_stem != next_stem


def _build_exercise_fidelity_ops(lines: List[str]) -> Tuple[List[PendingOp], List[dict]]:
    """Restore exercise typography only when the OCR text supplies evidence.

    Bondy-style exercise identifiers have three numeric components, but a bare
    ``1.2.3`` can also be a genuine third-level heading in another book.  A
    numeric run is therefore treated as exercises only when its two-component
    stem is anchored by an explicit ``Exercise(s)`` heading, a difficulty star,
    or an already-bold peer.  The latter additionally requires at least two
    distinct labels with that stem.  This preserves the words, numbering, and
    page markers while avoiding section-number guesses.

    The hard/easy-group ornament is equally conservative: only the exact OCR
    corruption ``\\mathrel{))}`` between two explicit rules is repaired.  A
    divider that disappeared completely has no textual anchor and is never
    synthesized here.
    """
    operations: List[PendingOp] = []
    notes: List[dict] = []
    heading_lines: List[int] = []
    labels_by_line: Dict[int, Tuple[str, bool]] = {}
    plain_labels: List[Tuple[int, re.Match[str], str, str, bool]] = []
    numbers_by_stem: Dict[str, set[str]] = {}
    formatted_stems: set[str] = set()
    starred_stems: set[str] = set()

    for line_no, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("%"):
            continue
        exercise_heading = EXERCISE_HEADING_RE.fullmatch(line)
        if exercise_heading is not None:
            if not _is_exercise_body_heading(lines, line_no):
                continue
            heading_lines.append(line_no)
            title = exercise_heading.group("title")
            operations.append(PendingOp(
                "replace_line",
                line_no,
                old=line,
                new=(
                    exercise_heading.group("prefix")
                    + f"\\textbf{{{title}}}"
                ),
            ))
            notes.append({
                "line": line_no,
                "status": "normalized-exercise-heading",
                "reason": f"保留练习标题文字并恢复原书粗体层级：{title}",
            })
            continue
        if FORMATTED_EXERCISE_HEADING_RE.fullmatch(line):
            if _is_exercise_body_heading(lines, line_no):
                heading_lines.append(line_no)
            continue

        formatted = FORMATTED_EXERCISE_LABEL_RE.match(line)
        if formatted is not None:
            number = formatted.group("number")
            stem = _exercise_number_stem(number)
            labels_by_line[line_no] = (stem, True)
            numbers_by_stem.setdefault(stem, set()).add(number)
            formatted_stems.add(stem)
            continue

        plain = PLAIN_EXERCISE_LABEL_RE.match(line)
        if plain is not None:
            number = plain.group("number")
            stem = _exercise_number_stem(number)
            prefix = plain.group("prefix")
            starred = bool(re.search(r"\\(?:star|ast)\b|[★☆]", prefix))
            labels_by_line[line_no] = (stem, False)
            numbers_by_stem.setdefault(stem, set()).add(number)
            plain_labels.append((line_no, plain, number, stem, starred))
            if starred:
                starred_stems.add(stem)

    anchored_stems = set(starred_stems)
    anchored_stems.update(
        stem for stem in formatted_stems
        if len(numbers_by_stem.get(stem, set())) >= 2
    )

    # An explicit Exercise(s) heading anchors only the first following numbered
    # run.  Do not let a heading classify every later three-part heading in the
    # document as an exercise.
    for heading_line in heading_lines:
        for line_no in range(heading_line + 1, min(len(lines), heading_line + 40) + 1):
            label = labels_by_line.get(line_no)
            if label is not None:
                anchored_stems.add(label[0])
                break
            stripped = lines[line_no - 1].strip()
            if not stripped or stripped.startswith("%"):
                continue
            if re.match(
                r"^\\(?:chapter|section|subsection|subsubsection)\*?\s*\{",
                stripped,
            ) and not FORMATTED_EXERCISE_HEADING_RE.fullmatch(stripped):
                break

    for line_no, match, number, stem, _starred in plain_labels:
        if stem not in anchored_stems:
            continue
        old = lines[line_no - 1]
        new = (
            match.group("prefix")
            + f"\\textbf{{{number}}}"
            + match.group("suffix")
        )
        operations.append(PendingOp("replace_line", line_no, old=old, new=new))
        notes.append({
            "line": line_no,
            "status": "normalized-exercise-number",
            "reason": f"练习编号由同组证据确认并恢复粗体：{number}",
        })

    for line_no, line in enumerate(lines, start=1):
        active = line.split("%", 1)[0]
        if (
            active.count(r"\rule") >= 2
            and active.count(BROKEN_EXERCISE_DIVIDER) == 1
        ):
            operations.append(PendingOp(
                "replace_line",
                line_no,
                old=line,
                new=line.replace(
                    BROKEN_EXERCISE_DIVIDER,
                    CANONICAL_EXERCISE_DIVIDER,
                    1,
                ),
            ))
            notes.append({
                "line": line_no,
                "status": "repaired-exercise-divider",
                "reason": "两侧规则线确认了练习难度分隔饰符；将 OCR 的 )) 恢复为双 \\wr",
            })

    return sorted(operations, key=lambda op: (op.line, op.kind)), notes


def _build_syntax_repair_ops(lines: List[str]) -> Tuple[List[PendingOp], List[dict]]:
    """修复 OCR 可证明的数学环境闭合和非法段落空行。

    只移动一条完整的 ``\\end{theorem}``（及同类环境），公式和正文逐字不改；
    展示数学环境内的纯空白行会产生非法 ``\\par``，因此只删除这类零字符
    行。所有改动仍通过 PendingOp 进入可逆补丁与内容不变校验。
    """
    outer_stack: List[Tuple[str, int]] = []
    math_stack: List[str] = []
    operations = []
    notes = []
    for line_no, line in enumerate(lines, start=1):
        if math_stack and not line.strip():
            operations.append(PendingOp("delete_line", line_no, old=line))
            notes.append({
                "line": line_no,
                "status": "normalized-display-spacing",
                "reason": "删除展示数学环境内会产生非法 \\par 的纯空白行",
            })
            continue
        env = EXACT_ENV_LINE_RE.match(line.split("%", 1)[0])
        if env and env.group("name") in OUTER_TEXT_ENVS:
            kind, name = env.group("kind"), env.group("name")
            if kind == "begin":
                outer_stack.append((name, line_no))
            elif outer_stack and outer_stack[-1][0] == name:
                if math_stack:
                    close_line = _find_math_close(lines, line_no + 1, math_stack)
                    if close_line:
                        anchor = close_line
                        if anchor < len(lines) and re.match(
                            r"^\s*\\(?:textit|emph)\s*\{.*\}\s*$",
                            lines[anchor],
                        ):
                            anchor += 1
                        operations.extend([
                            PendingOp("delete_line", line_no, old=line),
                            PendingOp("insert_line", anchor, new=line.strip()),
                        ])
                        notes.append({
                            "line": line_no,
                            "status": "repaired-syntax",
                            "reason": (
                                f"将过早的 \\end{{{name}}} 移到数学环境闭合后"
                                f"（原第 {line_no} 行 → 第 {anchor} 行后）"
                            ),
                        })
                outer_stack.pop()
        _update_math_stack(math_stack, line)
    return operations, notes


def _pending_op_key(op: PendingOp) -> Tuple:
    if op.kind == "insert_line":
        return (op.line, op.kind, op.new)
    return (op.line, op.kind)


def _pending_ops_conflict(left: PendingOp, right: PendingOp) -> bool:
    """Return true when two edits cannot safely share one source line."""
    if left.line != right.line:
        return False
    if left == right:
        return False
    # Inserts deliberately use the original line as an anchor and may coexist
    # with a replacement or deletion; the patch engine's delta accounting is
    # tested for that legacy move/marker behavior.
    if left.kind == "insert_line" or right.kind == "insert_line":
        return False
    # Same-kind edits retain the established deterministic last-wins behavior
    # (for example ``Contents`` first maps as an outline title and is then
    # replaced by the stronger, validated global TOC operation).
    if left.kind == right.kind:
        return False
    # Different destructive kinds on one source line are ambiguous.  This is
    # the P48 failure mode: delete_line and replace_line must never both apply.
    return True


def _add_pending_op_fail_safe(
    operations: Dict[Tuple, PendingOp],
    blocked_lines: set[int],
    op: PendingOp,
    notes: List[dict],
) -> None:
    """Add one edit, preserving the source line on any ambiguous collision."""
    if op.line in blocked_lines:
        return
    key = _pending_op_key(op)
    existing_exact = operations.get(key)
    if existing_exact == op:
        return
    same_line = [
        (existing_key, existing)
        for existing_key, existing in operations.items()
        if existing.line == op.line
    ]
    if any(_pending_ops_conflict(existing, op) for _key, existing in same_line):
        # Drop every edit anchored to the line.  This keeps the original source
        # byte-for-byte when different destructive interpretations disagree.
        for existing_key, _existing in same_line:
            operations.pop(existing_key, None)
        blocked_lines.add(op.line)
        notes.append({
            "line": op.line,
            "status": "conflict-preserved",
            "reason": "同一源行出现互斥结构补丁；已全部放弃并逐字保留原行",
        })
        return
    operations[key] = op


def build_ocr_structure_ops(text: str) -> Tuple[List[PendingOp], List[dict]]:
    """把 PDF 大纲映射为章节命令；所有改动都通过可逆 PendingOp 表达。"""
    metadata = parse_ocr_metadata(text)
    lines = text.split("\n")
    exercise_ops, exercise_notes = _build_exercise_fidelity_ops(lines)
    if not metadata or not metadata.get("outline"):
        # 即使 PDF 没有书签，OCR 仍可能把 theorem/proof 的结束命令放进
        # 尚未闭合的公式中。该修复不依赖大纲，且只移动可证明的完整结束行。
        syntax_ops, syntax_notes = _build_syntax_repair_ops(lines)
        combined: Dict[Tuple, PendingOp] = {}
        blocked_lines: set[int] = set()
        combined_notes = list(exercise_notes) + list(syntax_notes)
        for op in exercise_ops + syntax_ops:
            _add_pending_op_fail_safe(
                combined, blocked_lines, op, combined_notes,
            )
        return (
            sorted(combined.values(), key=lambda op: (op.line, op.kind)),
            combined_notes,
        )
    pages = _page_map(lines)
    page_positions = _page_line_positions(lines)
    kind = metadata["kind"]
    candidates = [
        hit for index, line in enumerate(lines, start=1)
        if (hit := _candidate_from_line(line, index, pages[index])) is not None
    ]
    outline_candidates = candidates + _outline_heading_span_candidates(
        lines, pages, candidates,
    )
    used: set[int] = set()
    operations: Dict[Tuple, PendingOp] = {}
    blocked_lines: set[int] = set()
    notes: List[dict] = list(exercise_notes)
    matched_lines: set[int] = set()
    mapped_chapter_lines: Dict[int, str] = {}
    mapped_chapter_titles: Dict[int, str] = {}

    def set_op(op: PendingOp):
        _add_pending_op_fail_safe(operations, blocked_lines, op, notes)

    for exercise_op in exercise_ops:
        set_op(exercise_op)

    outline = metadata["outline"]
    for entry in outline:
        noise_reason = _outline_noise_reason(entry, outline)
        if noise_reason:
            notes.append({
                "line": 1,
                "page": int(entry.get("page", 1)),
                "status": "outline-noise-rejected",
                "title": str(entry.get("title", "")),
                "reason": noise_reason,
            })
            continue
        expected_page = int(entry["page"])
        ranked = []
        for hit in outline_candidates:
            hit_start, hit_stop = _candidate_bounds(hit)
            if any(line_no in used for line_no in range(hit_start, hit_stop + 1)):
                continue
            page_delta = abs((hit.page or expected_page) - expected_page)
            if page_delta > 1:
                continue
            if not _outline_title_is_exact(entry["title"], hit.visible):
                continue
            if hit_stop > hit_start:
                first_piece = _candidate_from_line(
                    lines[hit_start - 1], hit_start, pages[hit_start],
                )
                first_visible = first_piece.visible if first_piece is not None else ""
                chapter_marker = CHAPTER_MARKER_RE.match(first_visible)
                bare_marker = BARE_CHAPTER_MARKER_RE.match(first_visible)
                if chapter_marker or bare_marker:
                    expected_number_match = NUMBERED_CHAPTER_TITLE_RE.match(
                        str(entry["title"])
                    )
                    expected_number = (
                        expected_number_match.group("number")
                        if expected_number_match else ""
                    )
                    numbered_book_chapter = (
                        kind == "book"
                        and int(entry["level"]) == 0
                        and not _front_matter(entry["title"])
                    )
                    marker_number = (
                        chapter_marker.group(1) if chapter_marker else bare_marker.group(1)
                    )
                    if (
                        not numbered_book_chapter
                        or (expected_number and marker_number != expected_number)
                        or (bare_marker and not expected_number)
                    ):
                        continue
            # Exact spans rank before a later suffix-only line.  Among candidates
            # with the same anchor, prefer the shortest confirmed span.
            ranked.append((page_delta, hit_start, hit_stop - hit_start, hit))
        if not ranked:
            notes.append({
                "line": 1,
                "status": "missing",
                "reason": f"PDF 大纲标题未在 OCR 正文中找到：{entry['title']}",
            })
            continue
        ranked.sort(key=lambda row: row[:3])
        hit = ranked[0][3]
        hit_start, hit_stop = _candidate_bounds(hit)
        hit_lines = set(range(hit_start, hit_stop + 1))
        used.update(hit_lines)
        matched_lines.update(hit_lines)
        command = _command_for(int(entry["level"]), kind)
        title = _title_without_number(hit.visible) or _title_without_number(entry["title"])
        expected_title = _title_without_number(entry["title"])
        # 行内标题常以句点和正文分隔；PDF 大纲不带该分隔符时，不把它写进
        # section 参数。问号/感叹号可能是标题本身，仍原样保留。
        if title.endswith(".") and not expected_title.endswith("."):
            title = title[:-1].rstrip()
        star = _front_matter(entry["title"]) and not NUMBER_PREFIX_RE.match(entry["title"])

        command_line = hit_start
        if kind == "book" and int(entry["level"]) == 0 and not star:
            # OCR 常把“Chapter 1”（或原书章首独立的一行 ``1``）和真正章名
            # 拆成两行；只有数字与 PDF 大纲编号一致时才合并为一个 chapter。
            expected_number_match = NUMBERED_CHAPTER_TITLE_RE.match(str(entry["title"]))
            expected_number = (
                expected_number_match.group("number") if expected_number_match else ""
            )

            def is_matching_marker(item: HeadingCandidate) -> bool:
                chapter_match = CHAPTER_MARKER_RE.match(item.visible)
                bare_match = BARE_CHAPTER_MARKER_RE.match(item.visible)
                if chapter_match:
                    number = chapter_match.group(1)
                    # Publisher bookmarks commonly omit the visible chapter
                    # number (``Ramsey numbers``), while OCR preserves it on a
                    # separate immediately preceding ``Chapter 1`` line.  The
                    # explicit word ``Chapter`` plus the same-page adjacency is
                    # sufficient to identify that line as the chapter marker.
                    # When the bookmark does carry a number, keep requiring an
                    # exact match so a wrong marker cannot be silently removed.
                    return not expected_number or number == expected_number
                if bare_match:
                    # A lone number may be a folio or genuine body text; only a
                    # numbered bookmark can make that weaker marker removable.
                    return bool(expected_number and bare_match.group(1) == expected_number)
                return False

            previous = next(
                (
                    item for item in candidates
                    if item.page == hit.page and item.line < hit.line
                    and hit.line - item.line <= 2 and is_matching_marker(item)
                ),
                None,
            )
            if previous is not None:
                command_line = previous.line
                used.add(previous.line)
                matched_lines.add(previous.line)

        trailing = hit.trailing
        replacement = f"\\{command}{'*' if star else ''}{{{title}}}"
        if trailing:
            replacement += " " + trailing
        set_op(PendingOp(
            "replace_line",
            command_line,
            old=lines[command_line - 1],
            new=replacement,
        ))
        if command == "chapter" and not star:
            chapter_number = NUMBERED_CHAPTER_TITLE_RE.match(str(entry["title"]))
            mapped_chapter_lines[command_line] = (
                chapter_number.group("number") if chapter_number else ""
            )
            mapped_chapter_titles[command_line] = title
        # Only lines belonging to an exact outline-confirmed span are consumed.
        # The first line becomes the structural command; every confirmed
        # continuation line is removed, while the following body line remains.
        for consumed_line in sorted(hit_lines):
            if consumed_line != command_line:
                set_op(PendingOp(
                    "delete_line", consumed_line, old=lines[consumed_line - 1],
                ))
        center_open, center_close = _center_bounds(lines, command_line)
        if center_open:
            set_op(PendingOp("delete_line", center_open, old=lines[center_open - 1]))
            set_op(PendingOp("delete_line", center_close, old=lines[center_close - 1]))
        is_contents = _plain_text(entry["title"]) == "contents"
        if star and not (is_contents and metadata.get("source_has_toc")):
            set_op(PendingOp(
                "insert_line", command_line,
                new=f"\\addcontentsline{{toc}}{{{command}}}{{{title}}}",
            ))
        notes.append({
            "line": command_line,
            "status": "mapped",
            "reason": (
                f"PDF 大纲 L{int(entry['level']) + 1} → "
                f"\\{command}{'*' if star else ''}{{{title}}}"
            ),
        })

    # 手抄目录只保存旧页码，重排后必然错误；换成可二次编译更新的真实目录。
    contents = next((hit for hit in candidates if _plain_text(hit.visible) == "contents"), None)
    if contents is not None and metadata.get("source_has_toc"):
        # A publisher TOC commonly spans several physical pages.  The next
        # outline-mapped heading is a stronger boundary than the first OCR page
        # break; using the latter leaves the second printed TOC page in the body.
        later_mapped = sorted(line for line in matched_lines if line > contents.line)
        stop = later_mapped[0] if later_mapped else len(lines) + 1
        if _manual_toc_region_is_safe(lines, contents.line + 1, stop):
            # Some publisher PDFs omit intentionally blank verso pages while
            # retaining the printed folio sequence.  Replacing the printed TOC
            # with a live TOC must not silently shift every later chapter page.
            # Accept folio claims only when chapter number + title match an
            # outline-mapped chapter and the skipped-page offset is small and
            # monotonically nondecreasing across at least three chapters.
            printed_claims = []
            for line_no in range(contents.line + 1, stop):
                parts = _manual_toc_entry_parts(lines[line_no - 1])
                if parts is None:
                    continue
                left, printed_page = parts
                left = re.sub(r"\\(?:quad|qquad)\b", " ", left).strip()
                chapter_claim = NUMBERED_CHAPTER_TITLE_RE.match(left)
                if chapter_claim is None:
                    continue
                claim_number = chapter_claim.group("number")
                claim_title = chapter_claim.group("title").strip()
                matches = [
                    chapter_line for chapter_line, chapter_number in mapped_chapter_lines.items()
                    if chapter_number == claim_number
                    and _score_title(
                        mapped_chapter_titles.get(chapter_line, ""), claim_title
                    ) >= 0.93
                ]
                if len(matches) == 1:
                    chapter_line = matches[0]
                    printed_claims.append({
                        "chapter_line": chapter_line,
                        "source_page": int(pages.get(chapter_line) or 0),
                        "printed_page": printed_page,
                    })
            printed_claims.sort(key=lambda item: item["chapter_line"])
            folios_are_safe = False
            if len(printed_claims) >= 3 and all(
                item["source_page"] > 0 for item in printed_claims
            ):
                first_source = printed_claims[0]["source_page"]
                first_printed = printed_claims[0]["printed_page"]
                adjustments = [
                    item["printed_page"]
                    - (first_printed + item["source_page"] - first_source)
                    for item in printed_claims
                ]
                printed_pages = [item["printed_page"] for item in printed_claims]
                folios_are_safe = (
                    all(left < right for left, right in zip(printed_pages, printed_pages[1:]))
                    and all(0 <= value <= 64 for value in adjustments)
                    and all(
                        0 <= right - left <= 8
                        for left, right in zip(adjustments, adjustments[1:])
                    )
                )
            if folios_are_safe:
                for claim in printed_claims:
                    chapter_line = int(claim["chapter_line"])
                    printed_page = int(claim["printed_page"])
                    set_op(PendingOp(
                        "insert_line",
                        chapter_line - 1,
                        new=f"{PRINTED_PAGE_MARKER_PREFIX}{printed_page}",
                    ))
                notes.append({
                    "line": contents.line,
                    "status": "mapped-printed-folios",
                    "reason": (
                        f"全局目录与 PDF 大纲双重确认了 {len(printed_claims)} 个章首页码；"
                        "保留省略空白页后的原印刷页码"
                    ),
                })
            set_op(PendingOp(
                "replace_line", contents.line,
                old=lines[contents.line - 1], new="\\tableofcontents",
            ))
            boundaries = [
                line_no for line_no in range(contents.line + 1, stop)
                if lines[line_no - 1].strip() in {r"\clearpage", r"\newpage"}
            ]
            keep_boundary = boundaries[-1] if boundaries else 0
            relocated_page_markers = []
            for line_no in range(contents.line + 1, stop):
                if line_no == keep_boundary:
                    continue
                is_page_marker = bool(
                    PAGE_RE.match(lines[line_no - 1])
                    or PAGE_BREAK_RE.match(lines[line_no - 1])
                )
                if is_page_marker and keep_boundary and line_no > keep_boundary:
                    # This marker already follows the retained final page
                    # boundary and therefore belongs to the first body page.
                    continue
                if is_page_marker and keep_boundary:
                    relocated_page_markers.append(lines[line_no - 1])
                set_op(PendingOp("delete_line", line_no, old=lines[line_no - 1]))
            for marker in relocated_page_markers:
                # Keep source-page provenance without placing comments between
                # ``\tableofcontents`` and its retained ``\clearpage``.
                set_op(PendingOp("insert_line", keep_boundary, new=marker))
            notes.append({
                "line": contents.line,
                "status": "mapped",
                "reason": "已删除带旧页码的手抄目录并改用 \\tableofcontents",
            })
        else:
            notes.append({
                "line": contents.line,
                "status": "rejected",
                "reason": "手抄目录区混有无法确认的正文，已完整保留并阻止自动导出",
            })

    # Chapter-opening pages may contain a second, chapter-local printed TOC.
    # Replace only a same-page Contents block immediately following a mapped
    # chapter and containing at least three unambiguous leader/page rows.  A
    # template can turn this inert marker into a live local TOC after AI has
    # constructed the section tree; ordinary prose named "Contents" is untouched.
    for local_contents in candidates:
        if (
            _plain_text(local_contents.visible) != "contents"
            or local_contents.line in matched_lines
        ):
            continue
        preceding_chapters = [
            line_no for line_no in mapped_chapter_lines
            if line_no < local_contents.line
            and local_contents.line - line_no <= 5
            and pages.get(line_no) == local_contents.page
        ]
        if not preceding_chapters:
            continue
        stop = local_contents.line + 1
        entry_lines = []
        removable = []
        while stop <= len(lines):
            stripped = lines[stop - 1].strip()
            if not stripped:
                removable.append(stop)
                stop += 1
                continue
            if _is_manual_toc_entry(stripped):
                entry_lines.append(stop)
                removable.append(stop)
                stop += 1
                continue
            break
        if len(entry_lines) < 3:
            continue
        chapter_line = max(preceding_chapters)
        chapter_number = mapped_chapter_lines.get(chapter_line, "")
        later_chapters = sorted(
            line_no for line_no in mapped_chapter_lines if line_no > chapter_line
        )
        chapter_stop = later_chapters[0] if later_chapters else len(lines) + 1
        entry_line_set = set(entry_lines)
        local_ops: List[PendingOp] = []
        local_notes: List[dict] = []
        local_body_lines: set[int] = set()
        mapped_local_headings = 0
        last_body_line = stop - 1
        for entry_line in entry_lines:
            heading = _manual_toc_entry_heading(lines[entry_line - 1])
            if heading is None:
                continue
            printed_number = str(heading["number"])
            if printed_number and chapter_number:
                if printed_number.split(".", 1)[0] != chapter_number:
                    continue
            ranked = []
            for hit in candidates:
                if (
                    hit.line <= last_body_line
                    or hit.line >= chapter_stop
                    or hit.line in local_body_lines
                    or hit.line in entry_line_set
                ):
                    continue
                if heading.get("requires_styled_body") and not (
                    hit.kind == "styled"
                    or (
                        hit.kind == "command"
                        and hit.command in {"subsection", "subsubsection"}
                    )
                ):
                    continue
                score = _score_title(str(heading["title"]), hit.visible)
                if score >= 0.93:
                    ranked.append((-score, hit.line, hit))
            if not ranked:
                continue
            ranked.sort(key=lambda item: item[:2])
            body_heading = ranked[0][2]
            local_body_lines.add(body_heading.line)
            last_body_line = body_heading.line
            mapped_local_headings += 1
            # A PDF-outline entry may already have mapped this exact body
            # heading.  It still satisfies the local TOC transaction, but does
            # not need a second competing replacement.
            if body_heading.line in matched_lines:
                continue
            command = str(heading["command"])
            starred = bool(heading["starred"])
            claimed_title = str(heading["title"])
            # The printed TOC is only structural evidence.  The matched body
            # heading remains the content authority, including math commands,
            # accents, and other TeX that a simplified TOC label may omit.
            title = _title_without_number(body_heading.visible).strip()
            styled_title = _candidate_from_line(title, body_heading.line, body_heading.page)
            if (
                styled_title is not None
                and styled_title.kind == "styled"
                and not styled_title.trailing
            ):
                title = styled_title.visible.strip()
            if title.endswith(".") and not claimed_title.endswith("."):
                title = title[:-1].rstrip()
            if not title:
                title = claimed_title
            replacement = f"\\{command}{'*' if starred else ''}{{{title}}}"
            if body_heading.trailing:
                replacement += " " + body_heading.trailing
            local_ops.append(PendingOp(
                "replace_line",
                body_heading.line,
                old=lines[body_heading.line - 1],
                new=replacement,
            ))
            if starred:
                local_ops.append(PendingOp(
                    "insert_line",
                    body_heading.line,
                    new=(
                        f"\\addcontentsline{{toc}}{{{command}}}"
                        f"{{{claimed_title}}}"
                    ),
                ))
            local_notes.append({
                "line": body_heading.line,
                "status": "mapped-local-heading",
                "reason": (
                    "章首目录与正文标题双重确认 → "
                    f"\\{command}{'*' if starred else ''}{{{title}}}"
                ),
            })
        if mapped_local_headings != len(entry_lines):
            notes.append({
                "line": local_contents.line,
                "status": "deferred-local-toc",
                "reason": (
                    f"章首目录仅确认 {mapped_local_headings}/{len(entry_lines)} 个正文标题；"
                    "为避免丢失目录层级，原子化保留整个目录等待后续页面"
                ),
            })
            continue
        for op in local_ops:
            set_op(op)
        used.update(local_body_lines)
        matched_lines.update(local_body_lines)
        notes.extend(local_notes)
        set_op(PendingOp(
            "replace_line",
            local_contents.line,
            old=lines[local_contents.line - 1],
            new=LOCAL_TOC_MARKER,
        ))
        for line_no in removable:
            set_op(PendingOp("delete_line", line_no, old=lines[line_no - 1]))
        notes.append({
            "line": local_contents.line,
            "status": "mapped-local-toc",
            "reason": "已将章首手抄目录替换为可由成品模板重建的局部目录标记",
        })

    # 重复、位于稳定页首外边距且未映射到 PDF 大纲的短文本才可确定为
    # 运行页眉污染。普通/样式文本三行以后已经进入正文版心；只有明确的
    # starred section 页眉语法可使用稍宽边距。紧跟展示公式的短句尤其常见于
    # 定理陈述尾部，始终视为正文证据。
    unmatched_commands = [
        hit for hit in candidates
        if hit.kind in {"command", "plain", "styled"} and hit.line not in matched_lines
        and not hit.trailing
        and _plain_text(hit.visible) not in ("contents", "")
        and not _is_exercise_body_heading(lines, hit.line)
        and not _exercise_label_stem(lines[hit.line - 1])
    ]
    near_top = [
        hit for hit in unmatched_commands
        if _within_running_header_margin(
            hit, page_positions.get(hit.line, 10_000),
        )
        and not _follows_display_math(lines, hit.line)
    ]
    counts = Counter(_plain_text(hit.visible) for hit in near_top)
    pages_by_title = {
        title: {hit.page for hit in near_top if _plain_text(hit.visible) == title}
        for title in counts
    }
    for hit in unmatched_commands:
        normalized = _plain_text(hit.visible)
        if (
            _within_running_header_margin(
                hit, page_positions.get(hit.line, 10_000),
            )
            and not _follows_display_math(lines, hit.line)
            and counts[normalized] >= 2
            and len(pages_by_title.get(normalized, set())) >= 2
        ):
            set_op(PendingOp("delete_line", hit.line, old=lines[hit.line - 1]))
            notes.append({
                "line": hit.line,
                "status": "removed-header",
                "reason": f"移除跨页重复运行页眉：{hit.visible}",
            })

    # 只删除位于页段末尾、形态完全明确的印刷页码。正文中的普通数字不动。
    for line_no, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not _near_page_segment_end(lines, line_no):
            continue
        if re.fullmatch(r"\\hfill\s*(?:\d+|[ivxlcdm]+)", stripped, re.I):
            set_op(PendingOp("delete_line", line_no, old=line))
            notes.append({
                "line": line_no,
                "status": "removed-footer",
                "reason": "移除页段末尾由 \\hfill 排版的印刷页码",
            })
            continue
        if re.fullmatch(r"\\centerline\{\s*(?:\d+|[ivxlcdm]+)\s*\}", stripped, re.I):
            set_op(PendingOp("delete_line", line_no, old=line))
            notes.append({
                "line": line_no,
                "status": "removed-footer",
                "reason": "移除页段末尾的印刷页码",
            })
            continue
        if not re.fullmatch(r"(?:\d+|[ivxlcdm]+)", stripped, re.I):
            continue
        center_open, center_close = _center_bounds(lines, line_no)
        if not center_open:
            continue
        for target_line in range(center_open, center_close + 1):
            set_op(PendingOp("delete_line", target_line, old=lines[target_line - 1]))
        if center_open > 1 and lines[center_open - 2].strip() == r"\hrule":
            set_op(PendingOp("delete_line", center_open - 1, old=lines[center_open - 2]))
        notes.append({
            "line": line_no,
            "status": "removed-footer",
            "reason": "移除页段末尾的居中印刷页码",
        })

    # 老 OCR 书稿使用 elegantbook；有可靠大纲后按真实层级切回中性的 article/book。
    for line_no, line in enumerate(lines, start=1):
        match = DOCUMENTCLASS_RE.match(line)
        if match:
            target = "book" if kind == "book" else "article"
            if match.group(1).strip().lower() == "elegantbook":
                set_op(PendingOp(
                    "replace_line", line_no, old=line,
                    new=f"\\documentclass[11pt]{{{target}}}",
                ))
                notes.append({
                    "line": line_no,
                    "status": "mapped",
                    "reason": f"OCR 文档类按大纲层级改为 {target}，避免 0.1 与定理计数冲突",
                })
            break

    syntax_ops, syntax_notes = _build_syntax_repair_ops(lines)
    for op in syntax_ops:
        set_op(op)
    notes.extend(syntax_notes)

    return sorted(operations.values(), key=lambda op: (op.line, op.kind)), notes


def _actual_headings(text: str) -> List[dict]:
    lines = text.split("\n")
    pages = _page_map(lines)
    result = []
    for line_no, line in enumerate(lines, start=1):
        if re.fullmatch(
            r"\s*\\begin\{thebibliography\}\{[^{}\r\n]+\}\s*", line,
        ):
            result.append({
                "line": line_no,
                "page": pages[line_no],
                "cmd": "thebibliography",
                "starred": True,
                "title": "",
                "normalized": "thebibliography",
            })
            continue
        hit = _candidate_from_line(line, line_no, pages[line_no])
        if hit is None or hit.kind != "command":
            continue
        result.append({
            "line": line_no,
            "page": hit.page,
            "cmd": hit.command,
            "starred": hit.starred,
            "title": hit.visible,
            "normalized": _plain_text(hit.visible),
        })
    return result


def _metadata_supports_generated_toc(metadata: dict) -> bool:
    """Return true when the PDF outline is substantial enough for a TOC.

    ``source_has_toc`` records whether the source visibly printed a directory;
    it does not say whether the PDF outline already proves a navigable chapter
    tree.  Publication templates should generate a TOC for the latter as well.
    """
    outline = [item for item in metadata.get("outline", []) if item.get("title")]
    if not outline:
        return False
    minimum_level = min(int(item.get("level", 0)) for item in outline)
    top_titles = {
        _plain_text(str(item.get("title", "")))
        for item in outline
        if int(item.get("level", 0)) == minimum_level
        and _plain_text(str(item.get("title", "")))
    }
    return len(top_titles) >= 2 or (len(top_titles) == 1 and len(outline) >= 4)


def check_ocr_structure(text: str) -> dict:
    """校验结构化结果是否完整对应源 PDF 大纲与目录。"""
    metadata = parse_ocr_metadata(text)
    if not metadata:
        return {"checked": False, "ok": True, "issues": [], "expected": 0, "matched": 0}
    issues = []
    _exercise_ops, exercise_notes = _build_exercise_fidelity_ops(text.split("\n"))
    exercise_issue_reasons = {
        "normalized-exercise-heading": "练习标题仍是普通字重，未保留源书层级",
        "normalized-exercise-number": "有证据确认的练习编号仍未加粗",
        "repaired-exercise-divider": "练习难度分隔饰符仍含 OCR 错字 ))",
    }
    for note in exercise_notes:
        reason = exercise_issue_reasons.get(str(note.get("status", "")))
        if reason:
            issues.append({"line": note.get("line", 1), "reason": reason})
    actual = _actual_headings(text)
    active_text = _active_latex(text)
    active_toc_count = len(ACTIVE_TOC_RE.findall(active_text))
    class_match = re.search(
        r"\\documentclass(?:\[[^\]]*\])?\s*\{([^{}]+)\}", active_text,
    )
    actual_class = class_match.group(1).strip().lower() if class_match else ""
    elegant_output = actual_class == "elegantbook"
    faithful_output = (
        actual_class == "book"
        and "% LaTeXStruct template: faithfulbook v1" in text
    )
    cursor = 0
    matched = 0
    outline = metadata.get("outline", [])
    rejected_outline = []
    meaningful_outline = []
    for entry in outline:
        noise_reason = _outline_noise_reason(entry, outline)
        if noise_reason:
            rejected_outline.append({
                "title": str(entry.get("title", "")),
                "page": int(entry.get("page", 1)),
                "reason": noise_reason,
            })
        else:
            meaningful_outline.append(entry)
    for entry in meaningful_outline:
        expected = _plain_text(entry["title"])
        if (
            expected == "contents"
            and metadata.get("source_has_toc")
            and active_toc_count == 1
        ):
            # 标准目录命令会自行生成 Contents 标题；它不应再被伪造为普通章节，
            # 也不能额外写进目录列表本身。
            matched += 1
            continue
        if (elegant_output or faithful_output) and metadata["kind"] == "article":
            level = max(0, min(3, int(entry["level"])))
            expected_cmd = ("chapter", "section", "subsection", "subsubsection")[level]
        else:
            expected_cmd = _command_for(int(entry["level"]), metadata["kind"])
        found = None
        for index in range(cursor, len(actual)):
            virtual_bibliography = (
                expected in {"references", "bibliography"}
                and actual[index]["cmd"] == "thebibliography"
            )
            if (
                virtual_bibliography
                or _outline_title_is_exact(expected, actual[index]["normalized"])
            ):
                found = index
                break
        if found is None:
            issues.append({"reason": f"缺少 PDF 大纲标题：{entry['title']}"})
            continue
        item = actual[found]
        virtual_bibliography = (
            expected in {"references", "bibliography"}
            and item["cmd"] == "thebibliography"
        )
        if item["cmd"] != expected_cmd and not virtual_bibliography:
            issues.append({
                "line": item["line"],
                "reason": f"标题层级错误：{entry['title']} 应为 \\{expected_cmd}，实际为 \\{item['cmd']}",
            })
        cursor = found + 1
        matched += 1

    normalized_counts = Counter(item["normalized"] for item in actual if item["normalized"])
    expected_counts = Counter(
        _plain_text(item["title"]) for item in meaningful_outline
        if _plain_text(item["title"])
    )
    for title, count in normalized_counts.items():
        expected_count = expected_counts.get(title, 0)
        if count > max(1, expected_count):
            lines = [item["line"] for item in actual if item["normalized"] == title]
            issues.append({
                "line": lines[0],
                "reason": (
                    f"章节标题出现 {count} 次，但 PDF 大纲仅有 {expected_count} 次"
                    f"（疑似运行页眉）：{title}"
                ),
            })

    expected_class = metadata["kind"]
    allowed_classes = {expected_class, "elegantbook"}
    if faithful_output:
        allowed_classes.add("book")
    if actual_class not in allowed_classes:
        issues.append({
            "line": 1,
            "reason": (
                f"OCR 大纲需要 documentclass={expected_class}，"
                "或经过校验的 ElegantBook/faithfulbook 成品"
            ),
        })

    toc_expected = bool(metadata.get("source_has_toc")) or (
        (elegant_output or faithful_output)
        and _metadata_supports_generated_toc(metadata)
    )
    if toc_expected:
        if active_toc_count == 0:
            issues.append({
                "reason": "源目录或可靠章节树要求全局目录，但结果没有 \\tableofcontents",
            })
        elif active_toc_count > 1:
            issues.append({"reason": f"结果含 {active_toc_count} 个活动 \\tableofcontents，必须且只能保留一个"})
        if re.search(r"\\dotfill\b", active_text):
            issues.append({"reason": "结果仍含手抄目录的 \\dotfill 与旧页码"})

    # 运行页眉/页脚不属于正文；若自动清理器未能证明并删除，最终安全门必须
    # fail closed，不能让“章节正确”掩盖仍存在的版面噪声。
    lines = text.split("\n")
    pages = _page_map(lines)
    positions = _page_line_positions(lines)
    for line_no, line in enumerate(lines, start=1):
        local_contents = _candidate_from_line(line, line_no, pages[line_no])
        if (
            local_contents is None
            or local_contents.kind not in {"plain", "styled", "command"}
            or _plain_text(local_contents.visible) != "contents"
        ):
            continue
        entry_count = 0
        scan = line_no + 1
        while scan <= len(lines):
            stripped = lines[scan - 1].strip()
            if not stripped:
                scan += 1
                continue
            if _is_manual_toc_entry(stripped):
                entry_count += 1
                scan += 1
                continue
            break
        if entry_count < 3:
            continue
        has_preceding_chapter = any(
            (
                (previous := _candidate_from_line(
                    lines[previous_no - 1], previous_no, pages[previous_no]
                ))
                is not None
                and previous.kind == "command"
                and previous.command == "chapter"
                and pages.get(previous_no) == pages.get(line_no)
            )
            for previous_no in range(max(1, line_no - 5), line_no)
        )
        if has_preceding_chapter:
            issues.append({
                "line": line_no,
                "reason": "章首手抄目录尚未完成正文标题全量匹配，仍含旧页码",
            })
            break
    near_top = []
    for line_no, line in enumerate(lines, start=1):
        hit = _candidate_from_line(line, line_no, pages[line_no])
        if hit is None or hit.kind not in {"plain", "styled"}:
            continue
        if hit.trailing:
            continue
        if _is_exercise_body_heading(lines, line_no) or _exercise_label_stem(line):
            continue
        if _follows_display_math(lines, line_no):
            continue
        normalized = _plain_text(hit.visible)
        if (
            positions.get(line_no, 10_000) <= RUNNING_HEADER_MAX_TOP_OFFSET
            and len(normalized) >= 6
        ):
            near_top.append((line_no, hit.page, normalized, hit.visible))
    top_counts = Counter(item[2] for item in near_top)
    for line_no, _page, normalized, visible in near_top:
        distinct_pages = {item[1] for item in near_top if item[2] == normalized}
        if top_counts[normalized] >= 2 and len(distinct_pages) >= 2:
            issues.append({
                "line": line_no,
                "reason": f"仍有跨页重复运行页眉：{visible}",
            })
            break
    for line_no, line in enumerate(lines, start=1):
        stripped = line.strip()
        if (
            _near_page_segment_end(lines, line_no)
            and re.fullmatch(r"\\hfill\s*(?:\d+|[ivxlcdm]+)", stripped, re.I)
        ):
            issues.append({"line": line_no, "reason": "仍有由 \\hfill 排版的印刷页码页脚"})
            break
        if re.fullmatch(r"\\centerline\{\s*(?:\d+|[ivxlcdm]+)\s*\}", stripped, re.I):
            issues.append({"line": line_no, "reason": "仍有印刷页码页脚"})
            break
        if re.fullmatch(r"(?:\d+|[ivxlcdm]+)", stripped, re.I):
            center_open, _center_close = _center_bounds(lines, line_no)
            if center_open:
                issues.append({"line": line_no, "reason": "仍有居中印刷页码页脚"})
                break

    # 全文选页从第一页开始时，不允许 section/subsection 脱离父级。
    selected = metadata.get("pages") or []
    if not selected or min(selected) == 1:
        base = "chapter" if metadata["kind"] == "book" or elegant_output else "section"
        levels = {name: index for index, name in enumerate(
            ("chapter", "section", "subsection", "subsubsection")
            if base == "chapter" else ("section", "subsection", "subsubsection", "paragraph")
        )}
        seen = set()
        for item in actual:
            level = levels.get(item["cmd"])
            if level is None:
                continue
            if level > 0 and level - 1 not in seen:
                issues.append({
                    "line": item["line"],
                    "reason": f"章节跳级：\\{item['cmd']} 缺少父级标题",
                })
            seen = {value for value in seen if value < level}
            seen.add(level)

    result = {
        "checked": True,
        "ok": not issues,
        "issues": issues[:50],
        "expected": len(meaningful_outline),
        "matched": matched,
        "actual": len(actual),
        "toc_expected": toc_expected,
    }
    if rejected_outline:
        result["rejected_outline"] = rejected_outline
    return result

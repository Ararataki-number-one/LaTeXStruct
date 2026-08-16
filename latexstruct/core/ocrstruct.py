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
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

from .patch import PendingOp

META_PREFIX = "% LaTeXStruct-OCR-Metadata: "
META_RE = re.compile(r"^% LaTeXStruct-OCR-Metadata:\s*([A-Za-z0-9_=-]+)\s*$", re.M)
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
PLAIN_NUMBERED_HEADING_RE = re.compile(
    r"^\s*(?P<title>\d+(?:\.\d+)+\.?\s+.+?[.!?])(?:\s+(?P<trailing>.+))?$"
)
FRONT_MATTER = {
    "abstract", "acknowledgements", "acknowledgments", "contents", "foreword",
    "introduction", "notation", "preface", "references", "bibliography",
}


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
    payload = {
        "version": 1,
        "kind": "book" if document_kind == "book" else "article",
        "pages": sorted({int(p) for p in selected_pages if int(p) > 0})[:1000],
        "source_has_toc": bool(source_has_toc),
        "outline": cleaned,
    }
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    token = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    return META_PREFIX + token


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
    if not isinstance(payload, dict) or payload.get("version") != 1:
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
    return {
        "version": 1,
        "kind": kind,
        "pages": [int(p) for p in payload.get("pages", []) if isinstance(p, int) and p > 0],
        "source_has_toc": bool(payload.get("source_has_toc")),
        "outline": outline,
    }


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
    if stripped and len(stripped) <= 220 and not stripped.startswith(("%", "\\begin", "\\end")):
        return HeadingCandidate(line_no, page, stripped, "", "plain")
    return None


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
    return NUMBER_PREFIX_RE.sub("", value).strip()


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


def _command_for(level: int, kind: str) -> str:
    names = ("chapter", "section", "subsection", "subsubsection") if kind == "book" else (
        "section", "subsection", "subsubsection", "paragraph",
    )
    return names[min(max(level, 0), len(names) - 1)]


def _page_map(lines: List[str]) -> Dict[int, Optional[int]]:
    current: Optional[int] = None
    out = {}
    for index, line in enumerate(lines, start=1):
        match = PAGE_RE.match(line)
        if match:
            current = int(match.group(1))
        out[index] = current
    return out


def _page_line_positions(lines: List[str]) -> Dict[int, int]:
    """返回每行距当前 ``% Page`` 标记的行数，用于保守识别运行页眉。"""
    start = 0
    out = {}
    for index, line in enumerate(lines, start=1):
        if PAGE_RE.match(line):
            start = index
        out[index] = index - start if start else 10_000
    return out


def _manual_toc_region_is_safe(lines: List[str], start: int, stop: int) -> bool:
    """目录区只有可证明的列表/点线/页码框架时才允许整体替换。"""
    dotfill = 0
    for line_no in range(start, stop):
        stripped = lines[line_no - 1].strip()
        if not stripped or stripped.startswith("%"):
            continue
        if r"\dotfill" in stripped:
            dotfill += 1
            continue
        if re.fullmatch(r"\\(?:begin|end)\{(?:itemize|enumerate|center)\}", stripped):
            continue
        if re.match(r"^\\(?:vspace|vfill|smallskip|medskip|bigskip)\b", stripped):
            continue
        visible = re.sub(r"\\textbf\s*\{([^{}]*)\}", r"\1", stripped).strip()
        if re.fullmatch(r"[ivxlcdm]+|\d+", visible, re.I):
            continue
        # 未知活动文本可能是真实正文；整段不改，交给最终目录门禁拦截。
        return False
    return dotfill >= 1


def _center_bounds(lines: List[str], line_no: int) -> Tuple[int, int]:
    if line_no > 1 and line_no < len(lines):
        before, after = lines[line_no - 2].strip(), lines[line_no].strip()
        if before == "\\begin{center}" and after == "\\end{center}":
            return line_no - 1, line_no + 1
    return 0, 0


def _front_matter(title: str) -> bool:
    return _plain_text(title) in {_plain_text(item) for item in FRONT_MATTER}


def build_ocr_structure_ops(text: str) -> Tuple[List[PendingOp], List[dict]]:
    """把 PDF 大纲映射为章节命令；所有改动都通过可逆 PendingOp 表达。"""
    metadata = parse_ocr_metadata(text)
    if not metadata or not metadata.get("outline"):
        return [], []
    lines = text.split("\n")
    pages = _page_map(lines)
    page_positions = _page_line_positions(lines)
    kind = metadata["kind"]
    candidates = [
        hit for index, line in enumerate(lines, start=1)
        if (hit := _candidate_from_line(line, index, pages[index])) is not None
    ]
    used: set[int] = set()
    operations: Dict[Tuple[int, str], PendingOp] = {}
    notes: List[dict] = []
    matched_lines: set[int] = set()

    def set_op(op: PendingOp):
        operations[(op.line, op.kind)] = op

    for entry in metadata["outline"]:
        expected_page = int(entry["page"])
        ranked = []
        for hit in candidates:
            if hit.line in used:
                continue
            page_delta = abs((hit.page or expected_page) - expected_page)
            if page_delta > 1:
                continue
            score = _score_title(entry["title"], hit.visible)
            if score < 0.82:
                continue
            ranked.append((page_delta, -score, hit.line, hit))
        if not ranked:
            notes.append({
                "line": 1,
                "status": "missing",
                "reason": f"PDF 大纲标题未在 OCR 正文中找到：{entry['title']}",
            })
            continue
        ranked.sort(key=lambda row: row[:3])
        hit = ranked[0][3]
        used.add(hit.line)
        matched_lines.add(hit.line)
        command = _command_for(int(entry["level"]), kind)
        title = _title_without_number(hit.visible) or _title_without_number(entry["title"])
        expected_title = _title_without_number(entry["title"])
        # 行内标题常以句点和正文分隔；PDF 大纲不带该分隔符时，不把它写进
        # section 参数。问号/感叹号可能是标题本身，仍原样保留。
        if title.endswith(".") and not expected_title.endswith("."):
            title = title[:-1].rstrip()
        star = _front_matter(entry["title"]) and not NUMBER_PREFIX_RE.match(entry["title"])

        command_line = hit.line
        delete_title_line = False
        if kind == "book" and int(entry["level"]) == 0 and not star:
            # OCR 常把“Chapter 1”和真正章名拆成两个 section*；合并为一个 chapter。
            previous = next(
                (
                    item for item in candidates
                    if item.page == hit.page and item.line < hit.line
                    and hit.line - item.line <= 2 and CHAPTER_MARKER_RE.match(item.visible)
                ),
                None,
            )
            if previous is not None:
                command_line = previous.line
                used.add(previous.line)
                matched_lines.add(previous.line)
                delete_title_line = True

        trailing = hit.trailing
        replacement = f"\\{command}{'*' if star else ''}{{{title}}}"
        if trailing:
            replacement += " " + trailing
        set_op(PendingOp("replace_line", command_line, old=lines[command_line - 1], new=replacement))
        if delete_title_line and hit.line != command_line:
            set_op(PendingOp("delete_line", hit.line, old=lines[hit.line - 1]))
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
            "reason": f"PDF 大纲 L{int(entry['level']) + 1} → \\{command}{'*' if star else ''}{{{title}}}",
        })

    # 手抄目录只保存旧页码，重排后必然错误；换成可二次编译更新的真实目录。
    contents = next((hit for hit in candidates if _plain_text(hit.visible) == "contents"), None)
    if contents is not None and metadata.get("source_has_toc"):
        stop = len(lines) + 1
        for line_no in range(contents.line + 1, len(lines) + 1):
            if PAGE_BREAK_RE.match(lines[line_no - 1]) or lines[line_no - 1].strip() in (
                r"\clearpage", r"\newpage"
            ):
                stop = line_no
                break
        if _manual_toc_region_is_safe(lines, contents.line + 1, stop):
            set_op(PendingOp(
                "replace_line", contents.line,
                old=lines[contents.line - 1], new="\\tableofcontents",
            ))
            for line_no in range(contents.line + 1, stop):
                set_op(PendingOp("delete_line", line_no, old=lines[line_no - 1]))
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

    # 只有重复且未映射到 PDF 大纲的“章节命令”才可确定为运行页眉污染。
    unmatched_commands = [
        hit for hit in candidates
        if hit.kind == "command" and hit.line not in matched_lines
        and _plain_text(hit.visible) not in ("contents", "")
    ]
    near_top = [
        hit for hit in unmatched_commands
        if page_positions.get(hit.line, 10_000) <= 8
    ]
    counts = Counter(_plain_text(hit.visible) for hit in near_top)
    pages_by_title = {
        title: {hit.page for hit in near_top if _plain_text(hit.visible) == title}
        for title in counts
    }
    for hit in unmatched_commands:
        normalized = _plain_text(hit.visible)
        if (
            page_positions.get(hit.line, 10_000) <= 8
            and counts[normalized] >= 2
            and len(pages_by_title.get(normalized, set())) >= 2
        ):
            set_op(PendingOp("delete_line", hit.line, old=lines[hit.line - 1]))
            notes.append({
                "line": hit.line,
                "status": "removed-header",
                "reason": f"移除跨页重复运行页眉：{hit.visible}",
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

    return sorted(operations.values(), key=lambda op: (op.line, op.kind)), notes


def _actual_headings(text: str) -> List[dict]:
    lines = text.split("\n")
    pages = _page_map(lines)
    result = []
    for line_no, line in enumerate(lines, start=1):
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


def check_ocr_structure(text: str) -> dict:
    """校验结构化结果是否完整对应源 PDF 大纲与目录。"""
    metadata = parse_ocr_metadata(text)
    if not metadata:
        return {"checked": False, "ok": True, "issues": [], "expected": 0, "matched": 0}
    issues = []
    actual = _actual_headings(text)
    class_match = re.search(r"\\documentclass(?:\[[^\]]*\])?\s*\{([^{}]+)\}", text)
    actual_class = class_match.group(1).strip().lower() if class_match else ""
    elegant_output = actual_class == "elegantbook"
    cursor = 0
    matched = 0
    for entry in metadata.get("outline", []):
        expected = _plain_text(entry["title"])
        if (
            expected == "contents"
            and metadata.get("source_has_toc")
            and "\\tableofcontents" in text
        ):
            # 标准目录命令会自行生成 Contents 标题；它不应再被伪造为普通章节，
            # 也不能额外写进目录列表本身。
            matched += 1
            continue
        if elegant_output and metadata["kind"] == "article":
            level = max(0, min(3, int(entry["level"])))
            expected_cmd = ("chapter", "section", "subsection", "subsubsection")[level]
        else:
            expected_cmd = _command_for(int(entry["level"]), metadata["kind"])
        found = None
        for index in range(cursor, len(actual)):
            if _score_title(expected, actual[index]["normalized"]) >= 0.88:
                found = index
                break
        if found is None:
            issues.append({"reason": f"缺少 PDF 大纲标题：{entry['title']}"})
            continue
        item = actual[found]
        if item["cmd"] != expected_cmd:
            issues.append({
                "line": item["line"],
                "reason": f"标题层级错误：{entry['title']} 应为 \\{expected_cmd}，实际为 \\{item['cmd']}",
            })
        cursor = found + 1
        matched += 1

    normalized_counts = Counter(item["normalized"] for item in actual if item["normalized"])
    expected_counts = Counter(
        _plain_text(item["title"]) for item in metadata.get("outline", [])
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
    if actual_class not in {expected_class, "elegantbook"}:
        issues.append({
            "line": 1,
            "reason": f"OCR 大纲需要 documentclass={expected_class} 或固定 ElegantBook 成品",
        })

    if metadata.get("source_has_toc"):
        if "\\tableofcontents" not in text:
            issues.append({"reason": "源文档含目录，但结果没有 \\tableofcontents"})
        if re.search(r"\\dotfill\b", text):
            issues.append({"reason": "结果仍含手抄目录的 \\dotfill 与旧页码"})

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

    return {
        "checked": True,
        "ok": not issues,
        "issues": issues[:50],
        "expected": len(metadata.get("outline", [])),
        "matched": matched,
        "actual": len(actual),
        "toc_expected": bool(metadata.get("source_has_toc")),
    }

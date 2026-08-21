# -*- coding: utf-8 -*-
"""Evidence-gated semantic normalization for OCR LaTeX.

This stage sits after deterministic OCR outline recovery and before template
conversion.  It intentionally handles only two structures for which the
source gives a complete, reversible inventory:

* printed equation numbers backed one-for-one by version-2 PDF evidence;
* a References outline region containing top-level entries numbered exactly
  ``[1]`` through ``[N]`` with a provable end boundary.

The module never repairs mathematical payloads or guesses bibliography
boundaries.  Every edit is returned as a :class:`PendingOp`, so the ordinary
pipeline content-invariant check can reverse it byte-for-byte.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import asdict, dataclass
from typing import List, Optional, Tuple

from .ocrstruct import PAGE_RE, parse_ocr_metadata
from .parser import Block, mask_comments, parse_latex
from .patch import PendingOp

EQUATION_LABEL = r"[0-9]{1,4}[A-Za-z]?"
ACTIVE_TAG_RE = re.compile(
    rf"(?<!\\)\\tag\s*\{{(?P<label>{EQUATION_LABEL})\}}",
)
ANY_ACTIVE_TAG_RE = re.compile(r"(?<!\\)\\tag(?![A-Za-z@])")
LITERAL_PREFIX_RE = re.compile(
    rf"^(?P<indent>\s*)\\text\s*\{{\s*\((?P<label>{EQUATION_LABEL})\)\s*\}}"
    r"\s*\\qquad(?![A-Za-z@])(?P<rest>.*)$",
)
LITERAL_SUFFIX_RE = re.compile(
    rf"^(?P<body>.*?)(?P<marker>\\qquad(?![A-Za-z@])\s*"
    rf"\((?P<label>{EQUATION_LABEL})\)\s*)$",
)
ANY_LITERAL_RE = re.compile(
    rf"\\text\s*\{{\s*\((?P<prefix>{EQUATION_LABEL})\)\s*\}}"
    rf"|\\qquad(?![A-Za-z@])\s*\((?P<suffix>{EQUATION_LABEL})\)",
)
DISPLAY_OPEN_RE = re.compile(r"^(?P<indent>\s*)\\\[\s*$")
DISPLAY_CLOSE_RE = re.compile(r"^(?P<indent>\s*)\\\]\s*$")
MATH_ENVS = {
    "equation", "equation*", "align", "align*", "alignat", "alignat*",
    "flalign", "flalign*", "gather", "gather*", "multline", "multline*",
}

REFERENCE_KEYS = {"references", "bibliography"}
REFERENCE_HEADING_RE = re.compile(
    r"^(?P<indent>\s*)\\(?P<command>chapter|section|subsection|subsubsection)"
    r"\*?\s*\{\s*(?P<title>References|Bibliography)\s*\}\s*$",
    re.I,
)
NUMBERED_REFERENCE_RE = re.compile(
    r"^(?P<prefix>\s*(?:\\noindent\s*)?\[(?P<number>[1-9][0-9]*)\]"
    r"\s*(?:\\quad(?![A-Za-z@])\s*)?)(?P<body>\S.*)$",
)
ACTIVE_BIBITEM_RE = re.compile(r"\\bibitem(?![A-Za-z@])")
BIBITEM_HEADER_RE = re.compile(
    r"\\bibitem(?![A-Za-z@])\s*(?:\[(?P<display>[^\]\r\n]*)\]\s*)?"
    r"\{(?P<key>[^{}\r\n]+)\}",
)
BIBITEM_KEY_RE = re.compile(r"ref(?P<number>[1-9][0-9]*)")
THEBIBLIOGRAPHY_END_RE = re.compile(
    r"(?<!\\)\\end\s*\{thebibliography\}",
)
THEBIBLIOGRAPHY_BEGIN_RE = re.compile(
    r"^\s*\\begin\{thebibliography\}\{[^{}\r\n]+\}\s*$",
)
REFERENCE_PREAMBLE_RE = re.compile(
    r"^\s*(?:\\phantomsection|"
    r"\\addcontentsline\{toc\}\{(?:chapter|section|subsection)\}"
    r"\{(?:References|Bibliography)\})\s*$",
    re.I,
)
REFERENCE_BOUNDARY_RE = re.compile(
    r"^\s*\\(?:bigskip|medskip|smallskip)\s*$"
    r"|^\s*\\vspace\*?\s*\{[^{}\r\n]+\}\s*$",
)
REFERENCE_PAGINATION_RE = re.compile(r"^\s*\\(?:newpage|clearpage)\s*$")
REFERENCE_BOUNDARY_ENVS = {
    "center", "flushleft", "flushright", "minipage", "tabular", "tabular*",
}
DOCUMENTCLASS_LINE_RE = re.compile(
    r"^\s*\\documentclass(?:\[(?P<options>[^\]]*)\])?\s*\{[^{}]+\}\s*$",
)
PASS_AMSMATH_OPTIONS_RE = re.compile(
    r"^\s*\\PassOptionsToPackage\s*\{(?P<options>[^{}]+)\}"
    r"\s*\{\s*amsmath\s*\}\s*$",
)
USE_AMSMATH_RE = re.compile(
    r"^\s*\\(?:usepackage|RequirePackage)(?:\[(?P<options>[^\]]*)\])?"
    r"\s*\{[^{}]*\bamsmath\b[^{}]*\}\s*$",
)
LEFT_EQUATION_OPTION = r"\PassOptionsToPackage{leqno}{amsmath}"


@dataclass(frozen=True)
class EquationIR:
    page: Optional[int]
    label: str
    line: int
    column: int
    start_line: int
    end_line: int
    representation: str
    payload_sha256: str
    rewritable: bool

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class BibliographyEntryIR:
    number: int
    start_line: int
    end_line: int
    payload_sha256: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class FrontMatterIR:
    kind: str
    page: Optional[int]
    start_line: int
    end_line: int
    payload_sha256: str
    source: str

    def to_dict(self) -> dict:
        return asdict(self)


def _plain_key(value: str) -> str:
    value = unicodedata.normalize("NFKC", str(value or "")).casefold().strip()
    return "".join(character for character in value if character.isalnum())


def _payload_sha256(value: str) -> str:
    canonical = " ".join(value.split())
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _active_command_matches(
    text: str,
    pattern: re.Pattern[str],
) -> List[re.Match[str]]:
    """Return TeX command starts, accounting for preceding slash parity."""
    result = []
    for match in pattern.finditer(text):
        slash_count = 0
        cursor = match.start() - 1
        while cursor >= 0 and text[cursor] == "\\":
            slash_count += 1
            cursor -= 1
        if slash_count % 2 == 0:
            result.append(match)
    return result


def _option_set(value: str) -> set[str]:
    return {
        option.strip().casefold()
        for option in str(value or "").split(",")
        if option.strip()
    }


def _equation_tag_side(evidence: List[dict]) -> Tuple[str, List[str]]:
    """Classify only unambiguous outer-margin source boxes."""
    sides = []
    for item in evidence:
        bbox = item.get("bbox_normalized")
        if not isinstance(bbox, (list, tuple)) or len(bbox) != 4:
            sides.append("unknown")
            continue
        try:
            x0, _y0, x1, _y1 = (float(value) for value in bbox)
        except (TypeError, ValueError):
            sides.append("unknown")
            continue
        if 0.0 <= x0 < x1 <= 0.25:
            sides.append("left")
        elif 0.75 <= x0 < x1 <= 1.0:
            sides.append("right")
        else:
            sides.append("unknown")
    if not sides:
        return "not_applicable", sides
    if "unknown" in sides:
        return "unknown", sides
    if all(side == "left" for side in sides):
        return "left", sides
    if all(side == "right" for side in sides):
        return "right", sides
    return "mixed", sides


def _equation_side_option_plan(
    text: str,
    tag_side: str,
) -> Tuple[List[PendingOp], Optional[dict]]:
    """Keep the verified side stable even when a later template swaps class."""
    active_lines = mask_comments(text).split("\n")
    class_items = [
        (line_no, match)
        for line_no, line in enumerate(active_lines, start=1)
        if (match := DOCUMENTCLASS_LINE_RE.fullmatch(line)) is not None
    ]
    if len(class_items) != 1:
        return [], {
            "line": class_items[0][0] if class_items else 1,
            "reason": "无法唯一定位 documentclass，不能安全固定公式编号左右位置",
        }
    class_line, class_match = class_items[0]
    left_sources = []
    right_sources = []
    left_pass_before_class = False
    for line_no, line in enumerate(active_lines, start=1):
        if match := PASS_AMSMATH_OPTIONS_RE.fullmatch(line):
            options = _option_set(match.group("options"))
            if "leqno" in options:
                left_sources.append(line_no)
                left_pass_before_class = left_pass_before_class or line_no < class_line
            if "reqno" in options:
                right_sources.append(line_no)
        if match := USE_AMSMATH_RE.fullmatch(line):
            options = _option_set(match.group("options"))
            if "leqno" in options:
                left_sources.append(line_no)
            if "reqno" in options:
                right_sources.append(line_no)
    class_options = _option_set(class_match.group("options"))
    if "leqno" in class_options:
        left_sources.append(class_line)
    if "reqno" in class_options:
        right_sources.append(class_line)

    if tag_side == "left":
        if right_sources:
            return [], {
                "line": right_sources[0],
                "reason": "PDF 证据为左侧公式编号，但导言区显式要求 reqno",
            }
        if left_sources and not left_pass_before_class:
            return [], {
                "line": left_sources[0],
                "reason": (
                    "已有 leqno 设置未位于 documentclass 前，模板换类后无法保证仍然生效"
                ),
            }
        if left_pass_before_class:
            return [], None
        return [PendingOp(
            "insert_line", class_line - 1, new=LEFT_EQUATION_OPTION,
        )], None

    if tag_side == "right" and left_sources:
        return [], {
            "line": left_sources[0],
            "reason": "PDF 证据为右侧公式编号，但导言区显式要求 leqno",
        }
    return [], None


def _page_map(lines: List[str]) -> List[Optional[int]]:
    pages: List[Optional[int]] = [None] * (len(lines) + 1)
    current = None
    for line_no, line in enumerate(lines, start=1):
        match = PAGE_RE.match(line)
        if match:
            current = int(match.group(1))
        pages[line_no] = current
    return pages


def _outer_math_env_blocks(blocks: List[Block]) -> List[Block]:
    candidates = [
        block for block in blocks
        if block.kind == "env" and block.name in MATH_ENVS
    ]
    result = []
    for block in candidates:
        contained = any(
            other is not block
            and other.span.start_line <= block.span.start_line
            and block.span.end_line <= other.span.end_line
            and (
                other.span.start_line < block.span.start_line
                or block.span.end_line < other.span.end_line
            )
            for other in candidates
        )
        if not contained:
            result.append(block)
    return result


def _display_equation_ir(
    block: Block,
    lines: List[str],
    pages: List[Optional[int]],
) -> Tuple[Optional[EquationIR], List[PendingOp], Optional[dict]]:
    first = lines[block.span.start_line - 1]
    last = lines[block.span.end_line - 1]
    opener = DISPLAY_OPEN_RE.fullmatch(first)
    closer = DISPLAY_CLOSE_RE.fullmatch(last)
    active = mask_comments(block.text)
    broad = list(ANY_LITERAL_RE.finditer(active))
    if not broad:
        return None, [], None
    if opener is None or closer is None or block.span.end_line - block.span.start_line < 2:
        return None, [], {
            "line": block.span.start_line,
            "reason": "公式编号候选不在独立、完整的 \\[...\\] 展示公式块中",
        }
    if ANY_ACTIVE_TAG_RE.search(active):
        return None, [], {
            "line": block.span.start_line,
            "reason": "同一展示公式同时含普通编号与活动 \\tag，无法唯一归一化",
        }

    exact_hits = []
    for line_no in range(block.span.start_line + 1, block.span.end_line):
        line = lines[line_no - 1]
        if match := LITERAL_PREFIX_RE.fullmatch(line):
            exact_hits.append(("literal_prefix", line_no, match))
        if match := LITERAL_SUFFIX_RE.fullmatch(line):
            exact_hits.append(("literal_suffix", line_no, match))
    if len(broad) != 1 or len(exact_hits) != 1:
        return None, [], {
            "line": block.span.start_line,
            "reason": "同一展示公式中的普通编号不是唯一、可逆的前缀或后缀",
        }

    representation, marker_line, match = exact_hits[0]
    broad_label = broad[0].group("prefix") or broad[0].group("suffix")
    label = match.group("label")
    if label != broad_label:
        return None, [], {
            "line": marker_line,
            "reason": "展示公式编号解析结果不一致，已保留原文",
        }

    inner = list(lines[block.span.start_line:block.span.end_line - 1])
    marker_index = marker_line - block.span.start_line - 1
    marker_source = lines[marker_line - 1]
    ops = [
        PendingOp(
            "replace_line",
            block.span.start_line,
            old=first,
            new=opener.group("indent") + r"\begin{equation}",
        ),
        PendingOp(
            "replace_line",
            block.span.end_line,
            old=last,
            new=closer.group("indent") + r"\end{equation}",
        ),
    ]
    if representation == "literal_prefix":
        prefix_end = match.start("rest")
        replacement = match.group("indent") + marker_source[prefix_end:]
        inner[marker_index] = replacement
        ops.append(PendingOp(
            "replace_line", marker_line, old=marker_source, new=replacement,
        ))
        ops.append(PendingOp(
            "insert_line",
            block.span.end_line - 1,
            new=closer.group("indent") + rf"\tag{{{label}}}",
        ))
    else:
        body = match.group("body")
        inner[marker_index] = body
        replacement = body + rf"\tag{{{label}}}"
        ops.append(PendingOp(
            "replace_line", marker_line, old=marker_source, new=replacement,
        ))

    return EquationIR(
        page=pages[marker_line],
        label=label,
        line=marker_line,
        column=max(0, marker_source.find("(")),
        start_line=block.span.start_line,
        end_line=block.span.end_line,
        representation=representation,
        payload_sha256=_payload_sha256("\n".join(inner)),
        rewritable=True,
    ), ops, None


def _equation_plan(text: str, metadata: dict) -> Tuple[List[PendingOp], List[dict], dict]:
    lines = text.split("\n")
    pages = _page_map(lines)
    document = parse_latex(text)
    equations: List[EquationIR] = []
    rewrite_groups: List[Tuple[EquationIR, List[PendingOp]]] = []
    issues = []

    for block in document.blocks_of_kind("displaymath"):
        item, operations, issue = _display_equation_ir(block, lines, pages)
        if issue:
            issues.append(issue)
        if item is not None:
            equations.append(item)
            rewrite_groups.append((item, operations))

    for block in _outer_math_env_blocks(document.blocks):
        active = mask_comments(block.text)
        tags = list(ACTIVE_TAG_RE.finditer(active))
        if ANY_ACTIVE_TAG_RE.search(active) and not tags:
            issues.append({
                "line": block.span.start_line,
                "reason": "AMS 展示公式含无法验证的活动 \\tag 标签",
            })
            continue
        payload = ACTIVE_TAG_RE.sub("", active)
        payload = re.sub(
            rf"^\s*\\begin\{{{re.escape(block.name)}\}}(?:\{{[^\r\n]*\}})?",
            "",
            payload,
        )
        payload = re.sub(
            rf"\\end\{{{re.escape(block.name)}\}}\s*$", "", payload,
        )
        payload_hash = _payload_sha256(payload)
        for tag in tags:
            relative = active.count("\n", 0, tag.start())
            line_no = block.span.start_line + relative
            equations.append(EquationIR(
                page=pages[line_no],
                label=tag.group("label"),
                line=line_no,
                column=tag.start() - (active.rfind("\n", 0, tag.start()) + 1),
                start_line=block.span.start_line,
                end_line=block.span.end_line,
                representation="active_tag",
                payload_sha256=payload_hash,
                rewritable=False,
            ))

    equations.sort(key=lambda item: (item.line, item.column))
    evidence = list(metadata.get("equation_tags") or [])
    evidence_pairs = [
        (int(item["page"]), str(item["label"])) for item in evidence
    ]
    actual_pairs = [(item.page, item.label) for item in equations]
    has_v2_evidence = int(metadata.get("version", 1)) >= 2
    tag_side, tag_side_inventory = _equation_tag_side(evidence)
    evidence_ordered = all(
        (right[0], right_bbox[1], right_bbox[0])
        >= (left[0], left_bbox[1], left_bbox[0])
        for (left, left_bbox), (right, right_bbox) in zip(
            [(pair, item["bbox_normalized"]) for pair, item in zip(evidence_pairs, evidence)],
            [(pair, item["bbox_normalized"]) for pair, item in zip(evidence_pairs, evidence)][1:],
        )
    )

    report = {
        "checked": True,
        "metadata_version": int(metadata.get("version", 1)),
        "source_evidence": len(evidence),
        "detected": len(equations),
        "literal": sum(item.representation.startswith("literal_") for item in equations),
        "active": sum(item.representation == "active_tag" for item in equations),
        "rewritten": 0,
        "inventory": [item.to_dict() for item in equations],
        "evidence_pairs": [list(pair) for pair in evidence_pairs],
        "actual_pairs": [list(pair) for pair in actual_pairs],
        "tag_side": tag_side,
        "tag_side_inventory": tag_side_inventory,
        "tag_side_option": "none",
        "issues": list(issues),
    }
    if not has_v2_evidence:
        report.update({"ok": True, "status": "inventory_only"})
        return [], [], report

    if not evidence_ordered:
        report["issues"].append({
            "line": 1,
            "reason": "PDF 公式编号证据未按页面与原页纵向位置排序",
        })
    if actual_pairs != evidence_pairs:
        report["issues"].append({
            "line": equations[0].line if equations else 1,
            "reason": (
                "活动/普通公式编号清单与 metadata v2 的 PDF 源证据未一一对应；"
                "整类公式改写已关闭"
            ),
        })
    if evidence and tag_side not in {"left", "right"}:
        report["issues"].append({
            "line": equations[0].line if equations else 1,
            "reason": (
                "PDF 公式编号横向位置不是全局一致、明确的左侧或右侧；"
                "整类公式改写已关闭"
            ),
        })
    if report["issues"] or not evidence_ordered or actual_pairs != evidence_pairs:
        report.update({"ok": False, "status": "rejected"})
        return [], [{
            "line": item.get("line", 1),
            "status": "rejected",
            "reason": item.get("reason", "公式语义证据校验失败"),
        } for item in report["issues"]], report

    operations = [
        operation
        for item, group in rewrite_groups
        if item in equations
        for operation in group
    ]
    side_operations, side_issue = _equation_side_option_plan(text, tag_side)
    if side_issue is not None:
        report["issues"].append(side_issue)
        report.update({"ok": False, "status": "rejected"})
        return [], [{
            "line": side_issue.get("line", 1),
            "status": "rejected",
            "reason": side_issue["reason"],
        }], report
    operations.extend(side_operations)
    if side_operations:
        report["tag_side_option"] = "inserted_pass_options_leqno"
    elif tag_side == "left":
        report["tag_side_option"] = "verified_existing_pass_options_leqno"
    report.update({
        "ok": True,
        "status": "normalized" if operations else "verified",
        "rewritten": len(rewrite_groups),
    })
    notes = [{
        "line": item.line,
        "status": "normalized-equation-tag",
        "reason": (
            f"PDF 第 {item.page} 页公式编号 ({item.label}) 已在同一完整展示公式内"
            "转换为活动 AMS 标签"
        ),
    } for item, _group in rewrite_groups]
    if side_operations:
        notes.append({
            "line": side_operations[0].line + 1,
            "status": "normalized-equation-tag-side",
            "reason": (
                "PDF 横向证据一致显示公式编号在左侧；已在 documentclass 前固定"
                " amsmath leqno，后续模板换类仍保留"
            ),
        })
    return operations, notes, report


def _top_level_block(block: Block) -> bool:
    if not block.in_env:
        return True
    return block.kind == "env" and block.in_env == (block.name,)


def _reference_entry(block: Block, lines: List[str]) -> Tuple[Optional[BibliographyEntryIR], str]:
    first = lines[block.span.start_line - 1]
    match = NUMBERED_REFERENCE_RE.fullmatch(first)
    if match is None:
        return None, ""
    payload_lines = [match.group("body")]
    payload_lines.extend(lines[block.span.start_line:block.span.end_line])
    return BibliographyEntryIR(
        number=int(match.group("number")),
        start_line=block.span.start_line,
        end_line=block.span.end_line,
        payload_sha256=_payload_sha256("\n".join(payload_lines)),
    ), match.group("prefix")


def _existing_bibliography_report(
    document,
    lines: List[str],
    pages: List[Optional[int]],
    reference_page: int,
) -> Optional[dict]:
    environments = [
        block for block in document.blocks
        if block.kind == "env" and block.name == "thebibliography"
    ]
    matching = [
        block for block in environments if pages[block.span.start_line] == reference_page
    ]
    if not environments:
        return None
    if len(environments) != 1 or len(matching) != 1:
        return {
            "checked": True,
            "ok": False,
            "status": "rejected",
            "detected": 0,
            "inventory": [],
            "issues": [{
                "line": environments[0].span.start_line,
                "reason": "thebibliography 环境无法唯一归属 PDF References 大纲区域",
            }],
        }
    block = matching[0]
    original = block.text
    active = mask_comments(original)
    commands = _active_command_matches(active, ACTIVE_BIBITEM_RE)
    environment_end = list(THEBIBLIOGRAPHY_END_RE.finditer(active))
    body_end = environment_end[-1].start() if environment_end else len(active)
    entries = []
    issues = []
    keys = []
    for index, command in enumerate(commands):
        line_no = block.span.start_line + active.count("\n", 0, command.start())
        header = BIBITEM_HEADER_RE.match(active, command.start())
        if header is None:
            issues.append({
                "line": line_no,
                "reason": "已有 thebibliography 含无法完整解析的活动 \\bibitem",
            })
            continue
        key = header.group("key")
        key_match = BIBITEM_KEY_RE.fullmatch(key)
        keys.append(key)
        if key_match is None:
            issues.append({
                "line": line_no,
                "reason": f"已有 thebibliography 含不可识别的活动 bibitem 键 {key!r}",
            })
            continue
        number_text = key_match.group("number")
        display = header.group("display")
        if display is not None:
            display_text = display.strip()
            if (
                re.fullmatch(r"[1-9][0-9]*", display_text) is None
                or display_text != number_text
            ):
                issues.append({
                    "line": line_no,
                    "reason": (
                        f"已有 thebibliography 的 {key} 可选显示号必须省略，"
                        f"或为严格相同的纯数字 [{number_text}]"
                    ),
                })

        next_start = (
            commands[index + 1].start()
            if index + 1 < len(commands)
            else body_end
        )
        # Comments are not active LaTeX.  Physical page-break controls inserted
        # between OCR pages likewise delimit layout rather than bibliography
        # payload, so they do not make the preceding entry's semantic hash drift.
        payload_lines = []
        for line in active[header.end():next_start].split("\n"):
            if REFERENCE_PAGINATION_RE.fullmatch(line):
                continue
            payload_lines.append(line)
        payload = "\n".join(payload_lines)
        if not payload.strip():
            issues.append({
                "line": line_no,
                "reason": f"已有 thebibliography 的 {key} 没有可验证正文",
            })
            continue
        payload_end = header.end() + len(
            active[header.end():next_start].rstrip()
        )
        end_line = block.span.start_line + active.count("\n", 0, payload_end)
        entries.append(BibliographyEntryIR(
            number=int(number_text),
            start_line=line_no,
            end_line=max(line_no, end_line),
            payload_sha256=_payload_sha256(payload),
        ))

    expected_keys = [f"ref{number}" for number in range(1, len(commands) + 1)]
    if not commands:
        issues.append({
            "line": block.span.start_line,
            "reason": "已有 thebibliography 不含任何活动 \\bibitem",
        })
    elif keys != expected_keys or len(entries) != len(commands):
        issues.append({
            "line": block.span.start_line,
            "reason": (
                "已有 thebibliography 的所有活动 bibitem 必须唯一且恰为"
                " ref1..refN（不得缺号、重复或含额外键）"
            ),
        })
    valid = not issues
    return {
        "checked": True,
        "ok": valid,
        "status": "already_structured" if valid else "rejected",
        "detected": len(commands),
        "active_bibitem_count": len(commands),
        "inventory": [item.to_dict() for item in entries],
        "payload_sha256": _payload_sha256("\n".join(
            item.payload_sha256 for item in entries
        )),
        "issues": issues,
    }


def _bibliography_plan(text: str, metadata: dict) -> Tuple[List[PendingOp], List[dict], dict]:
    outline = [
        item for item in metadata.get("outline", [])
        if _plain_key(item.get("title", "")) in REFERENCE_KEYS
    ]
    if not outline:
        return [], [], {
            "checked": False,
            "ok": True,
            "status": "not_applicable",
            "detected": 0,
            "inventory": [],
            "issues": [],
        }
    if len(outline) != 1:
        report = {
            "checked": True,
            "ok": False,
            "status": "rejected",
            "detected": 0,
            "inventory": [],
            "issues": [{
                "line": 1,
                "reason": "PDF 大纲含多个 References/Bibliography 节点，边界不唯一",
            }],
        }
        return [], [{"line": 1, "status": "rejected", "reason": report["issues"][0]["reason"]}], report

    lines = text.split("\n")
    pages = _page_map(lines)
    document = parse_latex(text)
    reference_page = int(outline[0]["page"])
    existing = _existing_bibliography_report(document, lines, pages, reference_page)
    if existing is not None:
        notes = [{
            "line": item.get("line", 1),
            "status": "rejected",
            "reason": item.get("reason", "参考文献环境不可验证"),
        } for item in existing["issues"]]
        return [], notes, existing

    headings = []
    for line_no, line in enumerate(lines, start=1):
        match = REFERENCE_HEADING_RE.fullmatch(line)
        if match and pages[line_no] == reference_page:
            headings.append((line_no, match))
    if len(headings) != 1:
        report = {
            "checked": True,
            "ok": False,
            "status": "rejected",
            "detected": 0,
            "inventory": [],
            "issues": [{
                "line": headings[0][0] if headings else 1,
                "reason": "无法在 PDF References 大纲页唯一定位参考文献标题",
            }],
        }
        return [], [{"line": report["issues"][0]["line"], "status": "rejected", "reason": report["issues"][0]["reason"]}], report

    heading_line, heading_match = headings[0]
    top_blocks = [
        block for block in document.blocks
        if _top_level_block(block) and block.span.start_line > heading_line
    ]
    in_reference_region = []
    for block in top_blocks:
        if block.section_path and _plain_key(block.section_path[-1]) not in REFERENCE_KEYS:
            break
        in_reference_region.append(block)

    entries: List[BibliographyEntryIR] = []
    prefixes: List[str] = []
    started = False
    boundary_index = None
    issues = []
    for index, block in enumerate(in_reference_region):
        if block.kind == "para" and block.span.start_line == heading_line:
            continue
        first = lines[block.span.start_line - 1]
        if not started and block.kind == "para" and REFERENCE_PREAMBLE_RE.fullmatch(first):
            continue
        item, prefix = (
            _reference_entry(block, lines) if block.kind == "para" and not block.in_env
            else (None, "")
        )
        if item is not None:
            if boundary_index is not None:
                issues.append({
                    "line": item.start_line,
                    "reason": "参考文献编号在已判定的结束边界之后再次出现",
                })
                break
            started = True
            entries.append(item)
            prefixes.append(prefix)
            continue
        if not started:
            # A title paragraph can contain \addcontentsline on its following
            # line.  Anything else before [1] makes the start boundary unclear.
            if block.kind == "para" and block.span.start_line == heading_line:
                continue
            issues.append({
                "line": block.span.start_line,
                "reason": "References 标题与 [1] 之间含无法归类的顶层内容",
            })
            break
        if block.kind == "para" and REFERENCE_PAGINATION_RE.fullmatch(first):
            next_entry = None
            for later in in_reference_region[index + 1:]:
                later_first = lines[later.span.start_line - 1]
                candidate, _candidate_prefix = (
                    _reference_entry(later, lines)
                    if later.kind == "para" and not later.in_env
                    else (None, "")
                )
                if candidate is not None:
                    next_entry = candidate
                    break
                if (
                    later.kind == "para"
                    and REFERENCE_PAGINATION_RE.fullmatch(later_first)
                ):
                    continue
                break
            if next_entry is not None:
                # A physical OCR page break inside a continuous [1]..[N]
                # sequence is pagination evidence, not the bibliography end.
                continue
        boundary_index = index
        valid_boundary = (
            (block.kind == "para" and REFERENCE_BOUNDARY_RE.fullmatch(first))
            or (block.kind == "para" and REFERENCE_PAGINATION_RE.fullmatch(first))
            or (block.kind == "env" and block.name in REFERENCE_BOUNDARY_ENVS)
        )
        if not valid_boundary:
            issues.append({
                "line": block.span.start_line,
                "reason": "最后一条参考文献后的结束边界不确定",
            })
            break

    numbers = [item.number for item in entries]
    if entries and numbers != list(range(1, len(entries) + 1)):
        issues.append({
            "line": entries[0].start_line,
            "reason": "参考文献必须从 [1] 开始且无缺号、重复或倒序",
        })
    if not entries:
        # A References heading with no numbered candidate is valid source text,
        # but supplies no authority for an automatic bibliography rewrite.
        report = {
            "checked": True,
            "ok": not issues,
            "status": "not_applicable" if not issues else "rejected",
            "detected": 0,
            "inventory": [],
            "issues": issues,
        }
        notes = [{
            "line": item.get("line", 1),
            "status": "rejected",
            "reason": item["reason"],
        } for item in issues]
        return [], notes, report
    if issues:
        report = {
            "checked": True,
            "ok": False,
            "status": "rejected",
            "detected": len(entries),
            "inventory": [item.to_dict() for item in entries],
            "issues": issues,
        }
        return [], [{
            "line": item.get("line", 1),
            "status": "rejected",
            "reason": item["reason"],
        } for item in issues], report

    operations = [PendingOp(
        "replace_line",
        heading_line,
        old=lines[heading_line - 1],
        new=heading_match.group("indent") + rf"\begin{{thebibliography}}{{{len(entries)}}}",
    )]
    for item, prefix in zip(entries, prefixes):
        operations.append(PendingOp(
            "replace_prefix",
            item.start_line,
            old=prefix,
            new=rf"\bibitem{{ref{item.number}}} ",
        ))
    operations.append(PendingOp(
        "insert_line", entries[-1].end_line, new=r"\end{thebibliography}",
    ))
    report = {
        "checked": True,
        "ok": True,
        "status": "normalized",
        "detected": len(entries),
        "inventory": [item.to_dict() for item in entries],
        "payload_sha256": _payload_sha256("\n".join(
            item.payload_sha256 for item in entries
        )),
        "issues": [],
    }
    return operations, [{
        "line": heading_line,
        "status": "normalized-bibliography",
        "reason": f"References 区连续 [1]..[{len(entries)}] 已转换为可编辑 bibitem",
    }], report


def _frontmatter_inventory(text: str, metadata: dict) -> dict:
    """Inventory explicit front-matter atoms without inferring new semantics."""
    lines = text.split("\n")
    pages = _page_map(lines)
    document = parse_latex(text)
    first_section_line = min(
        (section.span.start_line for section in document.sections),
        default=len(lines) + 1,
    )
    selected_pages = list(metadata.get("pages") or [])
    first_page = min(selected_pages) if selected_pages else None
    atoms: List[FrontMatterIR] = []

    command_kinds = {
        r"\frontmatter": "frontmatter_start",
        r"\tableofcontents": "table_of_contents",
        r"\mainmatter": "mainmatter_start",
        r"\maketitle": "maketitle",
    }
    for line_no, line in enumerate(lines, start=1):
        kind = command_kinds.get(line.strip())
        if kind:
            atoms.append(FrontMatterIR(
                kind=kind,
                page=pages[line_no],
                start_line=line_no,
                end_line=line_no,
                payload_sha256=_payload_sha256(line.strip()),
                source="explicit_latex_command",
            ))

    for block in document.blocks:
        if block.kind != "env" or block.name not in {"abstract", "center"}:
            continue
        page = pages[block.span.start_line]
        if block.name == "center":
            # A centered block is only inventoried as a title-page candidate on
            # the first selected page and before the first active section.  It
            # is never split into guessed title/author/date fields.
            if page != first_page or block.span.start_line >= first_section_line:
                continue
            nonempty = [line for line in block.text.splitlines()[1:-1] if line.strip()]
            if len(nonempty) < 2:
                continue
            kind = "title_page_center"
            source = "first_page_center_environment"
        else:
            kind = "abstract"
            source = "explicit_abstract_environment"
        atoms.append(FrontMatterIR(
            kind=kind,
            page=page,
            start_line=block.span.start_line,
            end_line=block.span.end_line,
            payload_sha256=_payload_sha256(block.text),
            source=source,
        ))
    atoms.sort(key=lambda item: (item.start_line, item.end_line, item.kind))
    return {
        "checked": True,
        "ok": True,
        "status": "inventory_only",
        "detected": len(atoms),
        "inventory": [item.to_dict() for item in atoms],
        "issues": [],
    }


def build_ocr_semantic_ops(text: str) -> Tuple[List[PendingOp], List[dict], dict]:
    """Return reversible OCR semantic edits plus a machine-readable gate report."""
    metadata = parse_ocr_metadata(text)
    if not metadata:
        return [], [], {
            "checked": False,
            "ok": True,
            "equations": {"checked": False, "ok": True, "status": "not_applicable"},
            "bibliography": {"checked": False, "ok": True, "status": "not_applicable"},
            "frontmatter": {"checked": False, "ok": True, "status": "not_applicable"},
            "issues": [],
        }
    equation_ops, equation_notes, equations = _equation_plan(text, metadata)
    bibliography_ops, bibliography_notes, bibliography = _bibliography_plan(text, metadata)
    frontmatter = _frontmatter_inventory(text, metadata)
    issues = (
        list(equations.get("issues") or [])
        + list(bibliography.get("issues") or [])
        + list(frontmatter.get("issues") or [])
    )
    report = {
        "checked": True,
        "ok": bool(
            equations.get("ok")
            and bibliography.get("ok")
            and frontmatter.get("ok")
        ),
        "equations": equations,
        "bibliography": bibliography,
        "frontmatter": frontmatter,
        "operations": len(equation_ops) + len(bibliography_ops),
        "issues": issues,
    }
    return equation_ops + bibliography_ops, equation_notes + bibliography_notes, report

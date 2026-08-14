# -*- coding: utf-8 -*-
"""补丁模型与应用引擎（M1 MVP，纯标准库）。

核心设计（对应设计文档 §14）：

- 一切修改以**可逆编辑**表达：插入整行 / 删除整行 / 整行替换 / 行内前缀替换；
- 插入文本只允许两种来源：固定结构模板、源文件自身逐字符子串（搬移）；
- 应用引擎按**升序**处理编辑并记录每条编辑在结果中的**最终行号**，
  从而支持"逆序撤销"：撤销全部编辑后必须与原文逐字符一致 ——
  这就是"内容不变"机器校验的实现基础（任何未被记录的改动都会导致比对失败）。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

AMSTHM_BLOCK = [
    "\\usepackage{amsthm}",
    "\\newtheorem{definition}{Definition}",
    "\\newtheorem{theorem}{Theorem}",
    "\\newtheorem{lemma}{Lemma}",
    "\\newtheorem{proposition}{Proposition}",
    "\\newtheorem{corollary}{Corollary}",
    "\\theoremstyle{remark}",
    "\\newtheorem{remark}{Remark}",
    "\\theoremstyle{definition}",
    "\\newtheorem{example}{Example}",
]

ITEM_PREFIX_RE = re.compile(r"^(\s*\d+\.\s*)")


@dataclass
class Decision:
    candidate_id: str
    action: str  # wrap | move-boundary | convert-to-exercise-env | merge-bilingual-title | preamble-add | none
    env: str = ""
    title_span: Optional[Tuple[int, int]] = None
    body_span: Optional[Tuple[int, int]] = None
    optional_arg: str = ""
    keep_title_text: bool = True
    source: str = "rule"
    reason: str = ""
    confidence: float = 0.0
    payload: Dict = field(default_factory=dict)


@dataclass
class Edit:
    kind: str  # insert_line | delete_line | replace_line | replace_prefix
    line: int  # 应用后的最终行号（1 基）
    old: str = ""
    new: str = ""


@dataclass
class AppliedPatch:
    decision: Decision
    edits: List[Edit]
    error: str = ""


@dataclass
class PendingOp:
    kind: str
    line: int  # 原始行号（1 基；insert 表示"插到该行之后"，0 表示文件头）
    old: str = ""
    new: str = ""


@dataclass
class PatchContext:
    is_elegantbook: bool = False
    existing_envs: set = field(default_factory=set)  # 已声明（不是仅被使用）的环境
    theorem_package: str = ""  # amsthm | ntheorem | ""
    exercise_env: str = "enumerate"
    preamble_anchor: int = 0  # \begin{document} 行号；0 = 无导言区


# ---------------------------------------------------------------------------
# 决策 → 编辑计划
# ---------------------------------------------------------------------------


def build_ops(decision: Decision, lines: List[str], ctx: PatchContext) -> Tuple[List[PendingOp], str]:
    a = decision.action
    if a == "none":
        return [], ""
    if a == "wrap":
        bs, be = decision.body_span or (0, 0)
        if not bs or not be or bs > be or be > len(lines):
            return [], f"wrap 范围 ({bs}, {be}) 非法"
        begin = f"\\begin{{{decision.env}}}"
        if decision.optional_arg:
            begin += f"[{decision.optional_arg}]"
        ops = [
            PendingOp("insert_line", bs - 1, new=begin),
            PendingOp("insert_line", be, new=f"\\end{{{decision.env}}}"),
        ]
        # 编号/标题词条剥离（keep_title_text=False 且给出可剥离前缀时）
        prefix = decision.payload.get("title_prefix", "") if not decision.keep_title_text else ""
        if prefix and lines[bs - 1].startswith(prefix):
            ops.append(PendingOp("replace_prefix", bs, old=prefix, new=""))
        return ops, ""

    if a == "move-boundary":
        old_end = decision.payload.get("old_end_line", 0)
        new_end = decision.payload.get("new_end_line", 0)
        if not (1 <= old_end <= len(lines)):
            return [], f"旧边界行 {old_end} 越界"
        line_content = lines[old_end - 1]
        if not re.match(rf"^\s*\\end\{{{re.escape(decision.env)}}}\s*$", line_content):
            return [], f"行 {old_end} 不是 \\end{{{decision.env}}}，保守放弃"
        return [
            PendingOp("delete_line", old_end, old=line_content),
            PendingOp("insert_line", new_end, new=f"\\end{{{decision.env}}}"),
        ], ""

    if a == "convert-to-exercise-env":
        env = decision.env or ctx.exercise_env
        items = sorted(decision.payload.get("item_lines", []))
        if len(items) < 2:
            return [], "习题条目少于 2 个，保守放弃"
        ops = [PendingOp("insert_line", items[0] - 1, new=f"\\begin{{{env}}}")]
        for L in items:
            if not (1 <= L <= len(lines)):
                return [], f"习题条目行 {L} 越界"
            m = ITEM_PREFIX_RE.match(lines[L - 1])
            if not m:
                return [], f"行 {L} 缺少裸编号前缀，保守放弃"
            ops.append(PendingOp("replace_prefix", L, old=m.group(1), new="\\item "))
        ops.append(PendingOp("insert_line", items[-1], new=f"\\end{{{env}}}"))
        return ops, ""

    if a == "merge-bilingual-title":
        sec_line = decision.payload.get("section_line", 0)
        cmd = decision.payload.get("section_cmd", "section")
        en = decision.payload.get("en_title", "")
        cn = decision.payload.get("cn_title", "")
        bl, be = decision.payload.get("box_lines", (0, 0))
        if not (1 <= sec_line <= len(lines)) or not (1 <= bl <= be <= len(lines)):
            return [], "双语标题合并范围越界"
        old_line = lines[sec_line - 1]
        if old_line.strip() != f"\\{cmd}*{{{en}}}":
            return [], f"行 {sec_line} 与英文标题不符，保守放弃"
        merged = f"\\{cmd}*{{{en}（{cn}）}}"
        ops = [
            PendingOp("replace_line", sec_line, old=old_line, new=merged),
            PendingOp("insert_line", sec_line, new=f"\\addcontentsline{{toc}}{{{cmd}}}{{{en}（{cn}）}}"),
        ]
        for L in range(be, bl - 1, -1):
            ops.append(PendingOp("delete_line", L, old=lines[L - 1]))
        return ops, ""

    if a == "preamble-add":
        if ctx.preamble_anchor <= 0:
            return [], "无导言区锚点"
        ops = []
        required_envs = (
            set(decision.payload.get("required_envs", []))
            if "required_envs" in decision.payload
            else None
        )
        for text in AMSTHM_BLOCK:
            if text == "\\usepackage{amsthm}" and ctx.theorem_package:
                continue
            if text.startswith("\\theoremstyle") and ctx.theorem_package == "ntheorem":
                continue
            declared = re.match(r"\\newtheorem\{([^{}]+)\}", text)
            if declared:
                env_name = declared.group(1)
                if env_name in ctx.existing_envs:
                    continue
                if required_envs is not None and env_name not in required_envs:
                    continue
            ops.append(PendingOp("insert_line", ctx.preamble_anchor - 1, new=text))
        return ops, ""

    return [], f"未知动作 {a}"


# ---------------------------------------------------------------------------
# 预校验 + 应用
# ---------------------------------------------------------------------------

_RANK = {"delete_line": 0, "replace_line": 1, "replace_prefix": 1, "insert_line": 2}


def validate_ops(lines: List[str], planned: List[Tuple[Decision, List[PendingOp]]]):
    ok = []
    rejected = []
    for d, ops in planned:
        err = ""
        for op in ops:
            if op.kind in ("delete_line", "replace_line"):
                if not (1 <= op.line <= len(lines)) or lines[op.line - 1] != op.old:
                    err = f"行 {op.line} 内容与预期不符或越界，保守放弃"
                    break
            elif op.kind == "replace_prefix":
                if not (1 <= op.line <= len(lines)) or not lines[op.line - 1].startswith(op.old):
                    err = f"行 {op.line} 前缀与预期不符，保守放弃"
                    break
            elif op.kind == "insert_line":
                if not (0 <= op.line <= len(lines)):
                    err = f"插入锚点行 {op.line} 越界"
                    break
        if err:
            rejected.append(AppliedPatch(decision=d, edits=[], error=err))
        else:
            ok.append((d, ops))
    return ok, rejected


def apply_patches(
    lines: List[str], planned: List[Tuple[Decision, List[PendingOp]]]
) -> Tuple[List[str], List[AppliedPatch], List[AppliedPatch]]:
    ok_planned, rejected = validate_ops(lines, planned)
    flat = []
    for d, ops in ok_planned:
        for op in ops:
            flat.append((d, op))
    flat.sort(key=lambda t: (t[1].line, _RANK[t[1].kind]))

    out = list(lines)
    delta = 0
    by_decision: Dict[str, AppliedPatch] = {}
    order: List[str] = []
    for d, op in flat:
        key = d.candidate_id
        if key not in by_decision:
            by_decision[key] = AppliedPatch(decision=d, edits=[])
            order.append(key)
        ap = by_decision[key]
        if op.kind == "insert_line":
            idx = op.line + delta
            out.insert(idx, op.new)
            delta += 1
            ap.edits.append(Edit("insert_line", idx + 1, old="", new=op.new))
        elif op.kind == "delete_line":
            idx = op.line - 1 + delta
            del out[idx]
            delta -= 1
            ap.edits.append(Edit("delete_line", idx + 1, old=op.old, new=""))
        elif op.kind == "replace_line":
            idx = op.line - 1 + delta
            out[idx] = op.new
            ap.edits.append(Edit("replace_line", idx + 1, old=op.old, new=op.new))
        elif op.kind == "replace_prefix":
            idx = op.line - 1 + delta
            out[idx] = op.new + out[idx][len(op.old) :]
            ap.edits.append(Edit("replace_prefix", idx + 1, old=op.old, new=op.new))
    return out, [by_decision[k] for k in order], rejected


# ---------------------------------------------------------------------------
# 撤销与内容不变校验
# ---------------------------------------------------------------------------


def revert_edits(out: List[str], applied: List[AppliedPatch]) -> Tuple[List[str], bool]:
    """逆序撤销全部编辑；任何不一致返回 (work, False)。"""
    work = list(out)
    for ap in reversed(applied):
        for ed in reversed(ap.edits):
            idx = ed.line - 1
            if ed.kind == "insert_line":
                if idx >= len(work) or work[idx] != ed.new:
                    return work, False
                del work[idx]
            elif ed.kind == "delete_line":
                work.insert(idx, ed.old)
            elif ed.kind == "replace_line":
                if idx >= len(work):
                    return work, False
                work[idx] = ed.old
            elif ed.kind == "replace_prefix":
                if idx >= len(work) or not work[idx].startswith(ed.new):
                    return work, False
                work[idx] = ed.old + work[idx][len(ed.new) :]
    return work, True


def content_invariant(original_lines: List[str], out: List[str], applied: List[AppliedPatch]) -> bool:
    reverted, ok = revert_edits(out, applied)
    return ok and reverted == original_lines

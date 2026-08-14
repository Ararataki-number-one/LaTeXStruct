# -*- coding: utf-8 -*-
"""规则扫描引擎：高召回候选识别 + 硬排除（M1 MVP，纯标准库）。

设计取向：**规则引擎宁可多报候选，由 AI 说"不是"，也不静默漏掉。**
规则引擎只回答"哪里可能是什么"；最终判定属于 AI 决策引擎（或快速模式下的高置信规则）。

性能说明：行号换算使用 Document 上缓存的行首偏移（O(log n) 二分），
盒子（tcolorbox 等）按起始行建索引一次复用，避免真实大书上的重复全表扫描。
"""

from __future__ import annotations

import re
from bisect import bisect_right
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .parser import PROTECTED_ENVS, Block, Document, Span

# ---------------------------------------------------------------------------
# 常量与模式
# ---------------------------------------------------------------------------

THEOREM_LIKE_ENVS = {
    "theorem", "lemma", "proposition", "corollary", "definition",
    "remark", "example", "conjecture", "problem", "claim",
    "exercise", "problemset", "note",
}
BOX_ENVS = {"tcolorbox", "mdframed", "framed", "quote", "quotation"}
ITEM_ENVS = {"enumerate", "itemize", "description", "problemset", "exercise", "problem"}
SKIP_ENVS = (
    THEOREM_LIKE_ENVS
    | ITEM_ENVS
    | {"proof", "solution", "thebibliography", "figure", "table",
       "algorithm", "algorithmic", "minipage"}
)

EN_MAP = {
    "Definition": "definition", "Theorem": "theorem", "Lemma": "lemma",
    "Proposition": "proposition", "Corollary": "corollary", "Remark": "remark",
    "Example": "example", "Conjecture": "conjecture", "Problem": "problem",
    "Claim": "claim",
    "定义": "definition", "定理": "theorem", "引理": "lemma",
    "命题": "proposition", "推论": "corollary", "注": "remark",
    "注记": "remark", "例": "example",
}

# 英文标题：关键词 + 可选编号 + 可选句点/冒号，后随空白/行尾/中文括号
EN_TITLE_RE = re.compile(
    r"^(Definition|Theorem|Lemma|Proposition|Corollary|Remark|Example|"
    r"Conjecture|Problem|Claim)\b"
    r"(?:\s+(\d+(?:\.\d+)*))?\s*[.:]?\s*(?=\s|$|（|\()"
)
# 中文长关键词：关键词后必须跟 编号/标点/空白+内容/括号（防"定义域"类误匹配）
CN_TITLE_RE = re.compile(
    r"^(定义|定理|引理|命题|推论|注记)"
    r"(?=\s*\d|\s*[:：.。]|\s+\S|（|\()"
)
# 中文长关键词 + 编号（用于编号提取与前缀剥离）
CN_NUM_PREFIX_RE = re.compile(
    r"^(定义|定理|引理|命题|推论|注记)\s*(\d+(?:\.\d+)*)\s*[:：.。]?\s*"
)
# 中文短关键词（注/例）：必须紧跟编号或标点（防"例如""注意"类误匹配）
CN_TITLE_SHORT_RE = re.compile(
    r"^(注|例)(?=\s*\d|\s*[:：.。])"
)
CN_SHORT_NUM_RE = re.compile(r"^(注|例)\s*(\d+(?:\.\d+)*)\s*[:：.。]?\s*")

PROOF_RE = re.compile(
    r"^(?:Proof\.?(?:\s|$)|Proof\s*\[[^\]]*\](?:\s*\.)?(?:\s|$)|Proof of\b|"
    r"Sketch of the proof\.?(?:\s|$)|"
    r"证明\s*[:：]\s*|证明\s*$|证明如下\s*[:：]?\s*)"
)
# 可安全剥离的证明起始前缀（剩余正文非空时才剥离）
PROOF_BRACKET_RE = re.compile(r"^Proof\s*\[([^\]]*)\](?:\s*\.)?\s*")
PROOF_SKETCH_RE = re.compile(r"^Sketch of the proof\.?\s*")
PROOF_SIMPLE_RE = re.compile(r"^(?:Proof\.\s+|Proof\s+|证明[。：]\s*|证明如下[：:]\s*)")

# 证明范围扩展（规则模式启发式）
SECTION_START_RE = re.compile(r"^\s*\\(chapter|section|subsection|subsubsection)\b")
# 续段连接词：证明的后续段落常以这些词开头；"There is" 等叙述性重启不在其中
PROOF_CONTINUE_RE = re.compile(
    r"^(?:now|then|hence|thus|therefore|consequently|it\s+follows|we|by|if|since|"
    r"suppose|assume|let|for|conversely|moreover|in\s+particular|indeed|first|second|third|"
    r"finally|also|this|from|because|note|observe|recall|clearly|obviously|as|so|but|"
    r"combining|substituting|using|taking|when|"
    r"to\s+(?:see|prove|show|complete|finish|obtain|establish|verify)|"
    r"consider|claim|next|on\s+the\s+other\s+hand|which|where|and|the|of|it)\b",
    re.I,
)
PROOF_END_MARKERS = ("□", "证毕")

EXERCISE_KEYWORDS = re.compile(r"exercises?|problems?|练习|习题|问题集", re.I)
BARE_NUM_RE = re.compile(r"^\s*\d+\.")
# 真实书稿常见 \begin{tcolorbox}\relax —— 允许盒内前导 \relax
BOX_INNER_SECTION_RE = re.compile(r"^\s*(?:\\relax\s*)?\\section\*\{([^{}]*)\}\s*$")


@dataclass
class Candidate:
    id: str
    kind: str  # theorem-like | proof | exercise-section | bilingual-title | scope-fix
    rule_id: str
    block_id: Optional[int]
    span: Span
    title_text: str = ""
    env_hint: str = ""  # 建议环境名 / 范围修正目标环境
    confidence: float = 0.5
    payload: Dict = field(default_factory=dict)


@dataclass
class ScanResult:
    candidates: List[Candidate]
    skipped: List[dict]
    stats: Dict[str, int]


# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------


def scan(doc: Document) -> ScanResult:
    candidates: List[Candidate] = []
    skipped: List[dict] = []
    cid = 1

    def add(**kw) -> Candidate:
        nonlocal cid
        c = Candidate(id=f"c-{cid:04d}", **kw)
        cid += 1
        candidates.append(c)
        return c

    # 盒子索引（一次构建，全程复用）
    box_ranges = [r for r in doc.env_ranges if r[0] in BOX_ENVS]
    boxes_by_start: Dict[int, List[tuple]] = {}
    for r in box_ranges:
        boxes_by_start.setdefault(offset_to_line(doc, r[1]), []).append(r)
    box_ivs = sorted((r[1], r[3]) for r in box_ranges)

    paras = doc.blocks_of_kind("para")
    for b in paras:
        first = _first_nonempty_line(b.text)
        if not first:
            continue
        envs = set(b.in_env)
        if envs & PROTECTED_ENVS or envs & SKIP_ENVS:
            continue
        if envs & BOX_ENVS:
            # 盒子内的标题行：多为英文条目的中文翻译辅助文本，按设计硬排除但记录跳过
            if _match_title(first):
                skipped.append(
                    {"line": b.span.start_line, "kind": "box-title",
                     "reason": "位于 tcolorbox/mdframed 内（疑似英文条目的中文翻译，保守不动）"}
                )
            continue
        m = _match_title(first)
        if m:
            kind_text, num, prefix = m
            add(
                kind="theorem-like",
                rule_id="bare-title",
                block_id=b.id,
                span=b.span,
                title_text=first,
                env_hint=EN_MAP[kind_text],
                confidence=0.85 if num else 0.7,
                payload={
                    "keyword": kind_text,
                    "number": num,
                    "title_prefix": prefix,
                    "in_env": tuple(envs),
                    "section_path": b.section_path,
                    "text": b.text,
                },
            )
            continue
        if PROOF_RE.match(first):
            strip, arg = _proof_strip(first)
            add(
                kind="proof",
                rule_id="proof-start",
                block_id=b.id,
                span=b.span,
                title_text=first,
                env_hint="proof",
                confidence=0.9,
                payload={
                    "in_env": tuple(envs),
                    "section_path": b.section_path,
                    "text": b.text,
                    "strip_prefix": strip,
                    "proof_arg": arg,
                },
            )
            continue

    # 习题节（内容范围 = 本节标题之后到下一个"非盒内"节标题之前）
    non_box_sections = [s for s in doc.sections if not _section_in_box(doc, s, box_ivs)]
    total_lines = doc.text.count("\n") + 1
    for i, s in enumerate(non_box_sections):
        if not EXERCISE_KEYWORDS.search(s.title):
            continue
        end_line = (
            non_box_sections[i + 1].span.start_line - 1
            if i + 1 < len(non_box_sections)
            else total_lines
        )
        items = []
        for b in paras:
            if b.span.start_line < s.span.end_line + 1 or b.span.start_line > end_line:
                continue
            if set(b.in_env) & (ITEM_ENVS | BOX_ENVS):
                # 已在列表环境内（不得重复包裹）；盒内中文翻译文本不得改写（R4 规则 6/9）
                continue
            if BARE_NUM_RE.match(_first_nonempty_line(b.text) or ""):
                items.append(b)
        if len(items) >= 2:
            add(
                kind="exercise-section",
                rule_id="exercise-section",
                block_id=None,
                span=s.span,
                title_text=s.title,
                env_hint="exercise",
                confidence=0.9,
                payload={
                    "section_cmd": s.cmd,
                    "starred": s.starred,
                    "item_block_ids": [b.id for b in items],
                    "item_lines": [b.span.start_line for b in items],
                },
            )

    # 双语标题（英文 \section* + 仅含中文翻译标题的 tcolorbox）
    for s in doc.sections:
        if not s.starred:
            continue
        box = _translation_box_after(doc, s, boxes_by_start)
        if box is None:
            continue
        rng, cn_title = box
        add(
            kind="bilingual-title",
            rule_id="bilingual-title",
            block_id=None,
            span=s.span,
            title_text=s.title,
            env_hint="",
            confidence=0.9,
            payload={
                "en_title": s.title,
                "cn_title": cn_title,
                "section_line": s.span.start_line,
                "section_cmd": s.cmd,
                "box_lines": (offset_to_line(doc, rng[1]), offset_to_line(doc, rng[3])),
            },
        )

    # 已有环境范围错误
    for b in doc.blocks:
        if b.kind != "env" or b.name not in THEOREM_LIKE_ENVS:
            continue
        nxt = _next_block_after(doc, b)
        if nxt is not None and nxt.span.start_line == b.span.end_line + 1:
            if nxt.kind == "para":
                add(
                    kind="scope-fix",
                    rule_id="env-body-outside",
                    block_id=b.id,
                    span=b.span,
                    title_text=f"{b.name} 环境",
                    env_hint=b.name,
                    confidence=0.75,
                    payload={"env_name": b.name, "next_kind": nxt.kind,
                             "next_line": nxt.span.start_line, "next_end_line": nxt.span.end_line},
                )
            elif nxt.kind == "displaymath":
                add(
                    kind="scope-fix",
                    rule_id="env-missing-display",
                    block_id=b.id,
                    span=b.span,
                    title_text=f"{b.name} 环境",
                    env_hint=b.name,
                    confidence=0.8,
                    payload={"env_name": b.name, "next_kind": nxt.kind,
                             "next_line": nxt.span.start_line, "next_end_line": nxt.span.end_line},
                )
        if _env_nonblank_lines(doc, b) <= 1:
            add(
                kind="scope-fix",
                rule_id="env-only-title",
                block_id=b.id,
                span=b.span,
                title_text=f"{b.name} 环境",
                env_hint=b.name,
                confidence=0.7,
                payload={"env_name": b.name},
            )

    stats: Dict[str, int] = {}
    for c in candidates:
        stats[c.kind] = stats.get(c.kind, 0) + 1
    return ScanResult(candidates=candidates, skipped=skipped, stats=stats)


# ---------------------------------------------------------------------------
# 辅助函数
# ---------------------------------------------------------------------------


def _first_nonempty_line(text: str) -> str:
    for line in text.split("\n"):
        if line.strip():
            return line
    return ""


def _match_title(first: str):
    """返回 (关键词, 编号, 可剥离前缀)；无匹配返回 None。"""
    m = EN_TITLE_RE.match(first)
    if m:
        return m.group(1), m.group(2), m.group(0)
    m = CN_NUM_PREFIX_RE.match(first)
    if m and m.group(2):
        return m.group(1), m.group(2), m.group(0)
    m = CN_TITLE_RE.match(first)
    if m:
        return m.group(1), None, m.group(0)
    m = CN_SHORT_NUM_RE.match(first)
    if m and m.group(2):
        return m.group(1), m.group(2), m.group(0)
    m = CN_TITLE_SHORT_RE.match(first)
    if m:
        return m.group(1), None, m.group(0)
    return None


def _proof_strip(first: str):
    """返回 (可剥离前缀, 可选参数)。Proof of ... 等含语义的形式不剥离。"""
    m = PROOF_BRACKET_RE.match(first)
    if m:
        return m.group(0), m.group(1)
    m = PROOF_SKETCH_RE.match(first)
    if m:
        return m.group(0), "Sketch"
    m = PROOF_SIMPLE_RE.match(first)
    if m:
        return m.group(0), ""
    return "", ""


def offset_to_line(doc: Document, off: int) -> int:
    starts = doc.line_starts
    if not starts:  # 防御：旧构造的 Document 无缓存
        starts = [0]
        for i, ch in enumerate(doc.text):
            if ch == "\n":
                starts.append(i + 1)
        doc.line_starts = starts
    return bisect_right(starts, off)


def _translation_box_after(doc: Document, s, boxes_by_start: Dict[int, List[tuple]]):
    r"""节标题后紧跟的、仅含中文 \section* 的 tcolorbox（允许中间夹 1–2 行）。"""
    for box_line in (s.span.end_line + 1, s.span.end_line + 2, s.span.end_line + 3):
        for rng in boxes_by_start.get(box_line, []):
            name, bs, be, es, ee = rng
            interior = doc.masked[be:es].strip()
            m = BOX_INNER_SECTION_RE.match(interior)
            if m:
                return rng, m.group(1)
    return None


def _section_in_box(doc: Document, s, box_ivs: List[Tuple[int, int]]) -> bool:
    off = s.span.start_off
    idx = bisect_right(box_ivs, (off, 1 << 62)) - 1
    if idx < 0:
        return False
    bs, es = box_ivs[idx]
    return bs <= off <= es


def _next_block_after(doc: Document, b: Block) -> Optional[Block]:
    nxt = None
    for other in doc.blocks:
        if other.id == b.id or other.kind == "env" and other.span.start_off == b.span.start_off:
            continue
        if other.span.start_line >= b.span.end_line and (nxt is None or other.span.start_line < nxt.span.start_line):
            nxt = other
    return nxt


def _env_nonblank_lines(doc: Document, b: Block) -> int:
    rng = next((r for r in doc.env_ranges if offset_to_line(doc, r[1]) == b.span.start_line), None)
    if rng is None:
        return 999
    _, _, be, es, _ = rng
    interior = doc.masked[be:es]
    return sum(1 for line in interior.split("\n") if line.strip())

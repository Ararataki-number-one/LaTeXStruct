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
from typing import Collection, Dict, List, Optional, Tuple

from .parser import PROTECTED_ENVS, Block, Document, Span
from .patch import NEW_THEOREM_RE
from .ruleset import SEMANTIC_SEPARATOR_PATTERN, TEX_HORIZONTAL_SPACE_PATTERN

# ---------------------------------------------------------------------------
# 常量与模式
# ---------------------------------------------------------------------------

THEOREM_LIKE_ENVS = {
    "theorem", "lemma", "proposition", "corollary", "definition",
    "remark", "example", "conjecture", "problem", "claim",
    "question", "fact", "observation", "exercise", "problemset", "note",
}
BOX_ENVS = {
    "tcolorbox", "mdframed", "framed", "quote", "quotation", "lsframedinset",
}
ITEM_ENVS = {"enumerate", "itemize", "description", "problemset", "exercise", "problem"}
MATH_ENVS = {
    "math", "displaymath", "equation", "equation*", "align", "align*", "alignat",
    "alignat*", "flalign", "flalign*", "gather", "gather*", "multline", "multline*",
    "eqnarray", "eqnarray*", "split", "aligned", "alignedat", "gathered", "cases",
    "array", "matrix", "pmatrix", "bmatrix", "Bmatrix", "vmatrix", "Vmatrix",
    "smallmatrix",
}
# TeX 在这些环境的单元格中处于受限水平模式，或由环境自己管理 ``&``/换行。
# 把 theorem/proof 环境插进单元格，可能直到编译器越过源文档的首个既有错误后
# 才暴露 ``Not allowed in LR mode``。扫描阶段必须硬排除，而不能把风险留给 AI。
ALIGNMENT_ENVS = {
    "tabular", "tabular*", "tabularx", "tabulary", "longtable", "longtabu",
    "supertabular", "xtabular", "mpxtabular", "tblr", "talltblr", "longtblr",
}
SKIP_ENVS = (
    THEOREM_LIKE_ENVS
    | ITEM_ENVS
    | MATH_ENVS
    | ALIGNMENT_ENVS
    | {"proof", "solution", "thebibliography", "figure", "table",
       "algorithm", "algorithmic", "minipage"}
)

EN_MAP = {
    "Definition": "definition", "Theorem": "theorem", "Lemma": "lemma",
    "Proposition": "proposition", "Corollary": "corollary", "Remark": "remark",
    "Example": "example", "Conjecture": "conjecture", "Problem": "problem",
    "Question": "question", "Claim": "claim", "Fact": "fact",
    "Observation": "observation", "Note": "note", "Exercise": "exercise",
    "定义": "definition", "定理": "theorem", "引理": "lemma",
    "命题": "proposition", "推论": "corollary", "注": "remark",
    "注记": "remark", "例": "example",
}

# 英文标题：关键词 + 可选编号 + 可选句点/冒号，后随空白/行尾/中文括号
EN_TITLE_RE = re.compile(
    r"^(Definition|Theorem|Lemma|Proposition|Corollary|Remark|Example|"
    r"Conjecture|Problem|Question|Claim|Fact|Observation|Note|Exercise)\b"
    r"(?:"
    r"\s+(\d+(?:\.\d+)*)(?:\s*[.:](?!\d)\s*|"
    rf"\s*{TEX_HORIZONTAL_SPACE_PATTERN}\s*|"
    r"\s+(?=[A-Z\\$(（(])|\s*$)"
    r"|\s+(?:\((?:[^()\n]|\([^()\n]{1,80}\)){1,1024}\)|\[[^\[\]\n]{1,1024}\])"
    r"(?:\s*[.:]\s*|\s*$)"
    rf"|\s*{TEX_HORIZONTAL_SPACE_PATTERN}\s*"
    r"|\s*[.:]\s*"
    r"|\s*$"
    r")(?=\S|$|（|\()"
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

_MULTILINE_NAMED_TITLE_HEAD_RE = re.compile(
    r"^\s*(?:Definition|Theorem|Lemma|Proposition|Corollary|Remark|Example|"
    r"Conjecture|Problem|Question|Claim|Fact|Observation|Note|Exercise)\b"
    r"[ \t]*(?P<open>[\[(])"
)
_TITLE_TRAILING_PUNCTUATION = frozenset({"", ".", ":", "：", "。"})
_MAX_MULTILINE_TITLE_CHARS = 4096
_MAX_MULTILINE_TITLE_LINES = 24

_PROOF_OF_TITLE_END_PATTERN = r"(?=\s*(?:[.:：。]|$))"
_PROOF_OF_REF_TOKEN_PATTERN = (
    # ``\\href``/``\\hyperref`` (and aliases ending in those names) create
    # links; they are not semantic result references.  The scoped case-folded
    # negative lookahead remains effective in both the hard-coded scanner and
    # the case-insensitive RulePack compiler.
    r"\\(?![A-Za-z@]*(?i:h(?:yper)?ref)\b)[A-Za-z@]*ref\*?"
    r"\s*\{[^{}\n]{1,160}\}"
)
_PROOF_OF_TYPED_QUALIFIER_PATTERN = (
    r"(?:\s+(?:up\s+to|for|on|in|under|with|of)\s+"
    r"[^.\n:：。]{1,160})?"
)
PROOF_OF_TARGET_PATTERN = (
    # A typed target must finish as a title.  Previously the bare ``Theorem``
    # alternative accepted prose such as ``Proof of Theorem 1 appears ...``.
    r"(?:Theorem|Lemma|Proposition|Corollary|Conjecture|Claim|Fact|Observation|"
    r"Definition|Result|Question|Problem|Exercise)\b"
    rf"(?:\s*~?\s*(?:\d+(?:\.\d+)*|{_PROOF_OF_REF_TOKEN_PATTERN}))?"
    rf"{_PROOF_OF_TYPED_QUALIFIER_PATTERN}{_PROOF_OF_TITLE_END_PATTERN}"
    r"|\d+(?:\.\d+)*"
    rf"{_PROOF_OF_TITLE_END_PATTERN}"
    # Real books commonly define semantic aliases such as ``\\thmref`` and
    # ``\\propref``.  Require one non-nested label argument and a terminal
    # title boundary, while explicitly excluding hyperlink commands.
    rf"|{_PROOF_OF_REF_TOKEN_PATTERN}{_PROOF_OF_TITLE_END_PATTERN}"
)
PROOF_OF_NAMED_TARGET_PATTERN = (
    r"the\s+(?:"
    r"(?:upper|lower)\s+bound(?:\s+(?:in|of|for)\s+"
    r"(?:Theorem|Lemma|Proposition|Corollary|Claim|Result)\s+\d+(?:\.\d+)*)?"
    r"|(?:main\s+)?(?:theorem|lemma|proposition|corollary|claim|result|assertion)\b"
    rf"){_PROOF_OF_TITLE_END_PATTERN}"
)
PROOF_OF_NATURAL_TARGET_PATTERN = (
    # Named results such as ``Green's theorem`` or ``the spectral theorem``.
    # A proper-name head (case-sensitive even inside an ``re.I`` pack), or a
    # definite descriptive name, is mandatory.  This rejects generic prose
    # such as ``Proof of a theorem.`` and ``Proof of this theorem.``.
    r"(?:"
    r"(?-i:[A-Z][A-Za-z0-9'’.-]*)"
    r"(?:\s+[A-Za-z][A-Za-z0-9'’.-]*){0,4}"
    r"|the\s+[A-Za-z][A-Za-z0-9'’.-]*"
    r"(?:\s+[A-Za-z][A-Za-z0-9'’.-]*){0,4}"
    r")\s+"
    r"(?:theorem|lemma|proposition|corollary|claim|result|assertion)\b"
    r"(?:\s+(?:for|on|in|under|with|of)\s+[^.\n:：。]{1,160})?"
    rf"{_PROOF_OF_TITLE_END_PATTERN}"
)
PROOF_RE = re.compile(
    rf"^(?:Proof(?!\s+of\b)\s*[:.]?(?:{SEMANTIC_SEPARATOR_PATTERN}|$)|"
    rf"Proof\s*\[[^\]]*\](?:\s*\.)?(?:{SEMANTIC_SEPARATOR_PATTERN}|$)|"
    rf"Proof of\s+(?:{PROOF_OF_TARGET_PATTERN}|{PROOF_OF_NAMED_TARGET_PATTERN}|"
    rf"{PROOF_OF_NATURAL_TARGET_PATTERN})|"
    rf"Sketch of the proof\.?(?:{SEMANTIC_SEPARATOR_PATTERN}|$)|"
    r"证明\s*[:：]\s*|证明\s*$|证明如下\s*[:：]?\s*)"
)
# 可安全剥离的证明起始前缀（剩余正文非空时才剥离）
PROOF_BRACKET_RE = re.compile(r"^Proof\s*\[([^\]]*)\](?:\s*\.)?\s*")
PROOF_SKETCH_RE = re.compile(r"^Sketch of the proof\.?\s*")
PROOF_SIMPLE_RE = re.compile(
    rf"^(?:Proof(?!\s+of\b)\s*[:.]?(?:{SEMANTIC_SEPARATOR_PATTERN}|$)|"
    r"证明[。：]\s*|证明如下[：:]\s*)"
)
PROOF_OF_RE = re.compile(
    rf"^(Proof of\s+(?:{PROOF_OF_TARGET_PATTERN}|{PROOF_OF_NAMED_TARGET_PATTERN}|"
    rf"{PROOF_OF_NATURAL_TARGET_PATTERN}).*?)"
    r"(?:[。:：.]|$)\s*",
    re.I,
)
STYLED_SEMANTIC_RE = re.compile(
    r"^(?P<leading>\s*(?:\\noindent\s*)?)"
    r"\\(?P<style>textbf|textit|emph|textsc)\s*\{"
)

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

# amsthm 之外的三种常见定理声明。这里只提取环境名，用于把已经结构化的
# 内容加入硬排除集合；声明的样式、编号和标题均不在扫描器职责范围内。
# 可选参数中允许普通的 ``{...}``（如 ``name={Main theorem}``），但不尝试
# 解析任意嵌套 TeX：匹配失败时宁可少识别声明，也不能误取正文命令。
_DECL_OPTIONS = r"(?:\[(?:[^\[\]{}]|\{[^{}]*\})*\]\s*)*"
NEW_TCB_THEOREM_RE = re.compile(
    rf"\\newtcbtheorem\s*\*?\s*{_DECL_OPTIONS}\{{([^{{}}]+)\}}",
    re.S,
)
DECLARE_THEOREM_RE = re.compile(
    rf"\\declaretheorem\s*\*?\s*{_DECL_OPTIONS}\{{([^{{}}]+)\}}",
    re.S,
)
NEW_MD_THEOREM_RE = re.compile(
    rf"\\newmdtheoremenv\s*\*?\s*{_DECL_OPTIONS}\{{([^{{}}]+)\}}",
    re.S,
)

# ``env-body-outside`` 会被规则模式直接执行 move-boundary，因此普通相邻段落
# 绝不能成为该候选。只保留源文本明确说明“正文漏在环境外”的迁移/测试标记；
# 其他不确定情形由 ``env-only-title`` 作为只读歧义提示，保持 fail closed。
EXPLICIT_OUTSIDE_BODY_RE = re.compile(
    r"(?:\b(?:left|placed|kept|fell)\s+outside\b.{0,80}\b(?:the\s+)?environment\b|"
    r"(?:正文|内容).{0,40}(?:漏在|遗漏在|位于|留在).{0,20}环境(?:之)?外)",
    re.I | re.S,
)


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


def scan(
    doc: Document,
    pack=None,
    structured_envs: Optional[Collection[str]] = None,
) -> ScanResult:
    from .ruleset import load_pack

    rp = load_pack(pack)
    title_res = rp.title_res
    proof_re = rp.proof_re or PROOF_RE
    exercise_re = rp.exercise_re or EXERCISE_KEYWORDS

    candidates: List[Candidate] = []
    skipped: List[dict] = []
    cid = 1

    # 用户定义的环境与内置 theorem 一样属于已结构化区域，里面即使出现
    # ``Theorem ...`` 字样也绝不能再次包裹。带星号的内置环境并不是新的
    # 语义类型（只是无编号版本），必须同步硬排除。
    supplied_structured_envs = {
        str(name).strip() for name in (structured_envs or ()) if name
    }
    custom_theorem_envs = (
        _declared_theorem_envs(doc.masked) | supplied_structured_envs
    )
    starred_theorem_envs = {
        f"{name}*" for name in THEOREM_LIKE_ENVS | {"proof", "solution"}
    }
    custom_starred_envs = {
        f"{name}*" for name in custom_theorem_envs if not name.endswith("*")
    }
    skip_envs = (
        SKIP_ENVS
        | starred_theorem_envs
        | custom_theorem_envs
        | custom_starred_envs
    )
    structured_theorem_envs = (
        THEOREM_LIKE_ENVS
        | {f"{name}*" for name in THEOREM_LIKE_ENVS}
        | custom_theorem_envs
        | custom_starred_envs
    )

    def add(**kw) -> Candidate:
        nonlocal cid
        c = Candidate(id=f"c-{cid:04d}", **kw)
        cid += 1
        candidates.append(c)
        return c

    def match_title(source):
        first, multiline = _title_probe(source)
        semantic, wrapper = _semantic_view(first)
        for env, pat in title_res:
            m = pat.match(semantic)
            if m:
                num = m.group(1) if m.groups() else None
                # A line-based patch cannot move an arbitrary multi-line title
                # into an optional environment argument.  It can, however,
                # safely remove the literal keyword on the first line and leave
                # every parenthesis/macro/comment byte in place.  This avoids a
                # duplicate ``Theorem`` label without risking a lossy rewrite.
                if multiline:
                    raw_prefix = ""
                    title_line_old, replacement = _multiline_title_line_rewrite(source)
                else:
                    raw_prefix = _raw_semantic_prefix(
                        first, semantic, m.end(), wrapper
                    )
                    replacement = _styled_semantic_replacement(
                        first, m.end(), wrapper
                    )
                    title_line_old = first if replacement else ""
                return (
                    env,
                    num,
                    raw_prefix,
                    semantic[m.end():].strip(),
                    title_line_old,
                    replacement,
                )
        return None

    def match_proof(first):
        semantic, _wrapper = _semantic_view(first)
        return proof_re.match(semantic)

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
        if envs & PROTECTED_ENVS or envs & skip_envs:
            continue
        if envs & BOX_ENVS:
            # 盒子内的标题行：多为英文条目的中文翻译辅助文本，按设计硬排除但记录跳过
            if match_title(b.text):
                skipped.append(
                    {"line": b.span.start_line, "kind": "box-title",
                     "reason": "位于 tcolorbox/mdframed 内（疑似英文条目的中文翻译，保守不动）"}
                )
            continue
        m = match_title(b.text)
        if m:
            kind_env, num, prefix, remainder, title_line_old, title_line_new = m
            title_text, _multiline = _title_probe(b.text)
            add(
                kind="theorem-like",
                rule_id="bare-title",
                block_id=b.id,
                span=b.span,
                title_text=title_text,
                env_hint=kind_env,
                confidence=0.85 if num else 0.7,
                payload={
                    "keyword": kind_env,
                    "number": num,
                    "title_prefix": prefix,
                    "title_remainder": remainder,
                    "title_line_old": title_line_old,
                    "title_line_new": title_line_new,
                    "in_env": tuple(envs),
                    "section_path": b.section_path,
                    "text": b.text,
                },
            )
            continue
        if match_proof(first):
            strip, arg, remainder, title_line_old, title_line_new = _proof_metadata(first)
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
                    "title_remainder": remainder,
                    "title_line_old": title_line_old,
                    "title_line_new": title_line_new,
                },
            )
            continue

    # 习题节（内容范围 = 本节标题之后到下一个"非盒内"节标题之前）
    non_box_sections = [s for s in doc.sections if not _section_in_box(doc, s, box_ivs)]
    total_lines = doc.text.count("\n") + 1
    for i, s in enumerate(non_box_sections):
        if not exercise_re.search(s.title):
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

    # 双语标题（英文 \section* + 仅含中文翻译标题的 tcolorbox；学术论文包可关闭）
    for s in doc.sections:
        if not rp.bilingual_titles:
            break
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

    # 已有环境范围错误。范围移动是破坏性操作，候选一旦进入规则模式就会
    # 自动执行，因此必须使用比裸标题扫描更严格的证据门。
    for b in doc.blocks:
        if b.kind != "env" or b.name not in structured_theorem_envs:
            continue
        only_title = _env_is_only_title(doc, b, match_title)
        explicit_outside = False
        nxt = _next_block_after(doc, b)
        masked_lines = doc.masked.split("\n")
        separator_lines = (
            masked_lines[b.span.end_line:nxt.span.start_line - 1]
            if nxt is not None else []
        )
        if nxt is not None and all(not line.strip() for line in separator_lines):
            if nxt.kind == "para":
                first = _first_nonempty_line(nxt.text)
                # 章节、下一个定理标题或证明起始语是新的结构边界。把它们
                # 移进前一个环境会造成语义破坏，因此不生成自动修复。
                starts_new_structure = bool(
                    SECTION_START_RE.match(first)
                    or match_title(first)
                    or match_proof(first)
                )
                # “环境后有一个普通段落”是标准写法，不能据此推断它属于环境。
                # 只有原文带有明确的迁移标记时才生成可自动移动的候选。
                explicit_outside = bool(
                    not starts_new_structure
                    and EXPLICIT_OUTSIDE_BODY_RE.search(nxt.text)
                )
                if explicit_outside:
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
            elif nxt.kind == "displaymath" and only_title:
                # 只有空环境/纯标题环境后紧跟公式时，公式才构成足够强的
                # “正文遗漏”证据；完整单行定理后的公式可能只是后续讨论。
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
        # 同一环境已有更具体的 env-body-outside 候选时不要再生成第二个
        # env-only-title ID；重复候选会让模型/规则只能回答其中一个，并造成
        # 虚假的“漏答”或两次移动同一边界。
        if only_title and not explicit_outside:
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


def _declared_theorem_envs(text: str) -> set:
    """提取常见定理声明命令定义的环境名。"""
    names = {m.group(2).strip() for m in NEW_THEOREM_RE.finditer(text)}
    for pattern in (NEW_TCB_THEOREM_RE, DECLARE_THEOREM_RE, NEW_MD_THEOREM_RE):
        names.update(m.group(1).strip() for m in pattern.finditer(text))
    return {name for name in names if name and "\\" not in name}


def _env_interior(doc: Document, b: Block) -> Optional[str]:
    """返回与环境块对应的已屏蔽内部文本；无法唯一定位时取最外层匹配。"""
    matches = []
    for rng in doc.env_ranges:
        name, bs, be, es, ee = rng
        if name != b.name:
            continue
        if (
            offset_to_line(doc, bs) == b.span.start_line
            and offset_to_line(doc, es) == b.span.end_line
        ):
            matches.append(rng)
    if not matches:
        return None
    _name, _bs, begin_end, end_start, _ee = max(
        matches, key=lambda item: item[3] - item[1]
    )
    return doc.masked[begin_end:end_start]


_NONCONTENT_ENV_COMMAND_RE = re.compile(
    # ``\\hypertarget{name}{text}`` has visible content in its second argument;
    # only its genuinely empty form is non-content.  Likewise, never consume an
    # accidental second group following ``\\label`` or ``\\index``.
    r"(?:\\(?:label|index)\s*\{[^{}]*\}"
    r"|\\hypertarget\s*\{[^{}]*\}\s*\{\s*\})",
    re.S,
)


def _env_is_only_title(doc: Document, b: Block, match_title) -> bool:
    """判断环境是否确实为空或只含标题，而不是粗暴按“一行”判断。"""
    interior = _env_interior(doc, b)
    if interior is None:
        return False
    visible = _NONCONTENT_ENV_COMMAND_RE.sub("", interior).strip()
    if not visible:
        return True

    nonblank = [line for line in visible.split("\n") if line.strip()]
    first = nonblank[0]
    hit = match_title(first)
    if hit is None:
        # 一行完整陈述（无论是否以 “Theorem” 开头）是合法正文。
        return False
    # A title-looking word is evidence of an empty theorem entry only when its
    # semantic type agrees with the enclosing built-in environment.  For
    # example, ``Exercise.`` is complete content inside a ``proof`` environment,
    # not a missing proof body.  Unknown aliases remain fail-closed because the
    # scanner does not have a trustworthy alias-to-canonical mapping here.
    enclosing = str(b.name or "").removesuffix("*").casefold()
    matched_env = str(hit[0] or "").casefold()
    if enclosing not in THEOREM_LIKE_ENVS or matched_env != enclosing:
        return False
    remainder = str(hit[3] or "").strip()
    tail = "\n".join(nonblank[1:]).strip()
    return not remainder and not tail


def _first_nonempty_line(text: str) -> str:
    for line in text.split("\n"):
        if line.strip():
            return line
    return ""


def _unescaped_comment_start(line: str) -> int:
    """Return the first TeX-comment percent index, ignoring ``\\%``."""
    for index, char in enumerate(line):
        if char != "%":
            continue
        backslashes = 0
        cursor = index - 1
        while cursor >= 0 and line[cursor] == "\\":
            backslashes += 1
            cursor -= 1
        if backslashes % 2 == 0:
            return index
    return -1


def _normalize_multiline_title(source: str) -> str:
    visible = []
    for line in source.split("\n"):
        comment = _unescaped_comment_start(line)
        if comment >= 0:
            line = line[:comment]
        if line.strip():
            visible.append(line.strip())
    return re.sub(r"\s+", " ", " ".join(visible)).strip()


def _title_probe(source: str) -> tuple[str, bool]:
    """Return a matchable title prefix and whether it spans source lines.

    OCR-style headings reconstructed from optional theorem arguments can contain
    ``\\footnote``/``\\href`` markup and balanced parentheses across several
    lines.  This bounded scanner accepts only a balanced named title whose closer
    is followed solely by title punctuation on that source line.  It therefore
    cannot turn an ordinary sentence after ``Theorem (name)`` into a heading.
    """
    first = _first_nonempty_line(source)
    if not first or "\n" not in source:
        return first, False
    first_offset = source.find(first)
    head = _MULTILINE_NAMED_TITLE_HEAD_RE.match(source[first_offset:])
    if head is None:
        return first, False
    opening = first_offset + head.start("open")
    opener = source[opening]
    closer = "]" if opener == "[" else ")"
    depth = 0
    cursor = opening
    limit = min(len(source), opening + _MAX_MULTILINE_TITLE_CHARS)
    line_count = 1
    closing = -1
    while cursor < limit:
        char = source[cursor]
        if char == "\n":
            line_count += 1
            if line_count > _MAX_MULTILINE_TITLE_LINES:
                return first, False
            cursor += 1
            continue
        if char == "%":
            line_start = source.rfind("\n", 0, cursor) + 1
            if _unescaped_comment_start(source[line_start:cursor + 1]) == cursor - line_start:
                newline = source.find("\n", cursor + 1, limit)
                if newline < 0:
                    return first, False
                cursor = newline
                continue
        if char == opener:
            depth += 1
        elif char == closer:
            depth -= 1
            if depth == 0:
                closing = cursor
                break
        cursor += 1
    if closing < 0 or line_count <= 1:
        return first, False

    line_end = source.find("\n", closing + 1)
    if line_end < 0:
        line_end = len(source)
    trailing = source[closing + 1:line_end]
    comment = _unescaped_comment_start(trailing)
    if comment >= 0:
        trailing = trailing[:comment]
    if trailing.strip() not in _TITLE_TRAILING_PUNCTUATION:
        return first, False
    normalized = _normalize_multiline_title(source[first_offset:line_end])
    return (normalized, True) if normalized else (first, False)


def _multiline_title_keyword_prefix(source: str) -> str:
    """Return only the first-line keyword prefix of a proven multi-line title."""
    first = _first_nonempty_line(source)
    if not first:
        return ""
    first_offset = source.find(first)
    head = _MULTILINE_NAMED_TITLE_HEAD_RE.match(source[first_offset:])
    if head is None:
        return ""
    return source[first_offset:first_offset + head.start("open")]


def _multiline_title_line_rewrite(source: str) -> tuple[str, str]:
    """Remove only a multi-line title's keyword while preserving indentation."""
    first = _first_nonempty_line(source)
    if not first:
        return "", ""
    head = _MULTILINE_NAMED_TITLE_HEAD_RE.match(first)
    if head is None:
        return "", ""
    leading = first[:len(first) - len(first.lstrip())]
    rewritten = leading + first[head.start("open"):]
    return (first, rewritten) if rewritten != first else ("", "")


def _semantic_view(first: str) -> Tuple[str, Optional[dict]]:
    """返回可匹配的可见文本，并记录安全可剥离的行首样式包装。"""
    match = STYLED_SEMANTIC_RE.match(first)
    if not match:
        return first, None
    opening = first.find("{", match.start())
    depth = 0
    escaped = False
    closing = -1
    for index in range(opening, len(first)):
        char = first[index]
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
                closing = index
                break
    if closing < 0:
        return first, None
    inner = first[opening + 1 : closing]
    trailing = first[closing + 1 :]
    return inner + trailing, {
        "opening": opening,
        "inner": inner,
        "closing": closing,
        "trailing": trailing,
    }


def _raw_semantic_prefix(
    first: str,
    semantic: str,
    match_end: int,
    wrapper: Optional[dict],
) -> str:
    if wrapper is None:
        return semantic[:match_end]
    inner = wrapper["inner"]
    # 只在样式命令内部恰好只有标题词条时剥离整个包装；否则保留原行，
    # 避免删除半个 \textbf{...} 后留下不配平花括号。
    if inner[match_end:].strip():
        return ""
    # ``semantic`` is exactly ``inner + trailing``.  If the title/proof regex
    # consumed a bounded TeX separator from ``trailing``, include those exact
    # source bytes in the removable structural prefix.  Ignoring them leaves a
    # stray leading ``\quad`` inside the generated environment; consuming only
    # one character would corrupt the command.  The match length provides a
    # lossless source-coordinate mapping, so no generated text is trusted here.
    trailing_consumed = max(0, match_end - len(inner))
    end = min(
        len(first),
        int(wrapper["closing"]) + 1 + trailing_consumed,
    )
    while end < len(first) and first[end].isspace():
        end += 1
    return first[:end]


def _styled_semantic_replacement(
    first: str,
    match_end: int,
    wrapper: Optional[dict],
) -> str:
    """安全删除样式命令内部的标题前缀，同时保留样式和正文。"""
    if wrapper is None:
        return ""
    inner = str(wrapper["inner"])
    # 匹配若已经越过样式命令的右花括号，应走普通前缀删除；若样式命令
    # 内没有正文，则也没有必要重写整行。
    if match_end > len(inner) or not inner[match_end:].strip():
        return ""
    opening = int(wrapper["opening"])
    remainder = inner[match_end:].lstrip()
    return first[: opening + 1] + remainder + "}" + str(wrapper["trailing"])


def _match_title(first: str):
    """返回 (关键词, 编号, 可剥离前缀)；无匹配返回 None。"""
    source = first
    first, multiline = _title_probe(first)
    semantic, wrapper = _semantic_view(first)
    m = EN_TITLE_RE.match(semantic)
    if m:
        return (
            m.group(1),
            m.group(2),
            (
                _multiline_title_keyword_prefix(source)
                if multiline
                else _raw_semantic_prefix(first, semantic, m.end(), wrapper)
            ),
        )
    m = CN_NUM_PREFIX_RE.match(semantic)
    if m and m.group(2):
        return (
            m.group(1),
            m.group(2),
            _raw_semantic_prefix(first, semantic, m.end(), wrapper),
        )
    m = CN_TITLE_RE.match(semantic)
    if m:
        return (
            m.group(1),
            None,
            _raw_semantic_prefix(first, semantic, m.end(), wrapper),
        )
    m = CN_SHORT_NUM_RE.match(semantic)
    if m and m.group(2):
        return (
            m.group(1),
            m.group(2),
            _raw_semantic_prefix(first, semantic, m.end(), wrapper),
        )
    m = CN_TITLE_SHORT_RE.match(semantic)
    if m:
        return (
            m.group(1),
            None,
            _raw_semantic_prefix(first, semantic, m.end(), wrapper),
        )
    return None


def _proof_metadata(first: str):
    """返回证明标题的安全前缀、说明、正文及可选整行重写。"""
    semantic, wrapper = _semantic_view(first)
    m = PROOF_BRACKET_RE.match(semantic)
    if m:
        label = m.group(1)
    else:
        m = PROOF_SKETCH_RE.match(semantic)
        if m:
            label = "Sketch"
        else:
            m = PROOF_OF_RE.match(semantic)
            if m:
                label = m.group(1).rstrip(".。:：").strip()
            else:
                m = PROOF_SIMPLE_RE.match(semantic)
                label = ""
    if not m:
        return "", "", "", "", ""
    replacement = _styled_semantic_replacement(first, m.end(), wrapper)
    return (
        _raw_semantic_prefix(first, semantic, m.end(), wrapper),
        label,
        semantic[m.end():].strip(),
        first if replacement else "",
        replacement,
    )


def _proof_strip(first: str):
    """兼容旧调用：返回 (可剥离前缀, 可选参数)。"""
    prefix, label, _remainder, _old, _new = _proof_metadata(first)
    return prefix, label


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
    from .texparse import interior_section_command

    for box_line in (s.span.end_line + 1, s.span.end_line + 2, s.span.end_line + 3):
        for rng in boxes_by_start.get(box_line, []):
            name, bs, be, es, ee = rng
            interior = doc.masked[be:es].strip()
            hit = interior_section_command(interior)
            if hit:
                return rng, hit[0]
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

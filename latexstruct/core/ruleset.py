# -*- coding: utf-8 -*-
"""Rule Pack：可配置规则集（评审 P1）。

- 内置规则包（`latexstruct/rulesets/*.json`，纯标准库 JSON，语义等价于建议的 YAML）：
  default（中英双语，即原硬编码规则）、english、chinese、academic-paper（+Conjecture/
  Problem/Claim/Fact/Observation 等论文扩展）；
- 用户自定义：JSON 文件路径，字段与内置包相同，未提供字段回退默认；
- title_patterns 的关键词自动按语言加防误匹配护栏（ASCII → 词边界；纯中文长词 →
  编号/标点/空白/括号前瞻；单字"注/例" → 必须紧跟编号或标点）。

加载顺序：pack=None → default；内置名 → 内置包；其余 → 视为 JSON 路径。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

RULESETS_DIR = Path(__file__).resolve().parent.parent / "rulesets"

CJK_RE = re.compile(r"^[\u4e00-\u9fff]+$")

# OCR and publisher sources often use TeX spacing rather than a literal blank
# between a styled result label and its name/body, for example
# ``\textbf{Theorem 7.7}\quad \textsc{Main Theorem}`` and
# ``\textbf{Proof}\quad Let ...``.  These commands are separators, not part of
# the semantic keyword.  Keep the grammar deliberately bounded: arbitrary TeX
# commands must not turn prose such as ``Theorem\ref{...} shows`` into a title.
TEX_HORIZONTAL_SPACE_PATTERN = (
    r"(?:~|\\(?:quad|qquad|enspace|enskip|space)\b|"
    r"\\hspace\*?\s*\{[^{}\n]{1,80}\}|\\[,;:!>]|\\[ \t])"
)
SEMANTIC_SEPARATOR_PATTERN = rf"(?:\s+|{TEX_HORIZONTAL_SPACE_PATTERN}\s*)"

_PROOF_TITLE_END = r"(?=\s*(?:[.:：。]|$))"
_PROOF_REF_TOKEN = (
    r"\\(?![A-Za-z@]*(?i:h(?:yper)?ref)\b)[A-Za-z@]*ref\*?"
    r"\s*\{[^{}\n]{1,160}\}"
)
_PROOF_TYPED_QUALIFIER = (
    r"(?:\s+(?:up\s+to|for|on|in|under|with|of)\s+"
    r"[^.\n:：。]{1,160})?"
)
_PROOF_TYPED_CORE = (
    r"(?:Theorem|Lemma|Proposition|Corollary|Conjecture|Claim|Fact|Observation|"
    r"Definition|Result|Question|Problem|Exercise)\b"
    rf"(?:\s*~?\s*(?:\d+(?:\.\d+)*|{_PROOF_REF_TOKEN}))?"
)
_PROOF_PRESENTATION_TARGET = (
    rf"(?:{_PROOF_TYPED_CORE}"
    rf"|\\(?:textbf|textit|emph|textsc)\s*\{{{_PROOF_TYPED_CORE}\}}"
    rf"|\\textcolor\s*\{{[^{{}}\n]{{1,64}}\}}\s*\{{{_PROOF_TYPED_CORE}\}}"
    rf"|\\href\s*\{{[^{{}}\n]{{1,320}}\}}\s*\{{{_PROOF_TYPED_CORE}\}}"
    rf"|\\hyperref\s*\[[^\[\]\n]{{1,160}}\]\s*\{{{_PROOF_TYPED_CORE}\}})"
)
_PROOF_TYPED_TARGET = (
    rf"{_PROOF_PRESENTATION_TARGET}"
    rf"{_PROOF_TYPED_QUALIFIER}{_PROOF_TITLE_END}"
)
_PROOF_NAMED_TARGET = (
    r"the\s+(?:"
    r"(?:upper|lower)\s+bound(?:\s+(?:in|of|for)\s+"
    r"(?:Theorem|Lemma|Proposition|Corollary|Claim|Result)\s+\d+(?:\.\d+)*)?"
    r"|(?:main\s+)?(?:theorem|lemma|proposition|corollary|claim|result|assertion)\b"
    rf"){_PROOF_TITLE_END}"
)
_PROOF_NATURAL_TARGET = (
    r"(?:(?-i:[A-Z][A-Za-z0-9'’.-]*)"
    r"(?:\s+[A-Za-z][A-Za-z0-9'’.-]*){0,4}"
    r"|the\s+[A-Za-z][A-Za-z0-9'’.-]*"
    r"(?:\s+[A-Za-z][A-Za-z0-9'’.-]*){0,4})\s+"
    r"(?:theorem|lemma|proposition|corollary|claim|result|assertion)\b"
    r"(?:\s+(?:for|on|in|under|with|of)\s+[^.\n:：。]{1,160})?"
    rf"{_PROOF_TITLE_END}"
)
DEFAULT_PROOF_OF_START = (
    rf"Proof of\s+(?:{_PROOF_TYPED_TARGET}|\d+(?:\.\d+)*{_PROOF_TITLE_END}|"
    rf"{_PROOF_REF_TOKEN}{_PROOF_TITLE_END}|{_PROOF_NAMED_TARGET}|"
    rf"{_PROOF_NATURAL_TARGET})"
)

DEFAULT_PROOF_STARTS = [
    rf"Proof(?!\s+of\b)\s*[:.]?(?:{SEMANTIC_SEPARATOR_PATTERN}|$)",
    rf"Proof\s*\[[^\]]*\](?:\s*\.)?(?:{SEMANTIC_SEPARATOR_PATTERN}|$)",
    DEFAULT_PROOF_OF_START,
    rf"Sketch of the proof\.?(?:{SEMANTIC_SEPARATOR_PATTERN}|$)",
    r"证明\s*[:：]\s*",
    r"证明\s*$",
    r"证明如下\s*[:：]?\s*",
]
DEFAULT_CONTINUE_WORDS = [
    "now", "then", "hence", "thus", "therefore", "consequently", "it follows",
    "we", "by", "if", "since", "suppose", "assume", "let", "for", "conversely",
    "moreover", "in particular", "indeed", "first", "second", "third", "finally",
    "also", "this", "from", "because", "note", "observe", "recall", "clearly",
    "obviously", "as", "so", "but", "combining", "substituting", "using", "taking",
    "when", "to see", "to prove", "to show", "to complete", "to finish", "to obtain",
    "to establish", "to verify", "consider", "claim", "next", "on the other hand",
    "which", "where", "and", "the", "of", "it",
]
DEFAULT_EXERCISE_KEYWORDS = ["exercises?", "problems?", "练习", "习题", "问题集"]
DEFAULT_END_MARKERS = ["□", "证毕"]

DEFAULT_TITLE_PATTERNS = {
    "definition": ["Definition", "定义"],
    "theorem": ["Theorem", "定理"],
    "lemma": ["Lemma", "引理"],
    "proposition": ["Proposition", "命题"],
    "corollary": ["Corollary", "推论"],
    "remark": ["Remark", "注", "注记"],
    "example": ["Example", "例"],
    "conjecture": ["Conjecture", "猜想"],
    "problem": ["Problem", "问题"],
    "question": ["Question"],
    "claim": ["Claim"],
    "fact": ["Fact"],
    "observation": ["Observation"],
    "note": ["Note"],
    "exercise": ["Exercise"],
}

ACADEMIC_TITLE_PATTERNS = {
    **DEFAULT_TITLE_PATTERNS,
    "conjecture": ["Conjecture", "猜想"],
    "problem": ["Problem", "问题"],
    "claim": ["Claim"],
    "proposition": ["Proposition", "命题", "Fact"],
    "remark": ["Remark", "注", "注记", "Observation"],
}


@dataclass
class RulePack:
    name: str
    title_patterns: Dict[str, List[str]] = field(default_factory=lambda: dict(DEFAULT_TITLE_PATTERNS))
    proof_starts: List[str] = field(default_factory=lambda: list(DEFAULT_PROOF_STARTS))
    continue_words: List[str] = field(default_factory=lambda: list(DEFAULT_CONTINUE_WORDS))
    end_markers: List[str] = field(default_factory=lambda: list(DEFAULT_END_MARKERS))
    exercise_keywords: List[str] = field(default_factory=lambda: list(DEFAULT_EXERCISE_KEYWORDS))
    bilingual_titles: bool = True

    # ---- 编译产物（load_pack 后填充） ----
    title_res: List[Tuple[str, re.Pattern]] = field(default_factory=list, repr=False)
    proof_re: Optional[re.Pattern] = field(default=None, repr=False)
    continue_re: Optional[re.Pattern] = field(default=None, repr=False)
    exercise_re: Optional[re.Pattern] = field(default=None, repr=False)

    def compile(self) -> "RulePack":
        self.title_res = []
        for env, kws in self.title_patterns.items():
            for kw in kws:
                self.title_res.append((env, _title_regex(kw)))
        self.proof_re = re.compile(r"^(?:" + "|".join(self.proof_starts) + ")", re.I) if self.proof_starts else None
        self.continue_re = re.compile(
            r"^(?:" + "|".join(re.escape(w) for w in self.continue_words) + r")\b", re.I
        ) if self.continue_words else None
        self.exercise_re = re.compile("|".join(self.exercise_keywords), re.I) if self.exercise_keywords else None
        return self


def _title_regex(kw: str) -> re.Pattern:
    """关键词 → 标题匹配正则（含防误匹配护栏与编号捕获组 1）。"""
    if CJK_RE.match(kw):
        if len(kw) == 1:  # 单字（注/例）：必须紧跟编号或标点
            return re.compile(
                rf"^{re.escape(kw)}\s*(\d+(?:\.\d+)*)\s*[:：.。]?\s*(?=\S|$)"
                rf"|^{re.escape(kw)}\s*[:：.。]\s*"
            )
        # 长中文词：编号捕获优先；无编号时需编号/标点/空白+内容/括号
        return re.compile(
            rf"^{re.escape(kw)}\s*(\d+(?:\.\d+)*)\s*[:：.。]?\s*(?=\S|$)"
            rf"|^{re.escape(kw)}(?:\s*[:：.。]\s*|\s+(?=\S)|(?=（|\())"
        )
    # 英文裸标题必须有可见的“标题证据”：标点、编号后大写/公式/括号开头的
    # 陈述，或标题在行尾。仅凭 ``Theorem 2 shows ...`` 这类引用句不能生成候选。
    return re.compile(
        rf"^{re.escape(kw)}\b(?:"
        rf"\s+(\d+(?:\.\d+)*)(?:\s*[.:](?!\d)\s*|"
        rf"\s*{TEX_HORIZONTAL_SPACE_PATTERN}\s*|"
        rf"\s+(?=[A-Z\\$(（(])|\s*$)"
        rf"|\s+(?:\((?:[^()\n]|\([^()\n]{{1,80}}\)){{1,1024}}\)|"
        rf"\[[^\[\]\n]{{1,1024}}\])"
        rf"(?:\s*[.:]\s*|\s*$)"
        rf"|\s*{TEX_HORIZONTAL_SPACE_PATTERN}\s*"
        rf"|\s*[.:]\s*"
        rf"|\s*$"
        rf")(?=\S|$|（|\()"
    )


def _builtin(name: str) -> Optional[Dict]:
    p = RULESETS_DIR / f"{name}.json"
    if p.is_file():
        return json.loads(p.read_text(encoding="utf-8"))
    return None


def _default_data() -> Dict:
    return {
        "name": "default",
        "title_patterns": dict(DEFAULT_TITLE_PATTERNS),
        "proof_starts": list(DEFAULT_PROOF_STARTS),
        "continue_words": list(DEFAULT_CONTINUE_WORDS),
        "end_markers": list(DEFAULT_END_MARKERS),
        "exercise_keywords": list(DEFAULT_EXERCISE_KEYWORDS),
        "bilingual_titles": True,
    }


def load_pack(spec=None) -> RulePack:
    """spec：None/内置名/JSON 文件路径。返回编译好的 RulePack。"""
    if spec is None:
        data = _default_data()
    elif isinstance(spec, RulePack):
        return spec.compile()
    else:
        data = _builtin(str(spec))
        if data is None:
            p = Path(str(spec))
            if not p.is_file():
                raise ValueError(f"规则包不存在：{spec}（内置包位于 latexstruct/rulesets/）")
            data = json.loads(p.read_text(encoding="utf-8"))
        elif str(spec) == "english":
            # The English-only pack predates the canonical proof-of grammar and
            # carries a serialized copy of it.  Replace that one stale slot at
            # load time so additions such as bounded presentation wrappers can
            # never make ``english`` diverge from ``default`` again, while the
            # pack still excludes the Chinese proof starters.
            proof_starts = [
                pattern for pattern in data.get("proof_starts", [])
                if not str(pattern).startswith(r"Proof of\s+")
            ]
            proof_starts.insert(min(2, len(proof_starts)), DEFAULT_PROOF_OF_START)
            data = {**data, "proof_starts": proof_starts}
    base = _default_data()
    merged = {**base, **{k: v for k, v in data.items() if v is not None and v != []}}
    pack = RulePack(
        name=merged["name"],
        title_patterns=merged["title_patterns"],
        proof_starts=merged["proof_starts"],
        continue_words=merged["continue_words"],
        end_markers=merged["end_markers"],
        exercise_keywords=merged["exercise_keywords"],
        bilingual_titles=merged.get("bilingual_titles", True),
    )
    return pack.compile()


def list_builtin_packs() -> List[str]:
    return sorted(p.stem for p in RULESETS_DIR.glob("*.json"))

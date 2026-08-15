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

DEFAULT_PROOF_STARTS = [
    r"Proof\.?(?:\s|$)",
    r"Proof\s*\[[^\]]*\](?:\s*\.)?(?:\s|$)",
    r"Proof of\b",
    r"Sketch of the proof\.?(?:\s|$)",
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
    return re.compile(
        rf"^{re.escape(kw)}\b(?:\s+(\d+(?:\.\d+)*))?\s*[.:]?\s*(?=\s|$|（|\()"
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

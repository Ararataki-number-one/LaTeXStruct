# -*- coding: utf-8 -*-
"""规则模式决策生成器（fast mode / 无 Key 降级路径）。

确定性规则对扫描候选直接产出决策：

- 裸定理标题       → wrap 对应环境（正文 = 标题所在段落）
- proof 起始语     → wrap proof（可选参数从 Proof [X] / Sketch 提取）
- 习题节           → convert-to-exercise-env（环境名自动探测）
- 双语标题         → merge-bilingual-title
- 范围修正         → move-boundary（env-body-outside / env-missing-display；
                    仅发现"环境只包标题"且无后续正文线索 → 歧义保留）
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Tuple

from .parser import Document
from .patch import Decision
from .scanner import (
    BOX_ENVS,
    PROOF_CONTINUE_RE,
    PROOF_END_MARKERS,
    PROOF_RE,
    SECTION_START_RE,
    ScanResult,
    _first_nonempty_line,
    _match_title,
)


def _extend_proof_body(doc: Document, c, proof_re=None, continue_re=None) -> int:
    """规则模式启发式：证明环境覆盖整段证明（正则可由 Rule Pack 定制）。

    停点（此前停止）：下一个定理类标题 / 节标题 / 另一证明起始语 /
    叙述性重启段（如 "There is another interesting..."）。
    停点（含此段停止）：含 □ / 证毕 的段落。
    并入：显示公式、环境块（align 等）、盒子（中文译文）、
    以连接词 / 小写字母 / 公式开头的续段。
    """
    proof_re = proof_re or PROOF_RE
    continue_re = continue_re or PROOF_CONTINUE_RE
    end = c.span.end_line
    blocks = doc.blocks
    idx = next(
        (i for i, b in enumerate(blocks)
         if b.kind == "para" and b.span.start_line == c.span.start_line),
        None,
    )
    if idx is None:
        return end
    for b in blocks[idx + 1 :]:
        if b.span.start_line <= end:
            continue
        if b.span.start_line > end + 2:
            break  # 超过一个空行的间隔 → 结构断裂
        if b.kind == "displaymath":
            end = b.span.end_line
            continue
        if b.kind == "env":
            end = b.span.end_line  # 公式/盒子等环境整体并入
            continue
        if b.kind != "para":
            continue
        if set(b.in_env) & BOX_ENVS:
            end = b.span.end_line  # 盒内中文译文并入
            continue
        first = _first_nonempty_line(b.text)
        if not first:
            end = b.span.end_line
            continue
        if any(mk in b.text for mk in PROOF_END_MARKERS):
            end = b.span.end_line
            break
        if _match_title(first) or proof_re.match(first) or SECTION_START_RE.match(first):
            break
        stripped = first.lstrip()
        if (
            continue_re.match(stripped)
            or stripped[:1].islower()
            or stripped.startswith(("\\(", "$", "\\[", "\\begin"))
        ):
            end = b.span.end_line
            continue
        break
    return end


@dataclass
class RuleConfig:
    wrap_min_confidence: float = 0.0  # 规则模式阈值（候选已过硬排除）


def build_rule_decisions(
    doc: Document,
    scan_res: ScanResult,
    config: RuleConfig = None,
    kinds: set = None,
    pack=None,
) -> Tuple[List[Decision], List[dict]]:
    """kinds: 仅处理指定候选类型（None = 全部）。AI 模式下用于确定性部分。"""
    cfg = config or RuleConfig()
    proof_re, continue_re = PROOF_RE, PROOF_CONTINUE_RE
    if pack is not None:
        from .ruleset import load_pack

        rp = load_pack(pack)
        proof_re = rp.proof_re or proof_re
        continue_re = rp.continue_re or continue_re
    decisions: List[Decision] = []
    ambiguous: List[dict] = []
    kinds = kinds or {"theorem-like", "proof", "exercise-section", "bilingual-title", "scope-fix"}
    use_scope = "scope-fix" in kinds

    # 范围修正按环境合并：优先采纳 env-body-outside / env-missing-display
    sf = [c for c in scan_res.candidates if c.kind == "scope-fix" and use_scope]
    by_env: Dict[int, list] = {}
    for c in sf:
        # 按具体环境块合并，不能把整本书里所有同名 theorem 当成同一个实例。
        by_env.setdefault(c.block_id or -1, []).append(c)
    handled = set()
    for _, cs in by_env.items():
        env = cs[0].env_hint
        body = next((c for c in cs if c.rule_id == "env-body-outside"), None)
        disp = next((c for c in cs if c.rule_id == "env-missing-display"), None)
        pick = body or disp
        if pick is not None:
            for c in cs:
                handled.add(c.id)  # 同环境的所有范围候选合并为一次边界修正
            decisions.append(
                Decision(
                    candidate_id=pick.id,
                    action="move-boundary",
                    env=env,
                    source="rule",
                    reason="环境正文被留在环境外，扩展边界" if body else "显示公式应属于定理陈述",
                    confidence=pick.confidence,
                    payload={
                        "old_end_line": pick.span.end_line,
                        "new_end_line": pick.payload["next_end_line"],
                    },
                )
            )
        else:
            for c in cs:
                ambiguous.append(
                    {
                        "candidate_id": c.id,
                        "line": c.span.start_line,
                        "reason": f"{env} 环境只包住标题，无法可靠确定正文范围，保守保留",
                    }
                )

    for c in scan_res.candidates:
        if c.kind not in kinds:
            continue
        if c.kind == "theorem-like":
            if c.confidence < cfg.wrap_min_confidence:
                ambiguous.append({"candidate_id": c.id, "line": c.span.start_line,
                                  "reason": "置信度过低，保守保留"})
                continue
            # 编号提取：编号进可选参数，标题词条从前缀剥离（剩余正文非空时才剥离）
            num = c.payload.get("number")
            prefix = c.payload.get("title_prefix", "")
            remainder = c.title_text[len(prefix):].strip() if num and prefix else ""
            keep = not (num and prefix and remainder)
            decisions.append(
                Decision(
                    candidate_id=c.id,
                    action="wrap",
                    env=c.env_hint,
                    body_span=(c.span.start_line, c.span.end_line),
                    title_span=(c.span.start_line, c.span.start_line),
                    optional_arg=num or "",
                    keep_title_text=keep,
                    source="rule",
                    reason="裸写标题包裹为定理类环境（编号保留进可选参数）" if not keep else "裸写标题包裹为定理类环境",
                    confidence=c.confidence,
                    payload={"title_prefix": "" if keep else prefix},
                )
            )
        elif c.kind == "proof":
            strip = c.payload.get("strip_prefix", "")
            arg = c.payload.get("proof_arg", "")
            remainder = c.title_text[len(strip):].strip() if strip else ""
            keep = not strip or not remainder
            body_end = _extend_proof_body(doc, c, proof_re=proof_re, continue_re=continue_re)  # 整段证明
            decisions.append(
                Decision(
                    candidate_id=c.id,
                    action="wrap",
                    env="proof",
                    body_span=(c.span.start_line, body_end),
                    optional_arg=arg,
                    keep_title_text=keep,
                    source="rule",
                    reason="证明起始语包裹为 proof 环境（覆盖整段证明）",
                    confidence=c.confidence,
                    payload={"title_prefix": "" if keep else strip},
                )
            )
        elif c.kind == "exercise-section":
            decisions.append(
                Decision(
                    candidate_id=c.id,
                    action="convert-to-exercise-env",
                    env="",
                    source="rule",
                    reason="习题节转换为题目列表环境",
                    confidence=c.confidence,
                    payload={"item_lines": c.payload["item_lines"], "section_title": c.title_text},
                )
            )
        elif c.kind == "bilingual-title":
            decisions.append(
                Decision(
                    candidate_id=c.id,
                    action="merge-bilingual-title",
                    source="rule",
                    reason="合并中英双语节标题并加入目录",
                    confidence=c.confidence,
                    payload={
                        "section_line": c.payload["section_line"],
                        "section_cmd": c.payload["section_cmd"],
                        "en_title": c.payload["en_title"],
                        "cn_title": c.payload["cn_title"],
                        "box_lines": c.payload["box_lines"],
                    },
                )
            )
        elif c.kind == "scope-fix":
            if c.id not in handled:
                ambiguous.append({"candidate_id": c.id, "line": c.span.start_line,
                                  "reason": "范围修正未确定，保守保留"})

    return decisions, ambiguous

# -*- coding: utf-8 -*-
"""AI 提示词构建（母提示词 v3 + 决策/复查 Schema + 上下文组装）。

母提示词 = 设计文档附录 A（P1/P2 综合去重 + ElegantBook 适配）。
每次调用在母提示词之后追加：文档元信息、输出 Schema、few-shot 与"只输出 JSON"指令。
"""

from __future__ import annotations

import json
from typing import Dict, List

from .parser import Document
from .scanner import Candidate

# ---------------------------------------------------------------------------
# 母提示词（附录 A，v3）
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """你是「LaTeX 数学文档结构化整理引擎」。你的唯一任务：对给定的候选点做出纯结构决策。
你只输出决策 JSON，绝不生成、改写、翻译任何正文内容。

【根本原则】
1. 只改结构，不改内容：正文文字、数学公式、标点、段落顺序逐字不变。
2. 最小改动：能不动就不动；无法确定时选择不动。
3. 绝不重复包裹已正确的环境。

【候选点类型与决策】
A. 定理类裸标题（行/段首：Definition/Theorem/Lemma/Proposition/Corollary/Remark/Example/
   定义/定理/引理/命题/推论/注/注记/例；论文模式追加 Conjecture/Problem/Claim）：
   - 确为正式条目标题 → action=wrap，env 取对应环境；标题自带编号（如 Theorem 2.3.4）
     时编号保留进 optional_arg 或环境首行，不得丢失；
   - 无编号条目（Remark./Example.）→ 直接包裹，不伪造编号；
   - 正文可能跨多段：body_span 应覆盖该条目的全部正文段落与紧接的显示公式；
   - body_span 的起点必须是标题所在行，终点是该条目正文最后一个段落的末行，
     **不包含**其后的中文翻译框、图注、其他条目或后续叙述段。
B. 证明起始语（Proof./Proof/证明/证明：/Proof [Outline]/Proof [Theorem x.y.z]/
   Sketch of the proof.）：
   - 确为证明开始 → action=wrap, env=proof；附加说明（Outline 等）保留为 optional_arg；
   - proof 必须覆盖同一证明的全部段落与公式（含多段证明与收束文字）；
   - body_span 从证明起始语所在段开始，持续到下一个定理类标题/节标题/另一证明起始语之前；
     中间的中文翻译框、显示公式、align 等环境均属于证明，必须并入；
   - 若出现明确结束标记（□、证毕、"This completes the proof"），在标记所在段结束；
   - 证明结束后紧跟的叙述性段落（如 "There is another interesting..."）不得并入。
C. 已有环境范围错误（scope-fix 候选）：
   - 环境只包了标题、正文在外 → action=move-boundary，move_payload.new_end_line 扩到正文末尾；
   - 环境吞入后续无关说明/背景段落 → action=move-boundary，new_end_line 缩小；
   - theorem 后紧跟的显示公式属于定理陈述 → new_end_line 纳入公式；
   - 环境与正文均正确 → action=none。

【硬性排除：以下任何情况必须 action=none】
- 候选位于任何 theorem 类/proof 环境内部；
- 位于注释、verbatim、参考文献、索引、图/表/算法题注内；
- **tcolorbox/mdframed 内的中文标题行**（如盒内的"定理 1.7.2 ……"）是英文条目的中文翻译，
  绝不包裹盒子及其内容；
- **"(a) ..." "(b) ..." 等字母编号条目**是例题/证明内部的列表项，不是定理标题；
- 图注行（"Figure 1.9. A graph ..."、"图 1.9。……"）不是定理；
- 章节标题本身；目录/页眉页脚/版权页；附录索引项；
- 引用性文字（"by Lemma 3.1"、"Theorem 1.2 has an application..."）；
- 证明内部的 "Claim 1"/局部断言（除非上下文明确，否则不动）。

【决策冲突优先级】
保持原文内容不变 > 结构正确 > 不误判 > 最小改动 > 全书一致性 > 局部美观。

【输出】
只输出一个 JSON 对象，schema 如系统注入所示；所有行号必须在候选的上下文行号范围内；
无法判定的候选输出 action=none 且 reason 注明"歧义"。
"""

PROMPT_VERSION = "3.1"

DECIDE_SCHEMA = """输出格式（严格 JSON，不要输出任何其他内容）：
{
  "decisions": [
    {
      "candidate_id": "c-0004",
      "action": "wrap | move-boundary | none",
      "env": "theorem",
      "body_span": {"start_line": 20, "end_line": 21},
      "optional_arg": "",
      "keep_title_text": true,
      "reason": "简短理由（≤40字）",
      "confidence": 0.92,
      "move_payload": {"old_end_line": 39, "new_end_line": 40}
    }
  ]
}
说明：
- action=wrap 时 env 必填，可选值：theorem/lemma/proposition/corollary/definition/remark/
  example/conjecture/problem/claim/proof；
- body_span 必须落在该候选上下文行号范围内；
- action=move-boundary 时提供 move_payload.old_end_line（当前 \\end{env} 所在行）与
  new_end_line（修正后的边界行）；
- action=none 表示该候选无需处理（含"歧义"），reason 说明原因。"""

REVIEW_SYSTEM_PROMPT = """你是「LaTeX 结构化整理复查引擎」。已完成的整理（决策 + 补丁）如下所示。
你的唯一任务：检查这些修改是否误包、漏包或范围错误；只输出复查 JSON，绝不生成或改写正文内容。

判定标准：
- 误包：该处是引用性文字/普通说明/习题条目，不应包裹环境 → verdict=should-remove；
- 环境类型错误 → verdict=wrong-env，fix.env 给出正确环境；
- 范围错误（正文没收全/多吞了段落）→ verdict=wrong-range，fix.body_span 给出正确范围；
- 修改正确 → verdict=ok；
- 发现该处理但没处理的（参见"歧义/跳过清单"）→ verdict=missed-extra，fix 给出 wrap 决策。
所有 fix 中的行号必须引用给出的行号范围内；无法给出可靠修正时 verdict=ok 并 reason 说明。"""

REVIEW_SCHEMA = """输出格式（严格 JSON）：
{
  "findings": [
    {
      "candidate_id": "c-0004",
      "verdict": "ok | wrong-env | wrong-range | should-remove | missed-extra",
      "fix": {"action": "wrap", "env": "lemma", "body_span": {"start_line": 20, "end_line": 22},
              "optional_arg": "", "move_payload": {"old_end_line": 0, "new_end_line": 0}},
      "reason": "简短理由（≤40字）"
    }
  ]
}"""


def build_decide_system(meta: Dict) -> str:
    return "\n\n".join(
        [
            SYSTEM_PROMPT,
            "【当前文档元信息】\n" + json.dumps(meta, ensure_ascii=False, indent=1),
            DECIDE_SCHEMA,
        ]
    )


def build_review_system(meta: Dict) -> str:
    return "\n\n".join(
        [
            REVIEW_SYSTEM_PROMPT,
            "【当前文档元信息】\n" + json.dumps(meta, ensure_ascii=False, indent=1),
            REVIEW_SCHEMA,
        ]
    )


def build_meta(doc: Document, ctx, mode: str) -> Dict:
    from .pipeline import DOC_CLASS_RE  # 延迟导入避免环

    m = DOC_CLASS_RE.search(doc.text)
    return {
        "document_class": m.group(1) if m else "",
        "is_elegantbook": ctx.is_elegantbook,
        "existing_env_definitions": sorted(ctx.existing_envs),
        "exercise_env": ctx.exercise_env,
        "mode": mode,
        "total_lines": doc.text.count("\n") + 1,
    }


# ---------------------------------------------------------------------------
# 决策请求消息组装
# ---------------------------------------------------------------------------


def _numbered(lines: List[str], start: int, end: int, mark: tuple = ()) -> List[str]:
    out = []
    for L in range(max(1, start), min(len(lines), end) + 1):
        tag = ">>>" if L in mark else "   "
        out.append(f"{tag}[{L:4d}] {lines[L - 1]}")
    return out


def build_decide_user(
    doc: Document, candidates: List[Candidate], context_lines: int = 6
) -> str:
    lines = doc.text.split("\n")
    total = len(lines)
    parts: List[str] = [f"待决策候选共 {len(candidates)} 个。每个候选附上下文（行号范围即判定合法范围）。"]
    for c in candidates:
        s = c.span.start_line
        e = c.span.end_line
        lo = max(1, s - context_lines)
        hi = min(total, e + context_lines)
        parts.append(f"\n### 候选 {c.id}")
        parts.append(f"kind: {c.kind} | 规则提示: {c.rule_id} | 建议环境: {c.env_hint or '-'} | 置信度: {c.confidence:.2f}")
        parts.append(f"首行: {c.title_text[:80]!r}")
        if c.kind == "scope-fix":
            parts.append(
                f"范围信息: 当前环境结束于第 {c.span.end_line} 行；后续块 "
                f"{c.payload.get('next_kind', '-')} 起于第 {c.payload.get('next_line', '-')} 行"
            )
        parts.append(f"合法行号范围: {lo}..{hi}")
        parts.append("上下文:")
        parts.extend(_numbered(lines, lo, hi, mark=tuple(range(s, e + 1))))
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# 复查请求消息组装
# ---------------------------------------------------------------------------


def build_review_user(
    result_lines: List[str],
    applied_summaries: List[Dict],
    ambiguous: List[dict],
    context_lines: int = 6,
) -> str:
    parts: List[str] = [f"已应用的修改共 {len(applied_summaries)} 项。"]
    for i, s in enumerate(applied_summaries, 1):
        bs, be = s.get("body_span", (1, 1))
        lo = max(1, bs - context_lines)
        hi = min(len(result_lines), be + context_lines)
        parts.append(f"\n### 修改 {i}（candidate {s.get('candidate_id')}）")
        parts.append(
            f"action={s.get('action')} env={s.get('env')} reason={s.get('reason')!r} "
            f"body_span={bs}..{be}（原文行号）"
        )
        parts.append("结果片段（结果文本行号；fix 中的行号请参照上文给出的原文行号）:")
        parts.extend(_numbered(result_lines, lo, hi, mark=tuple(range(bs, be + 1))))
    if ambiguous:
        parts.append("\n### 歧义/跳过清单（供 missed-extra 判断）")
        for a in ambiguous[:50]:
            parts.append(f"- 第 {a.get('line')} 行: {a.get('reason')}")
        if len(ambiguous) > 50:
            parts.append(f"- ……共 {len(ambiguous)} 项（其余省略，仅需复核此清单中的条目）")
    return "\n".join(parts)

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
4. 所有 body_span 都是“原始源文件行号”，不是修改后预览的行号。
5. 环境边界必须服从 LaTeX 嵌套：绝不能把 \\end{theorem}/\\end{proof} 放在
   尚未闭合的 \\[...\\]、equation、align、gather、multline 等数学环境内部。
6. 每个 candidate 是独立任务。只能依据该 candidate 的 ``>>>`` 标题行及其上下文判断；
   其他 candidate 的标题、环境或理由绝不能复制到当前 candidate。reason 必须指出当前
   candidate 的标题证据与结束证据；若两者任一不存在，action=none。

【候选点类型与决策】
A. 定理类裸标题（行/段首：Definition/Theorem/Lemma/Proposition/Corollary/Remark/Example/
   Conjecture/Problem/Question/Claim/Fact/Observation/Note/Exercise，或
   定义/定理/引理/命题/推论/注/注记/例）：
   - 确为正式条目标题 → action=wrap，env 取对应环境；标题自带编号（如 Theorem 2.3.4）
     时编号保留进 optional_arg 或环境首行，不得丢失；
   - 无编号条目（Remark./Example.）→ 直接包裹，不伪造编号；
    - 正文可能跨多段：body_span 应覆盖该条目的全部正文段落与紧接的显示公式；
   - body_span 的起点必须是标题所在行，终点是该条目正文最后一个段落的末行，
     **不包含**其后的中文翻译框、图注、其他条目或后续叙述段。
    - 定理陈述紧接的展示公式、公式后的限定语（如 “for all ...”）仍属于定理；
      body_span 必须覆盖完整数学环境及限定语，不能在 \\begin{equation} 与
      \\end{equation} 之间结束。
    - 请求会列出候选原子块之后、可靠结构停点之前的每个非空原子块。输出前必须
      逐块判断 inside/outside；句子语法完整、空行或换话题语气本身都不是 outside 证据。
      只要这些块仍属于当前条目，就必须选到列出的停点前最后原子块；若无法给出某块
      属于条目外的明确源文本证据，宁可 action=none，也不得输出漏掉该块的短范围。
B. 证明起始语（Proof./Proof/证明/证明：/Proof [Outline]/Proof [Theorem x.y.z]/
   Sketch of the proof.）：
   - 确为证明开始 → action=wrap, env=proof；附加说明（Outline 等）保留为 optional_arg；
   - proof 必须覆盖同一证明的全部段落与公式（含多段证明与收束文字）；
   - body_span 从证明起始语所在段开始，持续到下一个定理类标题/节标题/另一证明起始语之前；
     中间的中文翻译框、显示公式、align 等环境均属于证明，必须并入；
   - ``\\hfill $\\square$``、独立成行的 ``□/∎``、``\\qed``、``\\qedhere``、
     ``证毕`` 是可机器验证的硬结束标记，应在标记所在完整原子块结束；
   - 独立终句/分句 "This completes the proof"、"the/our proof is complete/done"
     可作为终点；嵌在条件句、"proof of Claim" 或普通叙述中的相似文字不是硬停点；
   - 证明结束后紧跟的叙述性段落（如 "There is another interesting..."）不得并入。
    - 没有明确结束标记、且下一个可靠结构停点前同时存在“证明收束”和后续叙述时，
      边界不可唯一恢复，必须 action=none 交人工确认，不能凭语感猜测结束位置。
    - 解析器给出的“可靠结构停点”优先于“多段可能歧义”：若停点是下一节、裸标题或
      已有 \\begin{theorem/lemma/proof/...}，并且停点前所有原子块都属于当前条目，应完整
      选到停点前最后一块；不能仅因正文多段就 action=none，也不能漏掉其中最后一段。
    - 若解析器明确写“没有可靠结构停点”：proof 无硬结束必须 action=none；独立成段的
      theorem 标题后若还要跨段，也必须 action=none。普通叙述、空行、"In particular"、
      "Now we..." 等语义转折不是可机器验证的停点，禁止在 reason 中虚构为 successor。
C. 已有环境范围错误（scope-fix 候选）：
   - 环境只包了标题、正文在外 → action=move-boundary，move_payload.new_end_line 扩到正文末尾；
   - 环境吞入后续无关说明/背景段落 → action=move-boundary，new_end_line 缩小；
   - theorem 后紧跟的显示公式属于定理陈述 → new_end_line 纳入公式；
   - 环境与正文均正确 → action=none。
   - move_payload 行号仅作说明；程序只会采用源文件扫描器确认的原子块边界，
     不会采用模型自行生成的边界坐标。

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
无法判定的候选输出 action=none 且 reason 注明"歧义"。必须对输入中的每个
candidate_id 恰好输出一个决策；不得漏答、重复回答或发明 candidate_id。
"""

PROMPT_VERSION = "3.6"

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
  example/conjecture/problem/question/claim/fact/observation/note/exercise/proof；
- body_span 必须落在该候选上下文行号范围内；
- action=move-boundary 时提供 move_payload.old_end_line（当前 \\end{env} 所在行）与
  new_end_line（修正后的边界行）；
- action=none 表示该候选无需处理（含"歧义"），reason 说明原因。"""

REVIEW_SYSTEM_PROMPT = """你是「LaTeX 结构化整理复查引擎」。已完成的整理（决策 + 补丁）如下所示。
你的唯一任务：检查这些修改是否误包、漏包或范围错误；只输出复查 JSON，绝不生成或改写正文内容。

请求中会同时给出修改前源片段、修改后结果片段和扫描候选元数据。必须比较 before/after，
不能只凭规则提示或环境名作结论。对请求中每个“待复查 candidate”必须恰好返回一个 finding；
不得用空 findings 表示全通过。对于待复核但尚未应用的候选，确认无需处理时也返回 verdict=ok。

判定标准：
- 误包：该处是引用性文字/普通说明/习题条目，不应包裹环境 → verdict=should-remove；
- 环境类型错误 → verdict=wrong-env，fix.env 给出正确环境，并提供 fix.confidence（0..1）
  和 fix.evidence（指出源片段中的具体语义证据）；没有明确证据时必须 verdict=ok 或
  should-remove，不得猜测环境类型；
- 范围错误（正文没收全/多吞了段落，尤其环境 closer 落进公式内部）→
  verdict=wrong-range；只报告原因，不提供/猜测修复行号，程序会撤销该初次补丁，
  保留原始正文交人工确认；
- 修改正确 → verdict=ok；
- 发现该处理但没处理的候选 → verdict=missed-extra；fix 必须给出 action/env/body_span/
  confidence/evidence，且 body_span 使用请求所示的“源文件行号”。程序仍会重新执行与初次
  决策相同的白名单、置信门、长候选窗口和补丁安全校验；不能通过结果预览坐标直接写回。
复查看到的是“结果文本行号”，初次 Decision 保存的是“源文本行号”，两者不可互换。
复查可自动执行的修正仅限有证据的 wrong-env、经源锚点重新验证的 missed-extra，
或撤销 should-remove/wrong-range。

边界复查必须重新执行以下硬规则，不能照抄初次 reason：
- 多段正文后存在解析器标出的可靠结构停点时，已应用范围必须覆盖停点前最后一个
  非空原子块；少一段就是 wrong-range，多跨停点也是 wrong-range；
- 请求列出的“当前选择后、可靠停点前遗漏原子块”必须逐块审计。句子已结束、空行、
  “It is worth mentioning” 或 “The collection ...” 等承接措辞都不能单独证明块在条目外；
  尚未应用候选若只是初次范围过短、且逐块确认都属于当前条目，应 verdict=missed-extra，
  fix.body_span 明确覆盖到停点前最后原子块。仍然漏块的修复会被安全门拒绝；
- 没有可靠结构停点时，无 QED/明确完成语的 proof 必须 wrong-range；独立标题后跨段的
  theorem-like 也不得仅凭语义猜终点；
- 普通叙述段不是结构停点。初次理由若声称普通叙述是 successor，必须判错。"""

REVIEW_SCHEMA = """输出格式（严格 JSON）：
{
  "findings": [
    {
      "candidate_id": "c-0004",
      "verdict": "ok | wrong-env | wrong-range | should-remove | missed-extra",
      "fix": {
        "action": "wrap",
        "env": "lemma",
        "body_span": {"start_line": 20, "end_line": 21},
        "confidence": 0.95,
        "evidence": "标题明确写作 Lemma"
      },
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


def _boundary_facts(
    doc: Document,
    start_line: int,
    upper_line: int,
    kind: str,
    structured_envs=None,
    candidate_end_line=None,
    selected_end_line=None,
) -> List[str]:
    """Render parser-derived boundary facts; the model may not invent replacements."""
    from .legalize import (
        _atomic_end,
        _next_stop_line,
        _pre_stop_atomic_end,
        _proof_end_line,
    )

    lines = doc.text.split("\n")
    masked_lines = doc.masked.split("\n")
    facts: List[str] = []
    candidate_end_line = candidate_end_line or start_line
    candidate_atomic_end = _atomic_end(
        doc, candidate_end_line, wrap_start=start_line
    )
    facts.append(f"候选原子块末行: 第 {candidate_atomic_end} 行")
    stop = _next_stop_line(doc, start_line, structured_envs)
    if stop is None:
        facts.append("解析器可靠结构停点: 无（普通叙述和空行不算停点）")
        facts.append("可靠停点前最后非空原子块末行: 无法机器确定")
    else:
        token = lines[stop - 1].strip()[:120] if stop <= len(lines) else ""
        facts.append(f"解析器可靠结构停点: 第 {stop} 行 {token!r}")
        complete_end = _pre_stop_atomic_end(doc, start_line, stop)
        if complete_end is None:
            facts.append("可靠停点前最后非空原子块末行: 无法机器确定")
        else:
            facts.append(f"可靠停点前最后非空原子块末行: 第 {complete_end} 行")

            def atomic_ranges_after(after_line):
                ranges = []
                cursor = after_line + 1
                while cursor <= complete_end:
                    while (
                        cursor <= complete_end
                        and not masked_lines[cursor - 1].strip()
                    ):
                        cursor += 1
                    if cursor > complete_end:
                        break
                    atom_start = cursor
                    atom_end = _atomic_end(doc, cursor, wrap_start=start_line)
                    if atom_end > complete_end:
                        break
                    ranges.append((atom_start, atom_end))
                    cursor = atom_end + 1
                return ranges

            all_post_candidate = atomic_ranges_after(candidate_atomic_end)
            if all_post_candidate:
                facts.append("候选原子块后、可靠停点前待逐块归属审计:")
                for index, (atom_start, atom_end) in enumerate(
                    all_post_candidate, 1
                ):
                    snippet = next(
                        (
                            lines[line_no - 1].strip()[:120]
                            for line_no in range(atom_start, atom_end + 1)
                            if lines[line_no - 1].strip()
                        ),
                        "",
                    )
                    facts.append(
                        f"  - 原子块 {index}: 第 {atom_start}..{atom_end} 行 {snippet!r}"
                    )
                facts.append(
                    "逐块审计要求: 每块都要判断 inside/outside；若不纳入 body_span，"
                    "reason 必须给出该块属于条目外的明确源文本证据。"
                )
            else:
                facts.append("候选原子块后、可靠停点前待逐块归属审计: 无")

            if selected_end_line is not None:
                bounded_end = max(start_line, min(int(selected_end_line), len(lines)))
                selected_atomic_end = _atomic_end(
                    doc, bounded_end, wrap_start=start_line
                )
                facts.append(
                    f"当前选择吸附后的原子块末行: 第 {selected_atomic_end} 行"
                )
                if selected_atomic_end >= stop:
                    facts.append("当前选择边界状态: 已跨越可靠结构停点，必须判为范围错误")
                omitted = atomic_ranges_after(selected_atomic_end)
                if omitted:
                    facts.append("当前选择后、可靠停点前遗漏的非空原子块:")
                    for index, (atom_start, atom_end) in enumerate(omitted, 1):
                        facts.append(
                            f"  - 遗漏原子块 {index}: 第 {atom_start}..{atom_end} 行"
                        )
                else:
                    facts.append("当前选择后、可靠停点前遗漏的非空原子块: 无")
    if kind == "proof":
        hard_end = _proof_end_line(doc, start_line, upper_line)
        if hard_end is None:
            facts.append("解析器明确证明结束标记: 无")
        else:
            facts.append(f"解析器明确证明结束标记所在原子块末行: 第 {hard_end} 行")
    return facts


def build_decide_user(
    doc: Document,
    candidates: List[Candidate],
    context_lines: int = 6,
    windows: Dict[str, tuple] = None,
    incomplete_windows: set = None,
    structured_envs=None,
) -> str:
    lines = doc.text.split("\n")
    total = len(lines)
    windows = windows or {}
    incomplete_windows = incomplete_windows or set()
    parts: List[str] = [f"待决策候选共 {len(candidates)} 个。每个候选附上下文（行号范围即判定合法范围）。"]
    parts.append(
        "逐个独立判断：只能把 >>> 标出的行当作当前候选锚点；上下文中的其他标题、"
        "引用或叙述不得替代当前锚点。"
    )
    for c in candidates:
        s = c.span.start_line
        e = c.span.end_line
        lo, hi = windows.get(
            c.id,
            (max(1, s - context_lines), min(total, e + context_lines)),
        )
        parts.append(f"\n### 候选 {c.id}")
        parts.append(f"kind: {c.kind} | 规则提示: {c.rule_id} | 建议环境: {c.env_hint or '-'} | 置信度: {c.confidence:.2f}")
        parts.append(f"首行: {c.title_text[:80]!r}")
        if c.kind == "scope-fix":
            parts.append(
                f"范围信息: 当前环境结束于第 {c.span.end_line} 行；后续块 "
                f"{c.payload.get('next_kind', '-')} 起于第 {c.payload.get('next_line', '-')} 行"
            )
        parts.append(f"合法行号范围: {lo}..{hi}")
        if c.id in incomplete_windows:
            parts.append(
                "安全提示: 下一个可靠结构停点超出本窗口；"
                "必须 action=none，不得生成截断环境。"
            )
        if c.kind in {"theorem-like", "proof"}:
            parts.extend(
                _boundary_facts(
                    doc,
                    s,
                    hi,
                    c.kind,
                    structured_envs,
                    candidate_end_line=c.span.end_line,
                )
            )
            if c.kind == "theorem-like":
                from .legalize import _candidate_atom_has_body

                same_atom_body = _candidate_atom_has_body(doc, c)
                parts.append(
                    "标题所在原子块含正文: " + ("是" if same_atom_body else "否")
                )
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
    source_lines: List[str] = None,
    pending_summaries: List[Dict] = None,
    structured_envs=None,
) -> str:
    source_lines = source_lines or result_lines
    from .parser import parse_latex

    source_doc = parse_latex("\n".join(source_lines))
    pending_summaries = pending_summaries or []
    review_ids = [s.get("candidate_id") for s in applied_summaries + pending_summaries]
    parts: List[str] = [
        f"本请求待复查 candidate 共 {len(review_ids)} 个："
        + ", ".join(str(cid) for cid in review_ids)
        + "。必须逐项且恰好返回一个 finding；空 findings 不是通过。",
        f"已应用修改 {len(applied_summaries)} 项，尚未应用候选 {len(pending_summaries)} 项。",
    ]
    for i, s in enumerate(applied_summaries, 1):
        source_bs, source_be = s.get("body_span", (1, 1))
        result_bs, result_be = s.get("result_span", (source_bs, source_be))
        source_lo = max(1, source_bs - context_lines)
        source_hi = min(len(source_lines), source_be + context_lines)
        lo = max(1, result_bs - context_lines)
        hi = min(len(result_lines), result_be + context_lines)
        parts.append(f"\n### 修改 {i}（candidate {s.get('candidate_id')}）")
        parts.append(
            f"action={s.get('action')} env={s.get('env')} reason={s.get('reason')!r} "
            f"source_body_span={source_bs}..{source_be}（只读源锚点，不得改写） | "
            f"result_span={result_bs}..{result_be}（下方预览行号）"
        )
        if s.get("candidate"):
            parts.append(
                "candidate 元数据: "
                + json.dumps(s["candidate"], ensure_ascii=False, sort_keys=True)
            )
            candidate_kind = str(s["candidate"].get("kind", ""))
            if candidate_kind in {"theorem-like", "proof"}:
                candidate_span = s["candidate"].get("candidate_span") or {}
                parts.extend(
                    _boundary_facts(
                        source_doc,
                        source_bs,
                        source_hi,
                        candidate_kind,
                        structured_envs,
                        candidate_end_line=candidate_span.get("end_line", source_bs),
                        selected_end_line=source_be,
                    )
                )
                if candidate_kind == "theorem-like":
                    parts.append(
                        "标题所在原子块含正文: "
                        + (
                            "是"
                            if s["candidate"].get("candidate_atom_has_body")
                            else "否"
                        )
                    )
        parts.append("修改前源片段（源文件行号，可用于 missed-extra 的 body_span）:")
        parts.extend(_numbered(
            source_lines,
            source_lo,
            source_hi,
            mark=tuple(range(source_bs, source_be + 1)),
        ))
        parts.append("结果片段（结果文本行号；只用于判断，不得写回 source_body_span）:")
        parts.extend(_numbered(
            result_lines,
            lo,
            hi,
            mark=tuple(range(result_bs, result_be + 1)),
        ))

    for i, s in enumerate(pending_summaries, 1):
        source_bs, source_be = s.get("body_span", (1, 1))
        lo, hi = s.get(
            "source_window",
            (
                max(1, source_bs - context_lines),
                min(len(source_lines), source_be + context_lines),
            ),
        )
        parts.append(
            f"\n### 尚未应用候选 {i}（candidate {s.get('candidate_id')}）"
        )
        parts.append(
            "candidate 元数据: "
            + json.dumps(s.get("candidate", {}), ensure_ascii=False, sort_keys=True)
        )
        candidate_kind = str(s.get("candidate", {}).get("kind", ""))
        if candidate_kind in {"theorem-like", "proof"}:
            candidate_span = s.get("candidate", {}).get("candidate_span") or {}
            parts.extend(
                _boundary_facts(
                    source_doc,
                    source_bs,
                    hi,
                    candidate_kind,
                    structured_envs,
                    candidate_end_line=candidate_span.get("end_line", source_bs),
                    selected_end_line=source_be,
                )
            )
            if candidate_kind == "theorem-like":
                parts.append(
                    "标题所在原子块含正文: "
                    + (
                        "是"
                        if s.get("candidate", {}).get("candidate_atom_has_body")
                        else "否"
                    )
                )
        parts.append(f"当前保守原因: {s.get('reason', '')}")
        parts.append(
            f"允许的源坐标窗口: {lo}..{hi}；若 verdict=missed-extra，"
            "fix.body_span 必须在此范围内。"
        )
        parts.append("真实源片段（源文件行号）:")
        parts.extend(_numbered(
            source_lines,
            lo,
            hi,
            mark=tuple(range(source_bs, source_be + 1)),
        ))
    if ambiguous:
        parts.append("\n### 其他人工清单（没有 candidate 元数据，不得自动生成补丁）")
        for a in ambiguous[:50]:
            parts.append(
                f"- candidate={a.get('candidate_id') or '-'}，"
                f"第 {a.get('line')} 行: {a.get('reason')}"
            )
        if len(ambiguous) > 50:
            parts.append(f"- ……共 {len(ambiguous)} 项（其余省略，仅需复核此清单中的条目）")
    return "\n".join(parts)

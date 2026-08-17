# -*- coding: utf-8 -*-
"""AI 复查引擎（M1 MVP）。

复查输入 = 全部变更点的结构化 diff（结果片段 + 决策理由）+ 歧义/跳过清单；
复查输出 = findings JSON（ok / wrong-env / wrong-range / should-remove / missed-extra）；
可自动修正的项回到决策列表重新打补丁（上限 review_max_rounds 轮），
无法修正的项升级到人工歧义清单。
"""

from __future__ import annotations

from typing import Dict, List, Tuple

from .ai import ALLOWED_WRAP_ENVS, AIConfig
from .patch import Decision
from .prompts import build_review_system, build_review_user, build_meta

REVIEW_VERDICTS = {"ok", "wrong-env", "wrong-range", "should-remove", "missed-extra"}


def parse_findings(obj: dict, applied_ids: set, total_lines: int) -> Tuple[List[dict], List[dict]]:
    """返回 (findings, invalid)。"""
    findings: List[dict] = []
    invalid: List[dict] = []
    raw = obj.get("findings")
    if not isinstance(raw, list):
        return [], [{"candidate_id": "-", "reason": "复查响应缺少 findings 数组"}]
    for item in raw:
        if not isinstance(item, dict):
            continue
        cid = item.get("candidate_id", "")
        verdict = item.get("verdict")
        if verdict not in REVIEW_VERDICTS:
            invalid.append({"candidate_id": cid, "reason": f"非法 verdict {verdict!r}"})
            continue
        if verdict != "missed-extra" and cid not in applied_ids:
            invalid.append({"candidate_id": cid, "reason": "引用了未知修改项"})
            continue
        finding = {
            "candidate_id": cid,
            "verdict": verdict,
            "fix": item.get("fix") if isinstance(item.get("fix"), dict) else {},
            "reason": str(item.get("reason", ""))[:120],
        }
        # fix 合法性预检
        if verdict in ("wrong-env", "wrong-range", "missed-extra"):
            fix = finding["fix"]
            ok = False
            if verdict == "wrong-env":
                ok = fix.get("env") in ALLOWED_WRAP_ENVS
            elif verdict == "wrong-range":
                # 复查看到的是结果文本。即使模型给了合法数字，也绝不能把
                # result 行号直接赋给源 Decision；范围结论只作报告/人工确认。
                ok = True
            elif verdict == "missed-extra":
                # 同理，漏项不能从结果坐标凭空创建源补丁。
                ok = True
            if not ok:
                invalid.append({"candidate_id": cid, "reason": f"{verdict} 的 fix 非法，升级人工"})
                continue
        findings.append(finding)
    return findings, invalid


def _valid_span(bs: dict, total_lines: int) -> bool:
    s = bs.get("start_line")
    e = bs.get("end_line")
    return (
        isinstance(s, int)
        and isinstance(e, int)
        and 1 <= s <= e <= total_lines
    )


def build_summaries(applied) -> List[Dict]:
    summaries = []
    for ap in applied:
        edit_lines = [edit.line for edit in ap.edits if edit.line > 0]
        source_span = ap.decision.body_span or (1, 1)
        result_span = (
            (min(edit_lines), max(edit_lines))
            if edit_lines else source_span
        )
        summaries.append({
            "candidate_id": ap.decision.candidate_id,
            "action": ap.decision.action,
            "env": ap.decision.env,
            "reason": ap.decision.reason,
            "body_span": source_span,
            "result_span": result_span,
        })
    return summaries


def run_review(
    client,
    doc,
    ctx,
    decisions: List[Decision],
    apply_fn,
    ambiguous: List[dict],
    ai_config: AIConfig,
    mode: str,
    progress_callback=None,
    control_callback=None,
):
    """复查主循环：复查 → 修正决策 → 重新打补丁（上限 review_max_rounds 轮）。

    apply_fn(decisions) -> (out_lines, applied, rejected, dropped)
    """
    usage_total: Dict = {}
    all_findings: List[dict] = []
    invalid_all: List[dict] = []
    escalations: List[dict] = []
    out, applied, rejected, dropped = apply_fn(decisions)
    for d, reason in dropped:
        ambiguous.append({"candidate_id": d.candidate_id, "line": 1, "reason": reason})

    system = build_review_system(build_meta(doc, ctx, mode))
    max_rounds = max(1, ai_config.review_max_rounds)
    completed_batches = 0
    for round_index in range(max_rounds):
        if control_callback:
            control_callback()
        # 成本优化：规则模式决策（双语合并/习题转换/导言区等）是确定性编辑，不送复查；
        # 但存在歧义/漏报清单时仍需复核（missed-extra 反悔）
        to_review = [ap for ap in applied if ap.decision.source != "rule"]
        if not to_review and not ambiguous:
            break
        result_lines = out
        round_findings: List[dict] = []
        batch_size = max(1, ai_config.review_batch)
        batches = [to_review[i : i + batch_size] for i in range(0, len(to_review), batch_size)]
        if not batches and ambiguous:
            batches = [[]]  # 无 AI 补丁但有漏报清单时，仍发一次复核
        for batch in batches:
            if control_callback:
                control_callback()
            user = build_review_user(result_lines, build_summaries(batch), ambiguous,
                                     ai_config.context_lines)
            obj, usage = client.chat_json(system, user)
            model = getattr(client, "cfg", None) and client.cfg.model or ""
            from ..pricing import add_usage

            add_usage(usage_total, usage, model)
            total = len(result_lines)
            # 每个请求只暴露当前 batch 的修改摘要。模型即使猜中另一个 batch 的
            # 合法 candidate_id，也不能借此撤销或改写未在本次请求中的补丁。
            batch_ids = {ap.decision.candidate_id for ap in batch}
            findings, invalid = parse_findings(obj, batch_ids, total)
            round_findings.extend(findings)
            invalid_all.extend(invalid)
            completed_batches += 1
            if progress_callback:
                progress_callback({
                    "round": round_index + 1,
                    "rounds": max_rounds,
                    "batch": completed_batches,
                    "usage": dict(usage_total),
                    "findings": len(all_findings) + len(round_findings),
                })
        all_findings.extend(round_findings)
        unsafe_coordinate_findings = [
            f for f in round_findings
            if f["verdict"] in {"wrong-range", "missed-extra"}
        ]
        for finding in unsafe_coordinate_findings:
            label = "范围问题" if finding["verdict"] == "wrong-range" else "疑似漏项"
            safe_action = (
                "已撤销对应的初次补丁，保留原始正文等待人工确认："
                if finding["verdict"] == "wrong-range"
                else "未自动新增无源坐标补丁，等待人工确认："
            )
            item = {
                "candidate_id": finding["candidate_id"],
                "line": 1,
                "reason": (
                    f"AI 复查报告{label}，但复查预览行号不能写回源文件；"
                    + safe_action
                    + finding.get("reason", "")
                )[:300],
            }
            if not any(
                old.get("candidate_id") == item["candidate_id"]
                and old.get("reason") == item["reason"]
                for old in escalations
            ):
                escalations.append(item)
            invalid_all.append({
                "candidate_id": finding["candidate_id"],
                "reason": "复查坐标与源坐标不同，已禁止自动改写范围",
            })
        actionable = [
            f for f in round_findings
            if f["verdict"] in {"wrong-env", "should-remove", "wrong-range"}
        ]
        if not actionable:
            break
        decisions = apply_findings(decisions, actionable, total)
        out, applied, rejected, dropped = apply_fn(decisions)
        for d, reason in dropped:
            ambiguous.append({"candidate_id": d.candidate_id, "line": 1, "reason": reason})
    return {
        "findings": all_findings,
        "invalid": invalid_all,
        "decisions": decisions,
        "out": out,
        "applied": applied,
        "rejected": rejected,
        "usage": usage_total,
        "escalations": escalations,
    }


def apply_findings(decisions: List[Decision], findings: List[dict], total_lines: int) -> List[Decision]:
    """只应用不涉及坐标变换的复查结论。

    ``wrong-env`` 复用原 Decision 的源锚点；``should-remove`` 与
    ``wrong-range`` 都撤销整个初次 Decision，以保留裸正文；
    ``missed-extra`` 只报告，不自动写回。
    """
    by_verdict: Dict[str, dict] = {}
    for f in findings:
        by_verdict[f["candidate_id"]] = f
    new_decisions: List[Decision] = []
    for d in decisions:
        f = by_verdict.get(d.candidate_id)
        if f is None or f["verdict"] == "ok":
            new_decisions.append(d)
            continue
        if f["verdict"] in {"should-remove", "wrong-range"}:
            continue
        fix = f["fix"]
        if f["verdict"] == "wrong-env" and d.action == "wrap":
            d.env = fix["env"]
            d.source = "review"
            new_decisions.append(d)
        else:
            new_decisions.append(d)
    return new_decisions

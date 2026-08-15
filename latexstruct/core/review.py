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
                bs = fix.get("body_span") or {}
                ok = _valid_span(bs, total_lines)
            elif verdict == "missed-extra":
                bs = fix.get("body_span") or {}
                ok = _valid_span(bs, total_lines) and fix.get("env") in ALLOWED_WRAP_ENVS
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
    return [
        {
            "candidate_id": ap.decision.candidate_id,
            "action": ap.decision.action,
            "env": ap.decision.env,
            "reason": ap.decision.reason,
            "body_span": ap.decision.body_span or (1, 1),
        }
        for ap in applied
    ]


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
            findings, invalid = parse_findings(obj, {d.candidate_id for d in decisions}, total)
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
        actionable = [f for f in round_findings if f["verdict"] != "ok"]
        if not actionable:
            break
        decisions = apply_findings(decisions, round_findings, total)
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
    }


def apply_findings(decisions: List[Decision], findings: List[dict], total_lines: int) -> List[Decision]:
    """按复查结论修正决策列表；missed-extra 追加新决策。"""
    by_verdict: Dict[str, dict] = {}
    for f in findings:
        by_verdict[f["candidate_id"]] = f
    new_decisions: List[Decision] = []
    for d in decisions:
        f = by_verdict.get(d.candidate_id)
        if f is None or f["verdict"] == "ok":
            new_decisions.append(d)
            continue
        if f["verdict"] == "should-remove":
            continue
        fix = f["fix"]
        if f["verdict"] == "wrong-env" and d.action == "wrap":
            d.env = fix["env"]
            d.source = "review"
            new_decisions.append(d)
        elif f["verdict"] == "wrong-range" and d.action == "wrap":
            bs = fix["body_span"]
            d.body_span = (bs["start_line"], bs["end_line"])
            d.source = "review"
            new_decisions.append(d)
        else:
            new_decisions.append(d)
    for f in findings:
        if f["verdict"] == "missed-extra":
            fix = f["fix"]
            bs = fix["body_span"]
            nid = f"review-missed-{f['candidate_id']}"
            if any(d.candidate_id == nid for d in new_decisions):
                continue  # 幂等：多轮复查不重复追加
            if _valid_span(bs, total_lines) and fix.get("env") in ALLOWED_WRAP_ENVS:
                new_decisions.append(
                    Decision(
                        candidate_id=nid,
                        action="wrap",
                        env=fix["env"],
                        body_span=(bs["start_line"], bs["end_line"]),
                        source="review",
                        reason=f.get("reason", "")[:120],
                        confidence=0.8,
                    )
                )
    return new_decisions

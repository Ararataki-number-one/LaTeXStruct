# -*- coding: utf-8 -*-
"""AI 复查引擎。

复查严格区分源坐标和结果坐标，并要求请求中每个候选恰好一个 finding。
任何漏答、重复答或无源锚点的修复都不会被静默当作通过。
"""

from __future__ import annotations

from math import isfinite
from typing import Dict, List, Optional, Tuple

from .ai import (
    ALLOWED_ACTIONS,
    ALLOWED_WRAP_ENVS,
    AIConfig,
    candidate_windows,
    parse_decisions,
)
from .legalize import theorem_requires_boundary_singleton
from .patch import Decision
from .prompts import build_meta, build_review_system, build_review_user

REVIEW_VERDICTS = {"ok", "wrong-env", "wrong-range", "should-remove", "missed-extra"}
REVIEW_ENV_CONFIDENCE = 0.90


def _as_confidence(value, default: float = 0.0) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    if not isfinite(parsed):
        return default
    return max(0.0, min(1.0, parsed))


def _target_decision(target) -> Optional[Decision]:
    if isinstance(target, Decision):
        return target
    if isinstance(target, dict) and isinstance(target.get("decision"), Decision):
        return target["decision"]
    return None


def _target_kind(target) -> str:
    if isinstance(target, dict):
        candidate = target.get("candidate")
        if candidate is not None and not isinstance(candidate, dict):
            return str(getattr(candidate, "kind", "") or "")
        if isinstance(candidate, dict):
            return str(candidate.get("kind", "") or "")
        return str(target.get("kind", "") or "")
    return ""


def parse_findings(
    obj: dict,
    applied_ids: set,
    total_lines: int,
    pending_ids: set = None,
    targets: Dict = None,
) -> Tuple[List[dict], List[dict]]:
    """校验复查输出，返回 ``(findings, invalid)``。

    每个本批暴露的 applied/pending ID 必须恰好出现一次。这既阻止跨 batch
    改写，也阻止空 findings 冒充全通过。
    """
    del total_lines  # 结果坐标不再用于自动修正，只保留兼容参数。
    findings: List[dict] = []
    invalid: List[dict] = []
    pending_ids = set(pending_ids or set())
    applied_ids = set(applied_ids or set())
    expected_ids = applied_ids | pending_ids
    targets = targets or {}
    raw = obj.get("findings")
    if not isinstance(raw, list):
        raw = []
        invalid.append({"candidate_id": "-", "reason": "复查响应缺少 findings 数组"})

    raw_by_id: Dict[str, List[dict]] = {}
    for item in raw:
        if not isinstance(item, dict):
            invalid.append({"candidate_id": "-", "reason": "findings 中包含非对象条目"})
            continue
        cid = str(item.get("candidate_id", "") or "")
        if cid not in expected_ids:
            verdict = item.get("verdict")
            reason = (
                "复查报告未知候选的疑似漏项，但没有真实源片段，已转人工确认"
                if verdict == "missed-extra"
                else "引用了本批次未暴露的未知修改项"
            )
            invalid.append({"candidate_id": cid, "reason": reason})
            continue
        raw_by_id.setdefault(cid, []).append(item)

    for cid in sorted(expected_ids):
        items = raw_by_id.get(cid, [])
        if not items:
            invalid.append({
                "candidate_id": cid,
                "reason": "复查未返回该候选的 finding，未视为通过",
            })
            continue
        if len(items) != 1:
            invalid.append({
                "candidate_id": cid,
                "reason": f"复查对该候选返回了 {len(items)} 个 findings，无法确定唯一结论",
            })
            continue

        item = items[0]
        verdict = item.get("verdict")
        if verdict not in REVIEW_VERDICTS:
            invalid.append({"candidate_id": cid, "reason": f"非法 verdict {verdict!r}"})
            continue
        if cid in pending_ids and verdict not in {"ok", "missed-extra"}:
            invalid.append({
                "candidate_id": cid,
                "reason": "尚未应用的候选只能判 ok 或 missed-extra",
            })
            continue
        if cid in applied_ids and verdict == "missed-extra":
            invalid.append({
                "candidate_id": cid,
                "reason": "已应用修改不能再次声明为 missed-extra",
            })
            continue

        fix = item.get("fix") if isinstance(item.get("fix"), dict) else {}
        reason = str(item.get("reason", ""))[:120]
        finding = {
            "candidate_id": cid,
            "verdict": verdict,
            "fix": fix,
            "reason": reason,
        }

        if verdict == "wrong-env":
            target = targets.get(cid)
            decision = _target_decision(target)
            env = str(fix.get("env", "") or "")
            evidence = str(fix.get("evidence") or "").strip()[:200]
            supplied_confidence = fix.get("confidence", item.get("confidence"))
            confidence = _as_confidence(supplied_confidence, 0.0)
            kind = _target_kind(target)
            candidate = target.get("candidate") if isinstance(target, dict) else None
            env_hint = str(getattr(candidate, "env_hint", "") or "")
            error = ""
            if decision is None or decision.action != "wrap":
                error = "wrong-env 只能修改本批已应用的 wrap 决策"
            elif env not in ALLOWED_WRAP_ENVS:
                error = f"wrong-env 环境 {env!r} 不在白名单"
            elif kind == "proof" and env != "proof":
                error = "证明候选只能使用 proof 环境"
            elif kind == "theorem-like" and env == "proof":
                error = "定理类候选不能改成 proof 环境"
            elif kind == "theorem-like" and env_hint and env != env_hint:
                error = (
                    f"wrong-env 与源标题确定的环境 {env_hint!r} 冲突；"
                    "复查不得覆盖确定性标题证据"
                )
            elif supplied_confidence is None:
                error = "wrong-env 缺少复查模型自己的置信度"
            elif confidence < REVIEW_ENV_CONFIDENCE:
                error = (
                    f"wrong-env 置信度 {confidence:.0%} 低于"
                    f" {REVIEW_ENV_CONFIDENCE:.0%} 自动修正门"
                )
            elif len(evidence) < 2:
                error = "wrong-env 缺少源文本语义证据"
            if error:
                invalid.append({"candidate_id": cid, "reason": error})
                continue
            finding["fix"] = {
                "env": env,
                "confidence": confidence,
                "evidence": evidence,
            }

        elif verdict == "missed-extra":
            action = fix.get("action")
            env = str(fix.get("env", "") or "")
            confidence = _as_confidence(fix.get("confidence"), 0.0)
            evidence = str(fix.get("evidence", "") or "").strip()[:200]
            if action not in ALLOWED_ACTIONS - {"none"}:
                invalid.append({
                    "candidate_id": cid,
                    "reason": "疑似漏项的 fix 缺少合法 action，已转人工确认",
                })
                continue
            if action == "wrap" and env not in ALLOWED_WRAP_ENVS:
                invalid.append({
                    "candidate_id": cid,
                    "reason": "疑似漏项的环境不在白名单，已转人工确认",
                })
                continue
            if confidence < 0.75 or len(evidence) < 2:
                invalid.append({
                    "candidate_id": cid,
                    "reason": "疑似漏项缺少足够置信度或源文本证据，已转人工确认",
                })
                continue
            finding["fix"] = dict(fix)
            finding["fix"]["confidence"] = confidence
            finding["fix"]["evidence"] = evidence

        findings.append(finding)
    return findings, invalid


def _candidate_metadata(candidate) -> Dict:
    if candidate is None:
        return {}
    payload = getattr(candidate, "payload", {}) or {}
    safe_payload = {
        key: payload[key]
        for key in (
            "keyword", "number", "section_path", "next_kind", "next_line",
            "next_end_line", "env_name",
        )
        if key in payload
    }
    source_atom = str(payload.get("text", "") or "").splitlines()
    candidate_atom_has_body = bool(
        str(payload.get("title_remainder", "") or "").strip()
        or any(line.strip() for line in source_atom[1:])
    )
    return {
        "kind": candidate.kind,
        "rule_id": candidate.rule_id,
        "title": candidate.title_text[:160],
        "env_hint": candidate.env_hint,
        "scanner_confidence": round(float(candidate.confidence), 3),
        "candidate_span": {
            "start_line": candidate.span.start_line,
            "end_line": candidate.span.end_line,
        },
        "candidate_atom_has_body": candidate_atom_has_body,
        "payload": safe_payload,
    }


def build_summaries(applied, candidates_by_id: Dict = None) -> List[Dict]:
    candidates_by_id = candidates_by_id or {}
    summaries = []
    for ap in applied:
        candidate = candidates_by_id.get(ap.decision.candidate_id)
        edit_lines = [edit.line for edit in ap.edits if edit.line > 0]
        source_span = ap.decision.body_span
        if source_span is None and candidate is not None:
            source_span = (candidate.span.start_line, candidate.span.end_line)
        source_span = source_span or (1, 1)
        result_span = (
            (min(edit_lines), max(edit_lines))
            if edit_lines else source_span
        )
        summaries.append({
            "candidate_id": ap.decision.candidate_id,
            "action": ap.decision.action,
            "env": ap.decision.env,
            "reason": ap.decision.reason,
            "confidence": ap.decision.confidence,
            "body_span": source_span,
            "result_span": result_span,
            "candidate": _candidate_metadata(candidate),
        })
    return summaries


def _pending_summaries(
    ambiguous: List[dict],
    candidates_by_id: Dict,
    applied_ids: set,
    doc,
    ai_config: AIConfig,
    structured_envs=None,
    decisions: List[Decision] = None,
) -> List[Dict]:
    reasons: Dict[str, List[str]] = {}
    for item in ambiguous:
        cid = str(item.get("candidate_id", "") or "")
        if cid in candidates_by_id and cid not in applied_ids:
            reason = str(item.get("reason", "") or "")
            if reason and reason not in reasons.setdefault(cid, []):
                reasons[cid].append(reason)
    candidates = [candidates_by_id[cid] for cid in reasons]
    rejected_decisions = {
        decision.candidate_id: decision
        for decision in (decisions or [])
        if getattr(decision, "_legalize_error", "")
    }
    windows, _ = candidate_windows(
        doc, candidates, ai_config, structured_envs
    )
    summaries = []
    for cid, reason_parts in reasons.items():
        candidate = candidates_by_id[cid]
        rejected_decision = rejected_decisions.get(cid)
        source_span = (
            rejected_decision.body_span
            if rejected_decision is not None and rejected_decision.body_span
            else (candidate.span.start_line, candidate.span.end_line)
        )
        summaries.append({
            "candidate_id": cid,
            # Preserve the actual range rejected by the source safety gate.  If
            # this is replaced with candidate.span, review cannot see which
            # post-end atoms the initial model omitted.
            "body_span": source_span,
            "source_window": windows[cid],
            "reason": "；".join(reason_parts)[:300],
            "candidate": _candidate_metadata(candidate),
        })
    return summaries


def _append_unique(items: List[dict], item: dict) -> None:
    if not any(
        old.get("candidate_id") == item.get("candidate_id")
        and old.get("reason") == item.get("reason")
        for old in items
    ):
        items.append(item)


def _invalid_escalation(invalid: dict, candidates_by_id: Dict) -> dict:
    cid = str(invalid.get("candidate_id", "") or "")
    candidate = candidates_by_id.get(cid)
    line = candidate.span.start_line if candidate is not None else 1
    reason = str(invalid.get("reason", "") or "")
    if "疑似漏项" in reason:
        prefix = "AI 复查报告疑似漏项，但无法形成安全源补丁："
    else:
        prefix = "AI 复查未形成唯一有效结论："
    return {"candidate_id": cid, "line": line, "reason": (prefix + reason)[:300]}


def _recover_missed_decision(
    finding: dict,
    candidate,
    doc,
    ai_config: AIConfig,
    structured_envs=None,
) -> Tuple[Optional[Decision], List[dict]]:
    fix = dict(finding.get("fix") or {})
    fix.update({
        "candidate_id": candidate.id,
        "reason": finding.get("reason") or fix.get("evidence", "复查确认漏项"),
    })
    windows, incomplete = candidate_windows(
        doc, [candidate], ai_config, structured_envs
    )
    decisions, ambiguous, _ = parse_decisions(
        {"decisions": [fix]},
        [candidate],
        windows,
        doc,
        incomplete_windows=incomplete,
    )
    if len(decisions) != 1:
        return None, ambiguous
    decision = decisions[0]
    decision.source = "review"
    decision.reason = str(finding.get("reason") or "复查确认漏项")[:120]
    # The reviewer does not bypass the production boundary gate.  A second short
    # selection remains manual; only a range that independently proves complete
    # on source coordinates is eligible to replace the rejected initial decision.
    from .legalize import legalize_wrap

    legalize_wrap(doc, decision, candidate, structured_envs)
    legalize_error = str(getattr(decision, "_legalize_error", "") or "")
    if legalize_error:
        return None, [{
            "candidate_id": candidate.id,
            "line": candidate.span.start_line,
            "reason": "复查范围仍未通过源坐标安全门：" + legalize_error,
        }]
    return decision, []


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
    candidates_by_id: Dict = None,
    preserve_pending_ids: set = None,
):
    """复查并安全修正；最终报告只返回最后一次实际复查轮次。"""
    from ..pricing import add_usage

    candidates_by_id = candidates_by_id or {}
    preserve_pending_ids = set(preserve_pending_ids or set())
    usage_total: Dict = {}
    history: List[dict] = []
    final_findings: List[dict] = []
    final_invalid: List[dict] = []
    preserved_candidate_ids: set[str] = set()
    preserved_findings: Dict[str, dict] = {}
    persistent_escalations: List[dict] = []
    out, applied, rejected, dropped = apply_fn(decisions)
    for d, reason in dropped:
        candidate = candidates_by_id.get(d.candidate_id)
        _append_unique(persistent_escalations, {
            "candidate_id": d.candidate_id,
            "line": candidate.span.start_line if candidate is not None else 1,
            "reason": reason,
        })

    system = build_review_system(build_meta(doc, ctx, mode))
    max_rounds = max(1, ai_config.review_max_rounds)
    completed_batches = 0
    source_lines = doc.text.split("\n")
    applied_ids = {ap.decision.candidate_id for ap in applied}
    pending = _pending_summaries(
        ambiguous,
        candidates_by_id,
        applied_ids,
        doc,
        ai_config,
        ctx.existing_envs,
        decisions,
    )
    pending_by_id = {item["candidate_id"]: item for item in pending}

    for round_index in range(max_rounds):
        if control_callback:
            control_callback()
        # AI 模式下所有实际补丁（包括 bilingual-title/exercise-section 等 rule
        # 决策）都进入复查；模板补丁不在本函数的 decisions 范围内。
        to_review = list(applied)
        batch_size = max(1, ai_config.review_batch)
        review_batches: List[list] = []
        buffered_review: List = []

        def flush_review_buffer() -> None:
            nonlocal buffered_review
            if buffered_review:
                review_batches.append(buffered_review)
                buffered_review = []

        for patch in to_review:
            candidate = candidates_by_id.get(patch.decision.candidate_id)
            if candidate is not None and (
                candidate.kind in {"proof", "scope-fix"}
                or theorem_requires_boundary_singleton(
                    doc, candidate, ctx.existing_envs
                )
            ):
                flush_review_buffer()
                review_batches.append([patch])
                continue
            buffered_review.append(patch)
            if len(buffered_review) >= batch_size:
                flush_review_buffer()
        flush_review_buffer()
        jobs = [(batch, []) for batch in review_batches]
        pending_values = list(pending_by_id.values())
        buffered_pending: List[dict] = []

        def flush_pending_buffer() -> None:
            nonlocal buffered_pending
            if buffered_pending:
                jobs.append(([], buffered_pending))
                buffered_pending = []

        for item in pending_values:
            candidate = candidates_by_id.get(item["candidate_id"])
            if candidate is not None and (
                candidate.kind in {"proof", "scope-fix"}
                or theorem_requires_boundary_singleton(
                    doc, candidate, ctx.existing_envs
                )
            ):
                flush_pending_buffer()
                jobs.append(([], [item]))
                continue
            buffered_pending.append(item)
            if len(buffered_pending) >= batch_size:
                flush_pending_buffer()
        flush_pending_buffer()
        manual_items = [
            item for item in ambiguous
            if str(item.get("candidate_id", "") or "") not in pending_by_id
        ]
        if not jobs and manual_items:
            jobs = [([], [])]
        if not jobs:
            break

        round_findings: List[dict] = []
        round_invalid: List[dict] = []
        round_escalations: List[dict] = []
        for batch, pending_batch in jobs:
            if control_callback:
                control_callback()
            summaries = build_summaries(batch, candidates_by_id)
            visible_ids = {
                ap.decision.candidate_id for ap in batch
            } | {item["candidate_id"] for item in pending_batch}
            other_manual = [
                item for item in manual_items
                if str(item.get("candidate_id", "") or "") not in visible_ids
            ]
            user = build_review_user(
                out,
                summaries,
                other_manual,
                ai_config.context_lines,
                source_lines=source_lines,
                pending_summaries=pending_batch,
                structured_envs=ctx.existing_envs,
            )
            obj, usage = client.chat_json(system, user)
            model = getattr(client, "cfg", None) and client.cfg.model or ""
            add_usage(usage_total, usage, model)
            batch_ids = {ap.decision.candidate_id for ap in batch}
            pending_ids = {item["candidate_id"] for item in pending_batch}
            targets = {
                ap.decision.candidate_id: {
                    "decision": ap.decision,
                    "candidate": candidates_by_id.get(ap.decision.candidate_id),
                }
                for ap in batch
            }
            targets.update({
                cid: {"candidate": candidates_by_id.get(cid)}
                for cid in pending_ids
            })
            findings, invalid = parse_findings(
                obj,
                batch_ids,
                len(out),
                pending_ids=pending_ids,
                targets=targets,
            )
            round_findings.extend(findings)
            round_invalid.extend(invalid)
            for item in invalid:
                _append_unique(
                    round_escalations,
                    _invalid_escalation(item, candidates_by_id),
                )
            completed_batches += 1
            if progress_callback:
                progress_callback({
                    "round": round_index + 1,
                    "rounds": max_rounds,
                    "batch": completed_batches,
                    "usage": dict(usage_total),
                    "findings": len(round_findings),
                })

        final_findings = round_findings
        final_invalid = round_invalid
        history.append({
            "round": round_index + 1,
            "findings": list(round_findings),
            "invalid": list(round_invalid),
        })

        changed = False
        for finding in round_findings:
            if finding["verdict"] != "wrong-range":
                continue
            cid = finding["candidate_id"]
            candidate = candidates_by_id.get(cid)
            _append_unique(persistent_escalations, {
                "candidate_id": cid,
                "line": candidate.span.start_line if candidate is not None else 1,
                "reason": (
                    "AI 复查报告范围问题；结果坐标未写回源文件，"
                    "已撤销对应初次补丁并保留原始正文："
                    + finding.get("reason", "")
                )[:300],
            })

        actionable = [
            finding for finding in round_findings
            if finding["candidate_id"] not in pending_by_id
            and finding["verdict"] in {"wrong-env", "should-remove", "wrong-range"}
        ]
        if actionable:
            for finding in actionable:
                if finding["verdict"] == "should-remove":
                    preserved_candidate_ids.add(finding["candidate_id"])
                    preserved_findings[finding["candidate_id"]] = dict(finding)
            decisions = apply_findings(decisions, actionable, len(source_lines))
            changed = True

        for finding in round_findings:
            cid = finding["candidate_id"]
            if cid not in pending_by_id:
                continue
            pending_by_id.pop(cid, None)
            matching_indexes = [
                index for index, decision in enumerate(decisions)
                if decision.candidate_id == cid
            ]
            if finding["verdict"] == "ok":
                # A no-Decision pending item is auto-resolvable only when it came
                # from an explicit initial action=none.  Missing/duplicate/invalid
                # initial responses also have no Decision, but must remain failed
                # protocol outcomes even if a later reviewer says ``ok``.
                can_preserve = (
                    not matching_indexes and cid in preserve_pending_ids
                )
                if (
                    len(matching_indexes) == 1
                    and getattr(
                        decisions[matching_indexes[0]], "_legalize_error", ""
                    )
                ):
                    # A pending short wrap was never applied.  ``ok`` means the
                    # independent reviewer confirms that preserving the source is
                    # the correct outcome, so remove that exact rejected Decision.
                    # Do not remove overlap/env/protocol failures that never passed
                    # the legalizer: those remain unresolved and fail closed.
                    decisions.pop(matching_indexes[0])
                    changed = True
                    can_preserve = True
                if can_preserve:
                    preserved_candidate_ids.add(cid)
                    preserved_findings[cid] = dict(finding)
                else:
                    candidate = candidates_by_id.get(cid)
                    _append_unique(persistent_escalations, {
                        "candidate_id": cid,
                        "line": (
                            candidate.span.start_line
                            if candidate is not None else 1
                        ),
                        "reason": (
                            (
                                "AI 复查虽建议保留原文，但该 pending 候选仍有"
                                "非 legalizer 范围错误的决策，无法安全自动清理"
                            )
                            if matching_indexes
                            else (
                                "AI 复查的 ok 不能覆盖初次决策的缺失、重复或"
                                "协议错误，候选仍需人工确认"
                            )
                        ),
                    })
                continue
            if finding["verdict"] != "missed-extra":
                continue
            candidate = candidates_by_id.get(cid)
            recovered, recovery_ambiguous = _recover_missed_decision(
                finding, candidate, doc, ai_config, ctx.existing_envs,
            ) if candidate is not None else (None, [])
            if recovered is not None and not matching_indexes:
                decisions.append(recovered)
                changed = True
            elif (
                recovered is not None
                and len(matching_indexes) == 1
                and getattr(decisions[matching_indexes[0]], "_legalize_error", "")
            ):
                # Initial AI wrap exists but was deliberately not applied because
                # its range was short.  Replace that exact rejected decision; do
                # not append a duplicate ID and do not replace unrelated rejects.
                decisions[matching_indexes[0]] = recovered
                changed = True
            else:
                reasons = recovery_ambiguous or [{
                    "candidate_id": cid,
                    "line": candidate.span.start_line if candidate is not None else 1,
                    "reason": "复查漏项无法重新通过源坐标安全校验",
                }]
                for item in reasons:
                    _append_unique(persistent_escalations, {
                        "candidate_id": cid,
                        "line": item.get("line", 1),
                        "reason": (
                            "AI 复查报告疑似漏项，但安全决策未通过："
                            + str(item.get("reason", ""))
                        )[:300],
                    })

        invalid_ids = {
            str(item.get("candidate_id", "") or "") for item in round_invalid
        }
        for cid in list(pending_by_id):
            if cid in invalid_ids:
                pending_by_id.pop(cid, None)
                for item in round_escalations:
                    if item.get("candidate_id") == cid:
                        _append_unique(persistent_escalations, item)

        if not changed:
            for item in round_escalations:
                _append_unique(persistent_escalations, item)
            break

        out, applied, rejected, dropped = apply_fn(decisions)
        for d, reason in dropped:
            candidate = candidates_by_id.get(d.candidate_id)
            _append_unique(persistent_escalations, {
                "candidate_id": d.candidate_id,
                "line": candidate.span.start_line if candidate is not None else 1,
                "reason": reason,
            })

    # 若最后一轮同时包含安全修正与无效回答，循环可能因达到轮次上限结束。
    # 只把“最后一轮仍存在”的无效项升级人工；较早轮次、后来已修复的项不进入
    # 最终报告/清单。
    for item in final_invalid:
        _append_unique(
            persistent_escalations,
            _invalid_escalation(item, candidates_by_id),
        )

    return {
        "findings": final_findings,
        "invalid": final_invalid,
        "history": history,
        "decisions": decisions,
        "out": out,
        "applied": applied,
        "rejected": rejected,
        "usage": usage_total,
        "escalations": persistent_escalations,
        # A valid should-remove finding is a positive review conclusion: the
        # initial patch was a false positive and the source must be preserved.
        # Keep it separate from final decisions so coverage does not mistake
        # the intentional removal for a missing model reply.
        "preserved_candidate_ids": sorted(preserved_candidate_ids),
        "preserved_findings": preserved_findings,
    }


def apply_findings(
    decisions: List[Decision], findings: List[dict], total_lines: int,
) -> List[Decision]:
    """应用不涉及结果坐标写回的复查结论。"""
    del total_lines
    by_verdict: Dict[str, dict] = {
        finding["candidate_id"]: finding for finding in findings
    }
    new_decisions: List[Decision] = []
    for decision in decisions:
        finding = by_verdict.get(decision.candidate_id)
        if finding is None or finding["verdict"] == "ok":
            new_decisions.append(decision)
            continue
        if finding["verdict"] in {"should-remove", "wrong-range"}:
            continue
        if finding["verdict"] == "wrong-env" and decision.action == "wrap":
            decision.env = finding["fix"]["env"]
            decision.confidence = max(
                decision.confidence,
                _as_confidence(finding["fix"].get("confidence")),
            )
            decision.source = "review"
        new_decisions.append(decision)
    return new_decisions

# -*- coding: utf-8 -*-
"""Host-controlled reconciliation for the compile/render/repair loop.

The visual model never emits TeX or source ranges.  It may only name an
immutable formal-inventory item and one small structural verdict.  This module
turns such a verdict into the same reversible :class:`Decision` objects used by
the ordinary pipeline, after rechecking source hashes and target types.
"""

from __future__ import annotations

import copy
import hashlib
from dataclasses import dataclass, field
from typing import Dict, Iterable, List

from .ai import ALLOWED_WRAP_ENVS
from .formal_inventory import FormalAnchor, FormalInventory
from .patch import Decision


@dataclass
class VisualRepairPlan:
    decisions: List[Decision] = field(default_factory=list)
    repair_ids: List[str] = field(default_factory=list)
    preserved_candidate_ids: List[str] = field(default_factory=list)
    invalid: List[dict] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.invalid


def _source_hash(lines: List[str], start_line: int, end_line: int) -> str:
    if not (1 <= start_line <= end_line <= len(lines)):
        return ""
    return hashlib.sha256(
        "\n".join(lines[start_line - 1:end_line]).encode("utf-8")
    ).hexdigest()


def _candidate_for_anchor(anchor: FormalAnchor, candidates_by_id: Dict):
    wanted_kind = "proof" if anchor.suggested_env == "proof" else "theorem-like"
    matches = [
        candidate for candidate in candidates_by_id.values()
        if candidate.kind == wanted_kind
        and candidate.span.start_line == anchor.start_line
    ]
    if len(matches) == 1:
        return matches[0]
    exact = [
        candidate for candidate in matches
        if candidate.env_hint.removesuffix("*")
        == anchor.suggested_env.removesuffix("*")
    ]
    return exact[0] if len(exact) == 1 else None


def _same_environment_target(decision: Decision, start_line: int, end_line: int) -> bool:
    if decision.action not in {"change-env", "unwrap"}:
        return False
    return (
        int(decision.payload.get("begin_line", 0) or 0) == start_line
        and int(decision.payload.get("end_line", 0) or 0) == end_line
    )


def reconcile_visual_repairs(
    decisions: Iterable[Decision],
    suggestions,
    *,
    source_text: str,
    inventory: FormalInventory,
    candidates_by_id: Dict,
) -> VisualRepairPlan:
    """Return a replacement decision set for valid inventory-bound suggestions.

    A naked source anchor can only reuse an already host/model-reviewed wrap
    span.  Visual evidence is never allowed to invent a body boundary.  Existing
    source environments use their exact immutable begin/end lines and hash.
    """

    result = copy.deepcopy(list(decisions))
    lines = source_text.split("\n")
    anchors = {item.id: item for item in inventory.anchors}
    environments = {item.id: item for item in inventory.environments}
    invalid: List[dict] = []
    repair_ids: List[str] = []
    preserved: List[str] = []
    grouped: Dict[str, list] = {}
    for suggestion in suggestions:
        grouped.setdefault(str(getattr(suggestion, "inventory_id", "") or ""), []).append(
            suggestion
        )

    for inventory_id, values in sorted(grouped.items()):
        if not inventory_id or len(values) != 1:
            invalid.append({
                "inventory_id": inventory_id,
                "reason": "同一视觉目标必须恰好有一个修复结论",
            })
            continue
        suggestion = values[0]
        problem = str(getattr(suggestion, "problem", "") or "")
        env = str(getattr(suggestion, "env", "") or "")
        evidence = str(getattr(suggestion, "evidence", "") or "")[:240]
        confidence = float(getattr(suggestion, "confidence", 0.0) or 0.0)

        if inventory_id in anchors:
            anchor = anchors[inventory_id]
            if anchor.original_env:
                invalid.append({
                    "inventory_id": inventory_id,
                    "line": anchor.start_line,
                    "reason": "视觉 anchor 已位于源 formal 环境中，不能作为新增 wrapper 目标",
                })
                continue
            if _source_hash(lines, anchor.start_line, anchor.end_line) != anchor.source_sha256:
                invalid.append({
                    "inventory_id": inventory_id,
                    "line": anchor.start_line,
                    "reason": "视觉修复前源 anchor 哈希已变化",
                })
                continue
            candidate = _candidate_for_anchor(anchor, candidates_by_id)
            if candidate is None:
                invalid.append({
                    "inventory_id": inventory_id,
                    "line": anchor.start_line,
                    "reason": "视觉 anchor 没有宿主扫描器生成的唯一候选",
                })
                continue
            current = [
                decision for decision in result
                if decision.candidate_id == candidate.id and decision.action == "wrap"
            ]
            if len(current) != 1:
                invalid.append({
                    "inventory_id": inventory_id,
                    "candidate_id": candidate.id,
                    "line": anchor.start_line,
                    "reason": "视觉模型不能为 anchor 猜测正文范围；缺少唯一的既有可逆 wrap 决策",
                })
                continue
            if problem in {"missing-env", "wrong-env"}:
                if (
                    env not in ALLOWED_WRAP_ENVS
                    or env.removesuffix("*") != anchor.suggested_env.removesuffix("*")
                    or confidence < 0.95
                ):
                    invalid.append({
                        "inventory_id": inventory_id,
                        "candidate_id": candidate.id,
                        "line": anchor.start_line,
                        "reason": "视觉 wrapper 环境与宿主从源标题确定的类型不一致",
                    })
                    continue
                replacement = copy.deepcopy(current[0])
                replacement.env = env
                replacement.source = "visual-review"
                replacement.reason = evidence or "逐页视觉复核要求恢复正确 formal 环境"
                replacement.confidence = confidence
                replacement.payload = dict(replacement.payload or {})
                replacement.payload["visual_inventory_id"] = inventory_id
                result = [
                    decision for decision in result
                    if not (
                        decision.candidate_id == candidate.id
                        and decision.action == "wrap"
                    )
                ] + [replacement]
            elif problem == "overwrapped":
                if confidence < 0.95:
                    invalid.append({
                        "inventory_id": inventory_id,
                        "candidate_id": candidate.id,
                        "line": anchor.start_line,
                        "reason": "撤销新增 wrapper 的视觉置信度不足",
                    })
                    continue
                result = [
                    decision for decision in result
                    if not (
                        decision.candidate_id == candidate.id
                        and decision.action == "wrap"
                    )
                ]
                preserved.append(candidate.id)
            else:
                invalid.append({
                    "inventory_id": inventory_id,
                    "line": anchor.start_line,
                    "reason": f"anchor 不支持视觉动作 {problem!r}",
                })
                continue
            repair_ids.append(inventory_id)
            continue

        environment = environments.get(inventory_id)
        if environment is None:
            invalid.append({
                "inventory_id": inventory_id,
                "reason": "视觉修复引用了不存在的 formal inventory ID",
            })
            continue
        if (
            _source_hash(lines, environment.start_line, environment.end_line)
            != environment.source_sha256
        ):
            invalid.append({
                "inventory_id": inventory_id,
                "line": environment.start_line,
                "reason": "视觉修复前源 formal 环境哈希已变化",
            })
            continue
        environment_findings = [
            finding for finding in inventory.findings
            if finding.environment_id == inventory_id
        ]
        if problem == "wrong-env":
            host_targets = {
                finding.suggested_env.removesuffix("*")
                for finding in environment_findings
                if finding.kind == "wrong-env"
            }
            if (
                env not in ALLOWED_WRAP_ENVS
                or env == environment.original_env
                or env.removesuffix("*") not in host_targets
                or confidence < 0.95
            ):
                invalid.append({
                    "inventory_id": inventory_id,
                    "line": environment.start_line,
                    "reason": "视觉 change-env 缺少不同且合法的目标环境",
                })
                continue
            action = "change-env"
        elif problem == "overwrapped":
            if (
                not any(
                    finding.kind == "duplicate"
                    for finding in environment_findings
                )
                or confidence < 0.98
            ):
                invalid.append({
                    "inventory_id": inventory_id,
                    "line": environment.start_line,
                    "reason": "视觉 unwrap 未达到 98% 置信度",
                })
                continue
            action = "unwrap"
            env = ""
        else:
            invalid.append({
                "inventory_id": inventory_id,
                "line": environment.start_line,
                "reason": f"现有 formal 环境不支持视觉动作 {problem!r}",
            })
            continue
        result = [
            decision for decision in result
            if not _same_environment_target(
                decision, environment.start_line, environment.end_line
            )
        ]
        result.append(Decision(
            candidate_id=f"visual:{inventory_id}",
            action=action,
            env=env,
            source="visual-review",
            reason=evidence or "逐页视觉复核命中现有 formal 环境",
            confidence=confidence,
            payload={
                "old_env": environment.original_env,
                "begin_line": environment.start_line,
                "end_line": environment.end_line,
                "source_sha256": environment.source_sha256,
                "visual_inventory_id": inventory_id,
            },
        ))
        repair_ids.append(inventory_id)

    return VisualRepairPlan(
        decisions=result,
        repair_ids=repair_ids,
        preserved_candidate_ids=sorted(set(preserved)),
        invalid=invalid,
    )


__all__ = ["VisualRepairPlan", "reconcile_visual_repairs"]

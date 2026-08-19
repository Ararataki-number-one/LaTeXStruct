#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apply LaTeXStruct's production decision safety gate to external packets.

This tool deliberately has no scorer and never opens a gold/score file.  It
combines one or more blind prediction parts, renders each packet exactly as a
single source fragment, and sends every proposed ``wrap`` through the same
parser, scanner, legalizer and final candidate/environment/anchor checks used
by the production pipeline.

The main output remains a top-level prediction array so it can be consumed by
the strict external scorer.  A sibling ``.manifest.json`` records schemas,
input/output SHA-256 hashes, protocol observations and gate outcome counts.

Example (from the repository root)::

    python tools/apply_external_safety_gate.py \
      --packets ../work/external-results/release-packets.json \
      --prediction ../work/external-results/release-predictions-D01-D02.json \
      --prediction ../work/external-results/release-predictions-D03-D04.json \
      --output ../work/external-results/release-production-predictions.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from latexstruct.core.ai import (  # noqa: E402
    ALLOWED_WRAP_ENVS,
    AUTO_APPLY_CONFIDENCE,
)
from latexstruct.core.legalize import legalize_decisions  # noqa: E402
from latexstruct.core.invariants import check_invariants  # noqa: E402
from latexstruct.core.parser import parse_latex  # noqa: E402
from latexstruct.core.patch import (  # noqa: E402
    Decision,
    apply_patches,
    build_ops,
    content_invariant,
)
from latexstruct.core.pipeline import (  # noqa: E402
    _adapt_elegantbook_theorem_env,
    _build_context,
    _normalize_theorem_wrap_start,
    _restore_theorem_title_metadata,
    _unsafe_candidate_env_reason,
    _unsafe_numbered_theorem_reason,
)
from latexstruct.core.scanner import scan  # noqa: E402
from latexstruct.core.verify import compare_braces, compare_env_balance  # noqa: E402


PACKET_SCHEMA_RE = re.compile(
    r"^latexstruct-external-[a-z0-9-]+-packets-v[1-9][0-9]*$"
)
PREDICTION_ENVELOPE_SCHEMA_RE = re.compile(
    r"^latexstruct-external-[a-z0-9-]*predictions-v[1-9][0-9]*$"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ENV_NAME_RE = re.compile(r"^[A-Za-z@][A-Za-z0-9@*:_-]*$")
OUTPUT_ARRAY_SCHEMA = "latexstruct-external-safety-gated-prediction-array-v1"
ENVELOPE_SCHEMA = "latexstruct-external-safety-gate-v1"
MANIFEST_SCHEMA = "latexstruct-external-safety-gate-manifest-v1"
ALLOWED_INPUT_ACTIONS = frozenset({"wrap", "move-boundary", "preserve", "manual"})


@dataclass(frozen=True)
class BlockRange:
    block_id: int
    order: int
    start_off: int
    end_off: int
    start_line: int
    end_line: int


@dataclass(frozen=True)
class RenderedUnit:
    text: str
    blocks: dict[int, BlockRange]
    focus: BlockRange


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _strict_nonempty_string(value: object) -> str | None:
    if not isinstance(value, str) or not value or value != value.strip():
        return None
    return value


def _strict_block_id(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _safe_confidence(value: object) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0 <= float(value) <= 1
    ):
        return 0.0
    return float(value)


def _automatic_confidence_failure(raw: dict) -> tuple[str, str] | None:
    """Return a precise fail-closed audit result for unsafe confidence."""

    if "confidence" not in raw or raw.get("confidence") is None:
        return (
            "manual-missing-confidence",
            "automatic action requires explicit confidence at or above "
            f"the production threshold {AUTO_APPLY_CONFIDENCE:g}",
        )
    value = raw["confidence"]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return (
            "manual-invalid-confidence-type",
            "automatic confidence must be a finite non-boolean number in [0, 1]",
        )
    confidence = float(value)
    if not math.isfinite(confidence):
        return (
            "manual-nonfinite-confidence",
            "automatic confidence must be finite; NaN and infinity are unsafe",
        )
    if not 0 <= confidence <= 1:
        return (
            "manual-out-of-range-confidence",
            "automatic confidence must be in the inclusive range [0, 1]",
        )
    if confidence < AUTO_APPLY_CONFIDENCE:
        return (
            "manual-low-confidence",
            f"automatic confidence {confidence:g} is below the production "
            f"threshold {AUTO_APPLY_CONFIDENCE:g}",
        )
    return None


def _validate_sha256(value: str, label: str) -> str:
    normalized = value.lower()
    if not SHA256_RE.fullmatch(normalized):
        raise ValueError(f"{label} must be a 64-character hexadecimal SHA-256")
    return normalized


def _input_path_is_answer_bearing(path: Path) -> bool:
    tokens = {
        token.lower()
        for token in re.split(r"[^A-Za-z0-9]+", path.stem)
        if token
    }
    return bool(tokens & {"gold", "score"})


def _read_json_input(path: Path, *, expected_sha256: str | None = None) -> tuple[object, str]:
    # Check the name before opening the file.  This is an operational guard,
    # not merely a post-hoc schema check: the safety gate must remain blind.
    if _input_path_is_answer_bearing(path):
        raise ValueError(f"refusing to read answer-bearing gold/score input: {path.name}")
    raw = path.read_bytes()
    actual = _sha256_bytes(raw)
    if expected_sha256 is not None:
        expected = _validate_sha256(expected_sha256, f"expected hash for {path.name}")
        if actual != expected:
            raise ValueError(
                f"SHA-256 mismatch for {path.name}: expected {expected}, found {actual}"
            )
    try:
        return json.loads(raw.decode("utf-8-sig")), actual
    except UnicodeDecodeError as exc:
        raise ValueError(f"{path.name} is not UTF-8 JSON") from exc


def _validate_packet(packet: object) -> tuple[list[dict], frozenset[str]]:
    if not isinstance(packet, dict):
        raise ValueError("packet JSON must be an object")
    schema = packet.get("schema")
    if not isinstance(schema, str) or not PACKET_SCHEMA_RE.fullmatch(schema):
        raise ValueError(f"unsupported packet schema: {schema!r}")
    units = packet.get("units")
    if not isinstance(units, list) or not units:
        raise ValueError("packet units must be a non-empty array")

    instruction_envs = (packet.get("instructions") or {}).get("allowed_environments")
    if instruction_envs is None:
        allowed_envs = frozenset(ALLOWED_WRAP_ENVS)
    elif (
        not isinstance(instruction_envs, list)
        or not instruction_envs
        or any(_strict_nonempty_string(item) is None for item in instruction_envs)
    ):
        raise ValueError("instructions.allowed_environments must be a non-empty string array")
    else:
        allowed_envs = frozenset(instruction_envs)
    unsupported = sorted(allowed_envs - ALLOWED_WRAP_ENVS)
    if unsupported:
        raise ValueError(f"packet declares unsupported wrap environments: {unsupported}")

    seen_ids: set[str] = set()
    for index, unit in enumerate(units):
        if not isinstance(unit, dict):
            raise ValueError(f"packet unit {index} is not an object")
        unit_id = _strict_nonempty_string(unit.get("id"))
        if unit_id is None:
            raise ValueError(f"packet unit {index} has an invalid id")
        if unit_id in seen_ids:
            raise ValueError(f"packet unit id is duplicated: {unit_id}")
        seen_ids.add(unit_id)
        blocks = unit.get("blocks")
        if not isinstance(blocks, list) or not blocks:
            raise ValueError(f"{unit_id}: blocks must be a non-empty array")
        block_ids: set[int] = set()
        previous_block_id = -1
        for block_index, block in enumerate(blocks):
            if not isinstance(block, dict):
                raise ValueError(f"{unit_id}: block {block_index} is not an object")
            block_id = _strict_block_id(block.get("id"))
            if block_id is None or block_id in block_ids:
                raise ValueError(f"{unit_id}: invalid or duplicated block id")
            if block_id <= previous_block_id:
                raise ValueError(f"{unit_id}: block ids must increase in packet order")
            if not isinstance(block.get("text"), str):
                raise ValueError(f"{unit_id}: block {block_id} text must be a string")
            block_ids.add(block_id)
            previous_block_id = block_id
        focus = _strict_block_id(unit.get("focus_anchor"))
        if focus is None or focus not in block_ids:
            raise ValueError(f"{unit_id}: focus_anchor does not name a packet block")
        structured_envs = unit.get("known_structured_environments", [])
        if (
            not isinstance(structured_envs, list)
            or any(
                _strict_nonempty_string(name) is None
                or ENV_NAME_RE.fullmatch(name) is None
                for name in structured_envs
            )
            or len(set(structured_envs)) != len(structured_envs)
        ):
            raise ValueError(
                f"{unit_id}: known_structured_environments must be unique TeX env names"
            )
    return units, allowed_envs


def _prediction_records(payload: object, label: str) -> tuple[list[object], str]:
    if isinstance(payload, list):
        return payload, "prediction-array-v1"
    if isinstance(payload, dict):
        schema = payload.get("schema")
        if not isinstance(schema, str) or not PREDICTION_ENVELOPE_SCHEMA_RE.fullmatch(schema):
            raise ValueError(f"{label}: unsupported prediction envelope schema {schema!r}")
        records = payload.get("predictions")
        if not isinstance(records, list):
            raise ValueError(f"{label}: prediction envelope must contain a predictions array")
        return records, schema
    raise ValueError(f"{label}: predictions must be an array or a supported envelope")


def render_packet_unit(unit: dict) -> RenderedUnit:
    """Render packet blocks exactly as the fixture builders do."""

    pieces: list[str] = []
    ranges: dict[int, BlockRange] = {}
    cursor = 0
    for order, block in enumerate(unit["blocks"]):
        if order:
            pieces.append("\n\n")
            cursor += 2
        start = cursor
        text = block["text"]
        pieces.append(text)
        cursor += len(text)
        block_id = block["id"]
        ranges[block_id] = BlockRange(
            block_id=block_id,
            order=order,
            start_off=start,
            end_off=cursor,
            start_line=0,
            end_line=0,
        )
    rendered = "".join(pieces)
    with_lines: dict[int, BlockRange] = {}
    for block_id, item in ranges.items():
        start_line = rendered.count("\n", 0, item.start_off) + 1
        last_offset = max(item.start_off, item.end_off - 1)
        end_line = rendered.count("\n", 0, last_offset) + 1
        with_lines[block_id] = BlockRange(
            block_id=item.block_id,
            order=item.order,
            start_off=item.start_off,
            end_off=item.end_off,
            start_line=start_line,
            end_line=end_line,
        )
    return RenderedUnit(
        text=rendered,
        blocks=with_lines,
        focus=with_lines[unit["focus_anchor"]],
    )


def _base_result(unit: dict, action: str, reason: str, *, status: str,
                 raw: dict | None, candidate_count: int,
                 candidate_id: str = "", source_span: tuple[int, int] | None = None,
                 end_block: int | None = None) -> dict:
    focus = unit["focus_anchor"]
    result = {
        "id": unit["id"],
        "action": action,
        "env": "",
        "start_block": focus,
        "end_block": focus if end_block is None else end_block,
        "reason": reason,
        "_safety_gate": {
            "status": status,
            "raw_action": raw.get("action") if isinstance(raw, dict) else None,
            "candidate_count": candidate_count,
            "candidate_id": candidate_id,
            "reason": reason,
            "verification": {
                "content_preserved": True,
                "resources_preserved": True,
                "syntax_balanced": True,
                "environment_supported": True,
                "applied_edit": False,
            },
        },
    }
    if source_span is not None:
        result["_safety_gate"]["source_line_span"] = list(source_span)
    if isinstance(raw, dict):
        confidence = _safe_confidence(raw.get("confidence"))
        if confidence:
            result["confidence"] = confidence
    return result


def _preserve(unit: dict, reason: str, raw: dict | None, candidate_count: int) -> dict:
    return _base_result(
        unit,
        "preserve",
        reason,
        status="forced-preserve-no-focus-candidate",
        raw=raw,
        candidate_count=candidate_count,
    )


def _manual(unit: dict, reason: str, raw: dict | None, candidate_count: int,
            candidate_id: str = "", *, status: str = "manual-fail-closed") -> dict:
    return _base_result(
        unit,
        "manual",
        reason,
        status=status,
        raw=raw,
        candidate_count=candidate_count,
        candidate_id=candidate_id,
    )


def _focus_candidates(rendered: RenderedUnit, candidates: Iterable) -> list:
    focus = rendered.focus
    return [
        candidate
        for candidate in candidates
        if candidate.span.start_line <= focus.end_line
        and focus.start_line <= candidate.span.end_line
    ]


def _candidate_environment_reason(candidate, env: str, action: str) -> str:
    expected_kinds = (
        {"scope-fix"} if action == "move-boundary" else {"theorem-like", "proof"}
    )
    if candidate.kind not in expected_kinds:
        return (
            f"focus candidate kind {candidate.kind!r} is not a valid "
            f"{action!r} target"
        )
    if candidate.env_hint and env != candidate.env_hint:
        return (
            f"predicted environment {env!r} conflicts with scanner hint "
            f"{candidate.env_hint!r}"
        )
    return ""


def _block_for_exact_end(rendered: RenderedUnit, line: int) -> BlockRange | None:
    matches = [block for block in rendered.blocks.values() if block.end_line == line]
    if len(matches) != 1:
        return None
    return matches[0]


def gate_packet_unit(unit: dict, raw_items: Sequence[object],
                     allowed_envs: frozenset[str]) -> dict:
    """Return the one production-safe prediction for a packet unit."""

    rendered = render_packet_unit(unit)
    document = parse_latex(rendered.text)
    structured_envs = frozenset(unit.get("known_structured_environments", ()))
    scanned = scan(document, structured_envs=structured_envs)
    focus_candidates = _focus_candidates(rendered, scanned.candidates)
    candidate_count = len(focus_candidates)
    raw = raw_items[0] if len(raw_items) == 1 and isinstance(raw_items[0], dict) else None

    # Scanner-negative focus is authoritative.  It must never become a wrap,
    # even if the model guessed a structure or omitted the unit entirely.
    if not focus_candidates:
        return _preserve(
            unit,
            "production scanner found no candidate at focus; forced preserve",
            raw,
            candidate_count,
        )

    if len(raw_items) != 1:
        reason = (
            "prediction missing for a scanner-positive focus"
            if not raw_items
            else f"{len(raw_items)} predictions target one scanner-positive focus"
        )
        return _manual(unit, reason, raw, candidate_count)
    if raw is None:
        return _manual(unit, "prediction record is not an object", None, candidate_count)

    action = raw.get("action")
    if action in {"manual", "preserve"}:
        return _manual(
            unit,
            f"scanner-positive focus with model action {action!r} requires manual review",
            raw,
            candidate_count,
        )
    if action not in ALLOWED_INPUT_ACTIONS:
        return _manual(unit, f"invalid prediction action {action!r}", raw, candidate_count)

    confidence_failure = _automatic_confidence_failure(raw)
    if confidence_failure is not None:
        status, reason = confidence_failure
        return _manual(
            unit,
            reason,
            raw,
            candidate_count,
            status=status,
        )

    # One external prediction cannot provide the production requirement of one
    # unique decision per candidate when multiple candidates overlap the focus.
    if candidate_count != 1:
        return _manual(
            unit,
            f"focus overlaps {candidate_count} scanner candidates; unique target is unprovable",
            raw,
            candidate_count,
        )
    candidate = focus_candidates[0]
    candidate_id = candidate.id
    if not (
        rendered.focus.start_line
        <= candidate.span.start_line
        <= rendered.focus.end_line
    ):
        return _manual(
            unit,
            "scanner candidate starts outside focus anchor",
            raw,
            candidate_count,
            candidate_id,
        )

    env = raw.get("env")
    if (
        not isinstance(env, str)
        or not env
        or env != env.strip()
        or env not in allowed_envs
        or env not in ALLOWED_WRAP_ENVS
    ):
        return _manual(
            unit,
            f"invalid or disallowed wrap environment {env!r}",
            raw,
            candidate_count,
            candidate_id,
        )
    env_reason = _candidate_environment_reason(candidate, env, action)
    if env_reason:
        return _manual(unit, env_reason, raw, candidate_count, candidate_id)

    start_id = _strict_block_id(raw.get("start_block"))
    end_id = _strict_block_id(raw.get("end_block"))
    if start_id not in rendered.blocks or end_id not in rendered.blocks:
        return _manual(
            unit,
            "automatic boundary does not name existing packet blocks",
            raw,
            candidate_count,
            candidate_id,
        )
    if start_id != unit["focus_anchor"]:
        return _manual(
            unit,
            "automatic start_block is not the focus anchor",
            raw,
            candidate_count,
            candidate_id,
        )
    start_block = rendered.blocks[start_id]
    end_block = rendered.blocks[end_id]
    if end_block.order < start_block.order:
        return _manual(
            unit,
            "automatic end_block precedes the focus anchor",
            raw,
            candidate_count,
            candidate_id,
        )

    if action == "move-boundary":
        old_end = candidate.span.end_line
        new_end = candidate.payload.get("next_end_line")
        if not isinstance(new_end, int) or end_block.end_line != new_end:
            return _manual(
                unit,
                "predicted move boundary does not equal the scanner-proven target",
                raw,
                candidate_count,
                candidate_id,
            )
        decision = Decision(
            candidate_id=candidate_id,
            action="move-boundary",
            env=env,
            source="ai",
            reason=str(raw.get("reason", ""))[:240],
            confidence=_safe_confidence(raw.get("confidence")),
            payload={"old_end_line": old_end, "new_end_line": new_end},
        )
    else:
        decision = Decision(
            candidate_id=candidate_id,
            action="wrap",
            env=env,
            source="ai",
            reason=str(raw.get("reason", ""))[:240],
            confidence=_safe_confidence(raw.get("confidence")),
            body_span=(start_block.start_line, end_block.end_line),
        )
    by_id = {candidate.id: candidate}
    if action == "wrap":
        legalize_decisions(document, [decision], by_id, structured_envs)
    unsafe_reason = str(getattr(decision, "_legalize_error", "") or "")
    if not unsafe_reason:
        unsafe_reason = _unsafe_candidate_env_reason(decision, candidate)
    if not unsafe_reason:
        unsafe_reason = _normalize_theorem_wrap_start(decision, candidate)

    # These deterministic metadata/numbering/build checks are also in the
    # production application path.  They ensure a range that passed semantic
    # legalization can actually be converted into patch operations.
    context = _build_context(document, structured_envs)
    if not unsafe_reason and action == "wrap":
        _restore_theorem_title_metadata(decision, candidate)
        _adapt_elegantbook_theorem_env(decision, candidate, context)
        unsafe_reason = _unsafe_numbered_theorem_reason(decision, candidate, context)
    if not unsafe_reason and decision.env not in allowed_envs:
        unsafe_reason = (
            f"production environment adaptation produced disallowed env {decision.env!r}"
        )
    if not unsafe_reason:
        ops, unsafe_reason = build_ops(decision, document.text.split("\n"), context)
        if not unsafe_reason and not ops:
            unsafe_reason = "production patch builder emitted no operations"
    verification = None
    if not unsafe_reason:
        original_lines = document.text.split("\n")
        output_lines, applied, rejected = apply_patches(
            original_lines, [(decision, ops)]
        )
        after = "\n".join(output_lines)
        invariants = check_invariants(document.text, after)
        braces = compare_braces(document.text, after)
        environments = compare_env_balance(document.text, after)
        verification = {
            "content_preserved": bool(
                not rejected
                and len(applied) == 1
                and content_invariant(original_lines, output_lines, applied)
            ),
            "resources_preserved": bool(
                invariants.get("images", {}).get("equal")
            ),
            "syntax_balanced": bool(braces.get("ok") and environments.get("ok")),
            "environment_supported": bool(decision.env in allowed_envs),
            "applied_edit": True,
        }
        if not all(
            verification[name]
            for name in (
                "content_preserved",
                "resources_preserved",
                "syntax_balanced",
                "environment_supported",
            )
        ):
            unsafe_reason = "applied patch failed deterministic content/resource/syntax verification"
    if unsafe_reason:
        return _manual(unit, unsafe_reason, raw, candidate_count, candidate_id)

    if action == "move-boundary":
        result = _base_result(
            unit,
            "move-boundary",
            "production scanner and deterministic safety gates accepted the boundary move",
            status="accepted-move-boundary",
            raw=raw,
            candidate_count=candidate_count,
            candidate_id=candidate_id,
            source_span=(candidate.span.start_line, end_block.end_line),
            end_block=end_block.block_id,
        )
        result["env"] = decision.env
        result["_safety_gate"]["verification"] = verification
        return result

    if not decision.body_span:
        return _manual(
            unit,
            "legalizer returned no body span",
            raw,
            candidate_count,
            candidate_id,
        )
    legal_start, legal_end = decision.body_span
    if not (
        rendered.focus.start_line <= legal_start <= rendered.focus.end_line
        and legal_start == candidate.span.start_line
    ):
        return _manual(
            unit,
            "legalized start does not equal the scanner-confirmed focus anchor line",
            raw,
            candidate_count,
            candidate_id,
        )
    exact_end = _block_for_exact_end(rendered, legal_end)
    if exact_end is None or exact_end.order < rendered.focus.order:
        return _manual(
            unit,
            "legalized source end cannot be represented by one exact packet block boundary",
            raw,
            candidate_count,
            candidate_id,
        )

    result = _base_result(
        unit,
        "wrap",
        "production scanner and deterministic safety gates accepted the wrap",
        status="accepted-wrap",
        raw=raw,
        candidate_count=candidate_count,
        candidate_id=candidate_id,
        source_span=decision.body_span,
        end_block=exact_end.block_id,
    )
    result["env"] = decision.env
    result["_safety_gate"]["verification"] = verification
    return result


def _validate_gate_output(records: list[dict], units: list[dict],
                          allowed_envs: frozenset[str]) -> None:
    expected_ids = [unit["id"] for unit in units]
    if len(records) != len(expected_ids):
        raise AssertionError("safety gate did not emit exactly one result per packet unit")
    if [item.get("id") for item in records] != expected_ids:
        raise AssertionError("safety gate output order/IDs differ from the packet")
    unit_by_id = {unit["id"]: unit for unit in units}
    for item in records:
        unit = unit_by_id[item["id"]]
        action = item.get("action")
        env = item.get("env")
        start = _strict_block_id(item.get("start_block"))
        end = _strict_block_id(item.get("end_block"))
        block_order = {block["id"]: index for index, block in enumerate(unit["blocks"])}
        if action not in ALLOWED_INPUT_ACTIONS:
            raise AssertionError(f"invalid gated action for {item['id']}")
        if not isinstance(env, str) or env != env.strip():
            raise AssertionError(f"invalid gated env for {item['id']}")
        if start not in block_order or end not in block_order:
            raise AssertionError(f"invalid gated boundary for {item['id']}")
        if start != unit["focus_anchor"] or block_order[start] > block_order[end]:
            raise AssertionError(f"unsafe gated anchor/range for {item['id']}")
        if action in {"wrap", "move-boundary"}:
            if not env or env not in allowed_envs:
                raise AssertionError(f"invalid gated automatic env for {item['id']}")
            confidence_failure = _automatic_confidence_failure(item)
            if confidence_failure is not None:
                raise AssertionError(
                    f"unsafe gated automatic confidence for {item['id']}: "
                    f"{confidence_failure[1]}"
                )
        elif env or end != unit["focus_anchor"]:
            raise AssertionError(f"manual/preserve must use the focus boundary for {item['id']}")
        gate = item.get("_safety_gate")
        if not isinstance(gate, dict) or _strict_nonempty_string(gate.get("status")) is None:
            raise AssertionError(f"missing safety gate audit for {item['id']}")


def apply_safety_gate(packet: object, prediction_payloads: Sequence[object]) -> dict:
    """Return a schema-bearing envelope with production-safe predictions."""

    units, allowed_envs = _validate_packet(packet)
    packet_ids = {unit["id"] for unit in units}
    records_by_id: dict[str, list[object]] = defaultdict(list)
    input_schemas: list[str] = []
    unknown_ids: list[str] = []
    invalid_record_count = 0
    source_record_count = 0
    for index, payload in enumerate(prediction_payloads):
        records, schema = _prediction_records(payload, f"prediction input {index + 1}")
        input_schemas.append(schema)
        source_record_count += len(records)
        for record in records:
            if not isinstance(record, dict):
                invalid_record_count += 1
                continue
            unit_id = _strict_nonempty_string(record.get("id"))
            if unit_id is None:
                invalid_record_count += 1
                continue
            if unit_id not in packet_ids:
                unknown_ids.append(unit_id)
                continue
            records_by_id[unit_id].append(record)

    output = [
        gate_packet_unit(unit, records_by_id.get(unit["id"], ()), allowed_envs)
        for unit in units
    ]
    _validate_gate_output(output, units, allowed_envs)
    duplicate_ids = sorted(
        unit_id for unit_id, records in records_by_id.items() if len(records) > 1
    )
    duplicate_record_count = sum(
        max(0, len(records) - 1) for records in records_by_id.values()
    )
    missing_ids = sorted(unit_id for unit_id in packet_ids if unit_id not in records_by_id)
    raw_protocol_error_count = (
        len(missing_ids)
        + duplicate_record_count
        + len(unknown_ids)
        + invalid_record_count
    )
    outcome_counts = Counter(item["action"] for item in output)
    status_counts = Counter(item["_safety_gate"]["status"] for item in output)
    document_verification = {}
    for unit, result in zip(units, output):
        document_id = str(unit.get("document_id", "") or "")
        if not document_id:
            continue
        entry = document_verification.setdefault(document_id, {
            "document": document_id,
            "unit_count": 0,
            "content_preserved": True,
            "resources_preserved": True,
            "syntax_balanced": True,
            "environments_supported": True,
        })
        entry["unit_count"] += 1
        verification = result["_safety_gate"]["verification"]
        for target, source in (
            ("content_preserved", "content_preserved"),
            ("resources_preserved", "resources_preserved"),
            ("syntax_balanced", "syntax_balanced"),
            ("environments_supported", "environment_supported"),
        ):
            entry[target] = bool(entry[target] and verification[source])
    return {
        "schema": ENVELOPE_SCHEMA,
        "packet_schema": packet["schema"],
        "output_array_schema": OUTPUT_ARRAY_SCHEMA,
        "predictions": output,
        "audit": {
            "packet_units": len(units),
            "source_prediction_records": source_record_count,
            "output_units": len(output),
            "input_prediction_schemas": input_schemas,
            "missing_ids": missing_ids,
            "duplicate_ids": duplicate_ids,
            "duplicate_record_count": duplicate_record_count,
            "unknown_ids": sorted(unknown_ids),
            "invalid_record_count": invalid_record_count,
            "raw_protocol_error_count": raw_protocol_error_count,
            "outcome_counts": dict(sorted(outcome_counts.items())),
            "status_counts": dict(sorted(status_counts.items())),
            "document_verification": [
                document_verification[key] for key in sorted(document_verification)
            ],
        },
    }


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(data)
    temporary.replace(path)


def write_gate_outputs(output_path: Path, manifest_path: Path, envelope: dict,
                       *, packet_path: Path, packet_hash: str,
                       prediction_paths: Sequence[Path], prediction_hashes: Sequence[str],
                       expected_output_sha256: str | None = None) -> dict:
    predictions = envelope["predictions"]
    output_bytes = _json_bytes(predictions)
    output_hash = _sha256_bytes(output_bytes)
    if expected_output_sha256 is not None:
        expected = _validate_sha256(expected_output_sha256, "expected output hash")
        if output_hash != expected:
            raise ValueError(
                f"output SHA-256 mismatch: expected {expected}, produced {output_hash}"
            )
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "packet": {
            "name": packet_path.name,
            "schema": envelope["packet_schema"],
            "sha256": packet_hash,
        },
        "prediction_inputs": [
            {
                "index": index,
                "name": path.name,
                "schema": envelope["audit"]["input_prediction_schemas"][index],
                "sha256": prediction_hashes[index],
            }
            for index, path in enumerate(prediction_paths)
        ],
        "output": {
            "name": output_path.name,
            "schema": OUTPUT_ARRAY_SCHEMA,
            "sha256": output_hash,
            "unit_count": len(predictions),
        },
        "audit": envelope["audit"],
    }
    _atomic_write(output_path, output_bytes)
    _atomic_write(manifest_path, _json_bytes(manifest))
    return manifest


def _default_manifest_path(output: Path) -> Path:
    return output.with_name(f"{output.stem}.manifest.json")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packets", type=Path, required=True, help="blind packet JSON")
    parser.add_argument(
        "--prediction",
        type=Path,
        action="append",
        required=True,
        help="prediction JSON array/envelope; repeat for disjoint parts",
    )
    parser.add_argument("--output", type=Path, required=True, help="gated prediction array")
    parser.add_argument("--manifest", type=Path, help="hash/schema sidecar path")
    parser.add_argument("--expect-packet-sha256")
    parser.add_argument(
        "--expect-prediction-sha256",
        action="append",
        default=[],
        help="expected prediction hash in --prediction order; repeat for all inputs",
    )
    parser.add_argument("--expect-output-sha256")
    args = parser.parse_args(argv)

    prediction_paths = [path.resolve() for path in args.prediction]
    packet_path = args.packets.resolve()
    output_path = args.output.resolve()
    manifest_path = (args.manifest.resolve() if args.manifest else _default_manifest_path(output_path))
    input_paths = {packet_path, *prediction_paths}
    if output_path in input_paths or manifest_path in input_paths:
        parser.error("output/manifest must not overwrite an input")
    if output_path == manifest_path:
        parser.error("output and manifest must be different paths")
    expected_prediction_hashes = args.expect_prediction_sha256
    if expected_prediction_hashes and len(expected_prediction_hashes) != len(prediction_paths):
        parser.error("provide one --expect-prediction-sha256 for every --prediction")

    try:
        packet, packet_hash = _read_json_input(
            packet_path,
            expected_sha256=args.expect_packet_sha256,
        )
        prediction_payloads: list[object] = []
        prediction_hashes: list[str] = []
        for index, path in enumerate(prediction_paths):
            expected = expected_prediction_hashes[index] if expected_prediction_hashes else None
            payload, payload_hash = _read_json_input(path, expected_sha256=expected)
            prediction_payloads.append(payload)
            prediction_hashes.append(payload_hash)
        envelope = apply_safety_gate(packet, prediction_payloads)
        manifest = write_gate_outputs(
            output_path,
            manifest_path,
            envelope,
            packet_path=packet_path,
            packet_hash=packet_hash,
            prediction_paths=prediction_paths,
            prediction_hashes=prediction_hashes,
            expected_output_sha256=args.expect_output_sha256,
        )
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError, AssertionError) as exc:
        parser.error(str(exc))

    print(json.dumps({
        "output": str(output_path),
        "manifest": str(manifest_path),
        "output_sha256": manifest["output"]["sha256"],
        "audit": manifest["audit"],
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Normalize frozen Codex blind answers to the formal prediction schema.

This adapter is intentionally limited to protocol shape.  It may rename the
legacy ``unit_id`` field, materialize the packet focus for null
``preserve``/``manual`` boundaries, and add transparent metadata.  It never
repairs an automatic action or changes an action, environment, or automatic
boundary.

All packet and prediction hashes are mandatory at the command line so the
adapter cannot silently normalize a different pass than the one that was
frozen and reviewed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Sequence


PACKET_SCHEMA_RE = re.compile(r"^latexstruct-external-[a-z0-9-]+-packets-v[1-9][0-9]*$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ENV_NAME_RE = re.compile(r"^[A-Za-z@][A-Za-z0-9@*:_-]*$")
ACTIONS = frozenset({"preserve", "wrap", "move-boundary", "manual"})
AUTOMATIC_ACTIONS = frozenset({"wrap", "move-boundary"})
INPUT_FIELDS = frozenset(
    {
        "id",
        "unit_id",
        "action",
        "env",
        "start_block",
        "end_block",
        "reason",
        "confidence",
    }
)
OUTPUT_ARRAY_SCHEMA = "latexstruct-codex-blind-prediction-array-v1"
MANIFEST_SCHEMA = "latexstruct-codex-blind-normalization-manifest-v1"
NORMALIZATION_REASON = (
    "Protocol-shape normalization only; semantic action, environment, and "
    "automatic boundaries are unchanged."
)
DEFAULT_CONFIDENCE = 0.0
FORBIDDEN_INPUT_NAME_TOKENS = frozenset(
    {
        "builder",
        "corpus",
        "fixture",
        "gold",
        "score",
        "source",
        "validation",
    }
)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _strict_string(value: object) -> str | None:
    if not isinstance(value, str) or not value or value != value.strip():
        return None
    return value


def _strict_block_id(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _validate_sha256(value: str, label: str) -> str:
    normalized = value.lower()
    if not SHA256_RE.fullmatch(normalized):
        raise ValueError(f"{label} must be a 64-character hexadecimal SHA-256")
    return normalized


def _input_path_is_forbidden(path: Path) -> bool:
    tokens = {token.lower() for token in re.split(r"[^A-Za-z0-9]+", path.stem) if token}
    return bool(tokens & FORBIDDEN_INPUT_NAME_TOKENS)


def _read_json_input(path: Path, *, expected_sha256: str) -> tuple[object, str]:
    # Refuse answer-bearing or corpus inputs before opening the path.  This
    # keeps the adapter operationally isolated, not merely label-blind later.
    if _input_path_is_forbidden(path):
        raise ValueError(f"refusing forbidden blind-normalization input: {path.name}")
    expected = _validate_sha256(expected_sha256, f"expected hash for {path.name}")
    raw = path.read_bytes()
    actual = _sha256_bytes(raw)
    if actual != expected:
        raise ValueError(f"SHA-256 mismatch for {path.name}: expected {expected}, found {actual}")
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
    instructions = packet.get("instructions")
    if not isinstance(instructions, dict):
        raise ValueError("packet instructions must be an object")
    raw_allowed_envs = instructions.get("allowed_environments")
    if (
        not isinstance(raw_allowed_envs, list)
        or not raw_allowed_envs
        or any(
            _strict_string(env) is None or ENV_NAME_RE.fullmatch(env) is None
            for env in raw_allowed_envs
        )
        or len(set(raw_allowed_envs)) != len(raw_allowed_envs)
    ):
        raise ValueError("instructions.allowed_environments must be unique TeX environment names")
    allowed_envs = frozenset(raw_allowed_envs)

    units = packet.get("units")
    if not isinstance(units, list) or not units:
        raise ValueError("packet units must be a non-empty array")
    seen_ids: set[str] = set()
    for index, unit in enumerate(units):
        if not isinstance(unit, dict):
            raise ValueError(f"packet unit {index} is not an object")
        unit_id = _strict_string(unit.get("id"))
        if unit_id is None:
            raise ValueError(f"packet unit {index} has an invalid id")
        if unit_id in seen_ids:
            raise ValueError(f"packet unit id is duplicated: {unit_id}")
        seen_ids.add(unit_id)
        blocks = unit.get("blocks")
        if not isinstance(blocks, list) or not blocks:
            raise ValueError(f"{unit_id}: blocks must be a non-empty array")
        block_ids: set[int] = set()
        previous_id = -1
        for block_index, block in enumerate(blocks):
            if not isinstance(block, dict):
                raise ValueError(f"{unit_id}: block {block_index} is not an object")
            block_id = _strict_block_id(block.get("id"))
            if block_id is None or block_id in block_ids:
                raise ValueError(f"{unit_id}: invalid or duplicated block id")
            if block_id <= previous_id:
                raise ValueError(f"{unit_id}: block ids must increase in packet order")
            if not isinstance(block.get("text"), str):
                raise ValueError(f"{unit_id}: block {block_id} text must be a string")
            block_ids.add(block_id)
            previous_id = block_id
        focus = _strict_block_id(unit.get("focus_anchor"))
        if focus is None or focus not in block_ids:
            raise ValueError(f"{unit_id}: focus_anchor does not name a packet block")
    return units, allowed_envs


def _record_id(record: dict, label: str) -> tuple[str, bool, bool]:
    has_id = "id" in record
    has_unit_id = "unit_id" in record
    if not has_id and not has_unit_id:
        raise ValueError(f"{label}: missing id/unit_id")
    canonical_id = _strict_string(record.get("id")) if has_id else None
    legacy_id = _strict_string(record.get("unit_id")) if has_unit_id else None
    if has_id and canonical_id is None:
        raise ValueError(f"{label}: invalid id")
    if has_unit_id and legacy_id is None:
        raise ValueError(f"{label}: invalid unit_id")
    if canonical_id is not None and legacy_id is not None and canonical_id != legacy_id:
        raise ValueError(f"{label}: conflicting id/unit_id ({canonical_id!r} != {legacy_id!r})")
    return canonical_id or legacy_id or "", not has_id, has_id and has_unit_id


def _confidence(value: object, label: str) -> float | int:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0 <= float(value) <= 1
    ):
        raise ValueError(f"{label}: confidence must be a finite number from 0 to 1")
    return value


def _normalize_record(
    record: dict,
    unit: dict,
    allowed_envs: frozenset[str],
    *,
    label: str,
) -> tuple[dict, dict[str, int]]:
    unknown_fields = sorted(set(record) - INPUT_FIELDS)
    if unknown_fields:
        raise ValueError(f"{label}: unsupported fields: {unknown_fields}")
    record_id, used_legacy_id, had_both_ids = _record_id(record, label)
    if record_id != unit["id"]:
        raise AssertionError("record/unit identity mismatch during normalization")

    action = record.get("action")
    if not isinstance(action, str) or action not in ACTIONS:
        raise ValueError(f"{record_id}: invalid action {action!r}")
    env = record.get("env")
    if not isinstance(env, str) or env != env.strip():
        raise ValueError(f"{record_id}: env must be a trimmed string")
    if action in AUTOMATIC_ACTIONS:
        if not env or env not in allowed_envs:
            raise ValueError(
                f"{record_id}: automatic action has invalid or packet-disallowed env {env!r}"
            )
    elif env:
        raise ValueError(f"{record_id}: {action} must use an empty env")

    if "start_block" not in record or "end_block" not in record:
        raise ValueError(f"{record_id}: start_block and end_block are required")
    source_start = record["start_block"]
    source_end = record["end_block"]
    focus = unit["focus_anchor"]
    block_order = {block["id"]: index for index, block in enumerate(unit["blocks"])}
    derived_boundary_fields = 0
    if action in AUTOMATIC_ACTIONS:
        if source_start is None or source_end is None:
            raise ValueError(
                f"{record_id}: refusing attempted automatic-boundary repair for {action}"
            )
        start = _strict_block_id(source_start)
        end = _strict_block_id(source_end)
        if start not in block_order or end not in block_order:
            raise ValueError(f"{record_id}: automatic boundary is not a packet block")
        if start != focus:
            raise ValueError(f"{record_id}: automatic start_block must equal focus_anchor")
        if block_order[end] < block_order[start]:
            raise ValueError(f"{record_id}: automatic end_block precedes start_block")
        # Assign verbatim values after validation: automatic boundaries are
        # never inferred, widened, narrowed, or converted by this adapter.
        start = source_start
        end = source_end
    else:
        if source_start is None:
            start = focus
            derived_boundary_fields += 1
        else:
            start = _strict_block_id(source_start)
            if start != focus:
                raise ValueError(f"{record_id}: {action} start_block must equal focus_anchor")
        if source_end is None:
            end = focus
            derived_boundary_fields += 1
        else:
            end = _strict_block_id(source_end)
            if end != focus:
                raise ValueError(f"{record_id}: {action} end_block must equal focus_anchor")

    source_reason = record.get("reason")
    reason_added = 0
    if source_reason is None or source_reason == "":
        reason = NORMALIZATION_REASON
        reason_added = 1
    elif not isinstance(source_reason, str) or source_reason != source_reason.strip():
        raise ValueError(f"{record_id}: reason must be a nonempty trimmed string")
    else:
        reason = source_reason

    source_confidence = record.get("confidence")
    confidence_added = 0
    if source_confidence is None:
        confidence: float | int = DEFAULT_CONFIDENCE
        confidence_added = 1
    else:
        confidence = _confidence(source_confidence, record_id)

    output = {
        "id": record_id,
        "action": action,
        "env": env,
        "start_block": start,
        "end_block": end,
        "reason": reason,
        "confidence": confidence,
    }
    source_semantics = (
        record_id,
        action,
        env,
        focus if source_start is None and action not in AUTOMATIC_ACTIONS else source_start,
        focus if source_end is None and action not in AUTOMATIC_ACTIONS else source_end,
    )
    output_semantics = (
        output["id"],
        output["action"],
        output["env"],
        output["start_block"],
        output["end_block"],
    )
    if source_semantics != output_semantics:
        raise AssertionError(f"{record_id}: semantic fields changed during normalization")
    return output, {
        "legacy_id_conversion_count": int(used_legacy_id),
        "matching_dual_id_count": int(had_both_ids),
        "derived_boundary_field_count": derived_boundary_fields,
        "derived_boundary_record_count": int(derived_boundary_fields > 0),
        "reason_addition_count": reason_added,
        "confidence_addition_count": confidence_added,
        "automatic_record_count": int(action in AUTOMATIC_ACTIONS),
    }


def normalize_predictions(packet: object, prediction_payloads: Sequence[object]) -> dict:
    """Return normalized predictions and a strict semantic-change audit."""

    units, allowed_envs = _validate_packet(packet)
    unit_by_id = {unit["id"]: unit for unit in units}
    normalized_by_id: dict[str, dict] = {}
    audit_counts: Counter[str] = Counter()
    input_record_counts: list[int] = []

    for input_index, payload in enumerate(prediction_payloads, start=1):
        if not isinstance(payload, list) or not payload:
            raise ValueError(f"prediction input {input_index} must be a non-empty JSON array")
        input_record_counts.append(len(payload))
        for record_index, record in enumerate(payload):
            label = f"prediction input {input_index} record {record_index}"
            if not isinstance(record, dict):
                raise ValueError(f"{label} is not an object")
            record_id, _, _ = _record_id(record, label)
            if record_id not in unit_by_id:
                raise ValueError(f"{label}: unknown packet id {record_id!r}")
            if record_id in normalized_by_id:
                raise ValueError(f"duplicate prediction id across frozen parts: {record_id}")
            normalized, record_audit = _normalize_record(
                record,
                unit_by_id[record_id],
                allowed_envs,
                label=label,
            )
            normalized_by_id[record_id] = normalized
            audit_counts.update(record_audit)

    missing_ids = [unit["id"] for unit in units if unit["id"] not in normalized_by_id]
    if missing_ids:
        preview = ", ".join(missing_ids[:5])
        suffix = "..." if len(missing_ids) > 5 else ""
        raise ValueError(f"missing {len(missing_ids)} packet prediction IDs: {preview}{suffix}")
    output = [normalized_by_id[unit["id"]] for unit in units]
    if len(output) != sum(input_record_counts):
        raise AssertionError("normalization did not preserve the one-record-per-unit count")
    action_counts = Counter(record["action"] for record in output)
    return {
        "packet_schema": packet["schema"],
        "predictions": output,
        "input_record_counts": input_record_counts,
        "audit": {
            "packet_units": len(units),
            "source_prediction_records": sum(input_record_counts),
            "output_units": len(output),
            "legacy_id_conversion_count": audit_counts["legacy_id_conversion_count"],
            "matching_dual_id_count": audit_counts["matching_dual_id_count"],
            "derived_boundary_field_count": audit_counts["derived_boundary_field_count"],
            "derived_boundary_record_count": audit_counts["derived_boundary_record_count"],
            "reason_addition_count": audit_counts["reason_addition_count"],
            "confidence_addition_count": audit_counts["confidence_addition_count"],
            "automatic_record_count": audit_counts["automatic_record_count"],
            "automatic_boundary_repair_count": 0,
            "semantic_change_count": 0,
            "action_counts": dict(sorted(action_counts.items())),
        },
    }


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(data)
    temporary.replace(path)


def _default_manifest_path(output: Path) -> Path:
    return output.with_name(f"{output.stem}.manifest.json")


def write_normalized_outputs(
    output_path: Path,
    manifest_path: Path,
    result: dict,
    *,
    packet_path: Path,
    packet_hash: str,
    prediction_paths: Sequence[Path],
    prediction_hashes: Sequence[str],
) -> dict:
    output_bytes = _json_bytes(result["predictions"])
    output_hash = _sha256_bytes(output_bytes)
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "normalization": {
            "output_schema": OUTPUT_ARRAY_SCHEMA,
            "added_reason": NORMALIZATION_REASON,
            "default_confidence": DEFAULT_CONFIDENCE,
            "semantic_fields": ["id", "action", "env", "start_block", "end_block"],
        },
        "packet": {
            "name": packet_path.name,
            "schema": result["packet_schema"],
            "sha256": packet_hash,
        },
        "prediction_inputs": [
            {
                "index": index,
                "name": path.name,
                "sha256": prediction_hashes[index],
                "record_count": result["input_record_counts"][index],
            }
            for index, path in enumerate(prediction_paths)
        ],
        "output": {
            "name": output_path.name,
            "schema": OUTPUT_ARRAY_SCHEMA,
            "sha256": output_hash,
            "unit_count": len(result["predictions"]),
        },
        "audit": result["audit"],
    }
    _atomic_write(output_path, output_bytes)
    _atomic_write(manifest_path, _json_bytes(manifest))
    return manifest


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packets", type=Path, required=True, help="frozen blind packet")
    parser.add_argument(
        "--prediction",
        type=Path,
        action="append",
        required=True,
        help="frozen blind prediction array; repeat for disjoint parts",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--expect-packet-sha256", required=True)
    parser.add_argument(
        "--expect-prediction-sha256",
        action="append",
        required=True,
        help="expected hash in --prediction order; repeat for every input",
    )
    args = parser.parse_args(argv)

    packet_path = args.packets.resolve()
    prediction_paths = [path.resolve() for path in args.prediction]
    output_path = args.output.resolve()
    manifest_path = (
        args.manifest.resolve() if args.manifest else _default_manifest_path(output_path)
    )
    if len(set(prediction_paths)) != len(prediction_paths):
        parser.error("each frozen prediction path may be supplied only once")
    input_paths = {packet_path, *prediction_paths}
    if output_path in input_paths or manifest_path in input_paths:
        parser.error("output/manifest must not overwrite an input")
    if output_path == manifest_path:
        parser.error("output and manifest must be different paths")
    if len(args.expect_prediction_sha256) != len(prediction_paths):
        parser.error("provide one --expect-prediction-sha256 for every --prediction")

    try:
        packet, packet_hash = _read_json_input(
            packet_path,
            expected_sha256=args.expect_packet_sha256,
        )
        prediction_payloads: list[object] = []
        prediction_hashes: list[str] = []
        for index, path in enumerate(prediction_paths):
            payload, payload_hash = _read_json_input(
                path,
                expected_sha256=args.expect_prediction_sha256[index],
            )
            prediction_payloads.append(payload)
            prediction_hashes.append(payload_hash)
        result = normalize_predictions(packet, prediction_payloads)
        manifest = write_normalized_outputs(
            output_path,
            manifest_path,
            result,
            packet_path=packet_path,
            packet_hash=packet_hash,
            prediction_paths=prediction_paths,
            prediction_hashes=prediction_hashes,
        )
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError, AssertionError) as exc:
        parser.error(str(exc))

    print(
        json.dumps(
            {
                "output": str(output_path),
                "manifest": str(manifest_path),
                "output_sha256": manifest["output"]["sha256"],
                "audit": manifest["audit"],
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

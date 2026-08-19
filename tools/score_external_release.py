#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Merge sealed external predictions and apply the strict release scorer.

Run this only after every predictor has finished.  Prediction workers receive
only ``release-packets.json``; this scorer is the first stage that opens the
physically separate gold and validation files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from latexstruct.accuracy import (  # noqa: E402
    passes_release_gate,
    release_policy,
    score_units,
)


DEFAULT_RESULTS = REPO_ROOT.parent / "work" / "external-results"
PREDICTION_PARTS = (
    "release-predictions-D01-D02.json",
    "release-predictions-D03-D04.json",
    "release-predictions-D05-D06.json",
)
GATE_MANIFEST_SCHEMA = "latexstruct-external-safety-gate-manifest-v1"
V3_VALIDATION_SCHEMA = "latexstruct-external-release-fixture-v3-validation"
V3_DOCUMENT_CHECKS_SCHEMA = (
    "latexstruct-external-release-fixture-v3-document-checks"
)
V3_DOCUMENT_CHECKS_FILE = "document-checks.json"
LEGACY_ARRAY_DOCUMENT_CHECK_SCHEMAS = frozenset({
    "latexstruct-external-release-fixture-v2-validation",
})


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def _json_sha256(value: object) -> str:
    return hashlib.sha256(_json_bytes(value)).hexdigest()


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _gate_manifest_path(prediction_path: Path) -> Path:
    return prediction_path.with_name(f"{prediction_path.stem}.manifest.json")


def _load_gate_manifest(prediction_path: Path, predictions: list,
                        packet_hash: str) -> dict:
    gated = [
        isinstance(item, dict) and isinstance(item.get("_safety_gate"), dict)
        for item in predictions
    ]
    if not any(gated):
        raise ValueError(
            f"ungated prediction array is not release evidence: {prediction_path.name}"
        )
    if not all(gated):
        raise ValueError(f"mixed gated and ungated records in {prediction_path.name}")
    manifest_path = _gate_manifest_path(prediction_path)
    manifest = _load(manifest_path)
    if not isinstance(manifest, dict) or manifest.get("schema") != GATE_MANIFEST_SCHEMA:
        raise ValueError(f"invalid safety-gate manifest: {manifest_path.name}")
    output = manifest.get("output")
    packet = manifest.get("packet")
    audit = manifest.get("audit")
    if not isinstance(output, dict) or not isinstance(packet, dict) or not isinstance(audit, dict):
        raise ValueError(f"incomplete safety-gate manifest: {manifest_path.name}")
    if output.get("name") != prediction_path.name:
        raise ValueError("safety-gate manifest output name mismatch")
    if output.get("sha256") != _sha256(prediction_path):
        raise ValueError("safety-gate output hash mismatch")
    if output.get("unit_count") != len(predictions):
        raise ValueError("safety-gate output unit count mismatch")
    if packet.get("sha256") != packet_hash:
        raise ValueError("safety-gate packet hash mismatch")

    missing = audit.get("missing_ids")
    unknown = audit.get("unknown_ids")
    duplicates = audit.get("duplicate_record_count")
    invalid = audit.get("invalid_record_count")
    raw_errors = audit.get("raw_protocol_error_count")
    if not isinstance(missing, list) or not isinstance(unknown, list):
        raise ValueError("safety-gate protocol ID lists are missing")
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value < 0
        for value in (duplicates, invalid, raw_errors)
    ):
        raise ValueError("safety-gate protocol counters are invalid")
    expected_raw_errors = len(missing) + len(unknown) + duplicates + invalid
    if raw_errors != expected_raw_errors:
        raise ValueError("safety-gate raw protocol count is inconsistent")

    verification = audit.get("document_verification")
    if not isinstance(verification, list):
        raise ValueError("safety-gate document verification is missing")
    seen = set()
    for item in verification:
        document = item.get("document") if isinstance(item, dict) else None
        if not isinstance(document, str) or not document or document in seen:
            raise ValueError("safety-gate document verification IDs are invalid")
        seen.add(document)
        if (
            isinstance(item.get("unit_count"), bool)
            or not isinstance(item.get("unit_count"), int)
            or item["unit_count"] <= 0
        ):
            raise ValueError("safety-gate document unit count is invalid")
        for key in (
            "content_preserved",
            "resources_preserved",
            "syntax_balanced",
            "environments_supported",
        ):
            if not isinstance(item.get(key), bool):
                raise ValueError(f"safety-gate document field {key!r} is invalid")
    manifest["_path"] = str(manifest_path)
    return manifest


def _validate_fixture_binding(validation: object, *, packets_path: Path,
                              gold_path: Path, packet_units: list,
                              gold_units: list) -> None:
    if not isinstance(validation, dict):
        raise ValueError("release fixture validation must be an object")
    schema = validation.get("schema")
    if not isinstance(schema, str) or "validation" not in schema:
        raise ValueError("release fixture validation schema is missing or unsupported")
    fixture_hashes = validation.get("fixture_hashes")
    if not isinstance(fixture_hashes, dict):
        raise ValueError("release fixture validation hashes are missing")
    expected_hashes = {
        "packets_sha256": _sha256(packets_path),
        "gold_sha256": _sha256(gold_path),
    }
    for key, expected in expected_hashes.items():
        if fixture_hashes.get(key) != expected:
            raise ValueError(f"release fixture validation {key} hash mismatch")

    packet_ids = [
        item.get("id") if isinstance(item, dict) else None
        for item in packet_units
    ]
    gold_ids = [
        item.get("id") if isinstance(item, dict) else None
        for item in gold_units
    ]
    if (
        any(not isinstance(unit_id, str) or not unit_id for unit_id in packet_ids)
        or any(not isinstance(unit_id, str) or not unit_id for unit_id in gold_ids)
        or len(set(packet_ids)) != len(packet_ids)
        or len(set(gold_ids)) != len(gold_ids)
        or set(packet_ids) != set(gold_ids)
    ):
        raise ValueError("release packet/gold IDs are invalid or do not match")
    packet_ids_sha256 = _json_sha256(packet_ids)
    gold_ids_sha256 = _json_sha256(gold_ids)
    if (
        fixture_hashes.get("packet_ids_sha256") != packet_ids_sha256
        or fixture_hashes.get("gold_ids_sha256") != gold_ids_sha256
    ):
        raise ValueError("release fixture validation ordered ID hash mismatch")
    id_binding = validation.get("id_binding")
    if not isinstance(id_binding, dict) or (
        id_binding.get("packet_ids_sha256") != packet_ids_sha256
        or id_binding.get("gold_ids_sha256") != gold_ids_sha256
        or id_binding.get("ordered_ids_match") is not True
        or id_binding.get("unique_id_count") != len(packet_ids)
    ):
        raise ValueError("release fixture validation ID binding is invalid")
    unit_count = validation.get("unit_count")
    if unit_count is not None and unit_count != len(packet_units):
        raise ValueError("release fixture validation unit count mismatch")


def _validate_document_evidence(item: dict, document: str) -> None:
    evidence = item.get("evidence")
    if not isinstance(evidence, dict) or not evidence:
        raise ValueError(
            f"fixture document_checks evidence is missing for {document!r}"
        )
    if item.get("evidence_sha256") != _json_sha256(evidence):
        raise ValueError(
            f"fixture document_checks evidence hash mismatch for {document!r}"
        )


def _validate_document_checks_binding(
    validation: dict,
    *,
    results_dir: Path,
    frozen_checks: list,
) -> None:
    """Validate the schema-specific frozen document-check evidence chain."""
    schema = validation.get("schema")
    fixture_hashes = validation.get("fixture_hashes")
    if not isinstance(fixture_hashes, dict):
        raise ValueError("release fixture validation hashes are missing")
    array_sha256 = _json_sha256(frozen_checks)

    if schema == V3_VALIDATION_SCHEMA:
        payload_sha256 = fixture_hashes.get("document_checks_sha256")
        bound_array_sha256 = fixture_hashes.get(
            "document_checks_array_sha256"
        )
        if not isinstance(payload_sha256, str) or not payload_sha256:
            raise ValueError(
                "v3 fixture document_checks payload hash binding is missing"
            )
        if not isinstance(bound_array_sha256, str) or not bound_array_sha256:
            raise ValueError(
                "v3 fixture document_checks array hash binding is missing"
            )
        if bound_array_sha256 != array_sha256:
            raise ValueError("v3 fixture document_checks array hash mismatch")

        expected_payload = {
            "schema": V3_DOCUMENT_CHECKS_SCHEMA,
            "generation": "v3",
            "unit_count": validation.get("unit_count"),
            "document_checks": frozen_checks,
        }
        expected_payload_sha256 = _json_sha256(expected_payload)
        if payload_sha256 != expected_payload_sha256:
            raise ValueError("v3 fixture document_checks payload hash mismatch")

        expected_artifact = {
            "schema": V3_DOCUMENT_CHECKS_SCHEMA,
            "sha256": payload_sha256,
            "array_sha256": array_sha256,
            "count": len(frozen_checks),
            "all_passed": True,
        }
        if validation.get("document_checks_artifact") != expected_artifact:
            raise ValueError(
                "v3 fixture document_checks artifact binding is invalid"
            )

        payload_path = results_dir / V3_DOCUMENT_CHECKS_FILE
        payload = _load(payload_path)
        if payload != expected_payload:
            raise ValueError(
                "v3 fixture document_checks payload file does not match validation"
            )
        if _sha256(payload_path) != payload_sha256:
            raise ValueError("v3 fixture document_checks payload file hash mismatch")
        return

    if schema in LEGACY_ARRAY_DOCUMENT_CHECK_SCHEMAS:
        if fixture_hashes.get("document_checks_sha256") != array_sha256:
            raise ValueError("legacy fixture document_checks array hash mismatch")
        return

    raise ValueError(
        "release fixture document_checks binding schema is unsupported"
    )


def score_release(results_dir: Path, prediction_paths: list[Path]) -> dict:
    packets_path = results_dir / "release-packets.json"
    gold_path = results_dir / "release-gold.json"
    validation_path = results_dir / "release-validation.json"
    packets = _load(packets_path)
    gold_payload = _load(gold_path)
    validation = _load(validation_path)
    if not isinstance(validation, dict) or validation.get("passed") is not True:
        raise ValueError("release fixture validation did not pass")

    packet_units = packets.get("units")
    gold_units = gold_payload.get("units")
    if not isinstance(packet_units, list) or not isinstance(gold_units, list):
        raise ValueError("release packet/gold units must be arrays")
    _validate_fixture_binding(
        validation,
        packets_path=packets_path,
        gold_path=gold_path,
        packet_units=packet_units,
        gold_units=gold_units,
    )

    packet_hash = _sha256(packets_path)
    predictions: list[dict] = []
    gate_manifests = []
    for path in prediction_paths:
        value = _load(path)
        if not isinstance(value, list):
            raise ValueError(f"prediction part is not an array: {path}")
        manifest = _load_gate_manifest(path, value, packet_hash)
        gate_manifests.append(manifest)
        predictions.extend(value)

    document_ids = sorted(
        {
            str(unit.get("document_id"))
            for unit in packet_units
            if isinstance(unit, dict)
        }
    )
    frozen_checks = validation.get("document_checks")
    if not isinstance(frozen_checks, list):
        raise ValueError(
            "fixture validation must contain independently generated document_checks"
        )
    _validate_document_checks_binding(
        validation,
        results_dir=results_dir,
        frozen_checks=frozen_checks,
    )
    frozen_by_document = {}
    for item in frozen_checks:
        document = item.get("document") if isinstance(item, dict) else None
        if not isinstance(document, str) or not document or document in frozen_by_document:
            raise ValueError("fixture document_checks contain invalid/duplicate documents")
        _validate_document_evidence(item, document)
        frozen_by_document[document] = dict(item)
    if set(frozen_by_document) != set(document_ids):
        raise ValueError("fixture document_checks do not exactly cover packet documents")

    gate_by_document = {}
    gate_protocol_errors = 0
    for manifest in gate_manifests:
        audit = manifest["audit"]
        gate_protocol_errors += audit["raw_protocol_error_count"]
        for item in audit["document_verification"]:
            document = item["document"]
            if document in gate_by_document:
                raise ValueError("multiple safety manifests cover the same document")
            gate_by_document[document] = item
    if set(gate_by_document) != set(document_ids):
        raise ValueError("safety-gate verification does not exactly cover packet documents")

    document_checks = []
    for document_id in document_ids:
        item = dict(frozen_by_document[document_id])
        gate = gate_by_document.get(document_id)
        if gate is not None:
            item["content_preserved"] = bool(
                item.get("content_preserved") and gate["content_preserved"]
            )
            item["resources_complete"] = bool(
                item.get("resources_complete") and gate["resources_preserved"]
            )
            item["environments_declared"] = bool(
                item.get("environments_declared")
                and gate["environments_supported"]
            )
            if not gate["syntax_balanced"]:
                item["compile_status"] = "failed"
            item["safety_gate_verification"] = dict(gate)
        document_checks.append(item)
    report = score_units(gold_units, predictions, document_checks)
    report["upstream_protocol_errors"] = gate_protocol_errors
    report["response_protocol_errors"] += gate_protocol_errors
    report["protocol_errors"] += gate_protocol_errors
    return {
        "schema": "latexstruct-external-release-score-v2",
        "release_policy": release_policy(),
        "fixture_hashes": {
            "packets_sha256": packet_hash,
            "gold_sha256": _sha256(gold_path),
            "validation_sha256": _sha256(validation_path),
        },
        "prediction_parts": [
            {"path": path.name, "sha256": _sha256(path)}
            for path in prediction_paths
        ],
        "safety_gate_manifests": [
            {
                "path": Path(item["_path"]).name,
                "sha256": _sha256(Path(item["_path"])),
                "raw_protocol_error_count": item["audit"]["raw_protocol_error_count"],
            }
            for item in gate_manifests
        ],
        "document_checks": document_checks,
        "score": report,
        "passes_release_gate": passes_release_gate(report),
        "predictions": predictions,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-dir", type=Path, default=DEFAULT_RESULTS)
    parser.add_argument("--prediction", type=Path, action="append", default=[])
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    results_dir = args.results_dir.resolve()
    prediction_paths = (
        [path.resolve() for path in args.prediction]
        if args.prediction
        else [results_dir / name for name in PREDICTION_PARTS]
    )
    output = (
        args.output.resolve()
        if args.output
        else results_dir / "release-score.json"
    )
    try:
        result = score_release(results_dir, prediction_paths)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    _write_json(output, result)
    print(json.dumps({
        "output": str(output),
        "passes_release_gate": result["passes_release_gate"],
        "score": result["score"],
    }, ensure_ascii=False, indent=2))
    return 0 if result["passes_release_gate"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

# -*- coding: utf-8 -*-
"""Tests for the explicit Codex blind protocol-shape adapter."""

import hashlib
import json

import pytest

from tools.apply_external_safety_gate import apply_safety_gate
from tools.normalize_codex_blind_predictions import (
    DEFAULT_CONFIDENCE,
    MANIFEST_SCHEMA,
    NORMALIZATION_REASON,
    OUTPUT_ARRAY_SCHEMA,
    _read_json_input,
    main,
    normalize_predictions,
)


ALLOWED_ENVS = [
    "theorem",
    "lemma",
    "definition",
    "proposition",
    "corollary",
    "remark",
    "example",
    "proof",
]


def _unit(unit_id, block_ids, focus):
    return {
        "id": unit_id,
        "document_id": "D01",
        "focus_anchor": focus,
        "blocks": [{"id": block_id, "text": f"block {block_id}"} for block_id in block_ids],
    }


def _packet(*units):
    return {
        "schema": "latexstruct-external-test-packets-v1",
        "instructions": {"allowed_environments": ALLOWED_ENVS},
        "units": list(units),
    }


def _record(
    unit_id,
    action="preserve",
    env="",
    start=0,
    end=0,
    **extra,
):
    return {
        "id": unit_id,
        "action": action,
        "env": env,
        "start_block": start,
        "end_block": end,
        **extra,
    }


def test_normalizes_only_legacy_shape_and_emits_packet_order_audit():
    packet = _packet(
        _unit("u-preserve", [3], 3),
        _unit("u-wrap", [7, 8], 7),
        _unit("u-manual", [4], 4),
    )
    preserve = _record("u-preserve", start=None, end=None)
    preserve["unit_id"] = preserve["id"]
    wrap = _record(
        "u-wrap",
        action="wrap",
        env="theorem",
        start=7,
        end=8,
        reason="Frozen source-based decision.",
        confidence=0.83,
    )
    manual = {
        "unit_id": "u-manual",
        "action": "manual",
        "env": "",
        "start_block": None,
        "end_block": None,
    }
    # Parts and records may arrive out of packet order.  The formal output is
    # always packet-ordered without altering any classification semantics.
    result = normalize_predictions(packet, [[manual], [wrap, preserve]])
    output = result["predictions"]

    assert [item["id"] for item in output] == ["u-preserve", "u-wrap", "u-manual"]
    assert output[0] == {
        "id": "u-preserve",
        "action": "preserve",
        "env": "",
        "start_block": 3,
        "end_block": 3,
        "reason": NORMALIZATION_REASON,
        "confidence": DEFAULT_CONFIDENCE,
    }
    assert output[1] == wrap
    assert output[2]["start_block"] == output[2]["end_block"] == 4
    assert output[2]["reason"] == NORMALIZATION_REASON
    assert output[2]["confidence"] == DEFAULT_CONFIDENCE
    assert "unit_id" not in output[0] and "unit_id" not in output[2]
    assert result["audit"] == {
        "packet_units": 3,
        "source_prediction_records": 3,
        "output_units": 3,
        "legacy_id_conversion_count": 1,
        "matching_dual_id_count": 1,
        "derived_boundary_field_count": 4,
        "derived_boundary_record_count": 2,
        "reason_addition_count": 2,
        "confidence_addition_count": 2,
        "automatic_record_count": 1,
        "automatic_boundary_repair_count": 0,
        "semantic_change_count": 0,
        "action_counts": {"manual": 1, "preserve": 1, "wrap": 1},
    }


def test_default_zero_confidence_from_normalizer_can_never_auto_apply():
    unit = _unit("u-wrap", [0, 1, 2], 0)
    unit["blocks"] = [
        {"id": 0, "text": "Theorem."},
        {"id": 1, "text": "A complete statement."},
        {"id": 2, "text": "Lemma. Next."},
    ]
    packet = _packet(unit)
    raw = _record(
        "u-wrap",
        action="wrap",
        env="theorem",
        start=0,
        end=1,
    )

    normalized = normalize_predictions(packet, [[raw]])
    assert normalized["predictions"][0]["confidence"] == DEFAULT_CONFIDENCE
    assert normalized["audit"]["confidence_addition_count"] == 1

    gated = apply_safety_gate(packet, [normalized["predictions"]])["predictions"][0]
    assert gated["action"] == "manual"
    assert gated["_safety_gate"]["status"] == "manual-low-confidence"
    assert "below the production threshold" in gated["reason"]


def test_cli_requires_and_records_every_frozen_input_hash(tmp_path):
    packet_path = tmp_path / "release-packets.json"
    part_a = tmp_path / "initial-part-a.json"
    part_b = tmp_path / "initial-part-b.json"
    output_path = tmp_path / "normalized.json"
    packet = _packet(_unit("u1", [2], 2), _unit("u2", [5, 6], 5))
    packet_path.write_text(json.dumps(packet), encoding="utf-8")
    part_a.write_text(
        json.dumps(
            [
                {
                    "unit_id": "u1",
                    "action": "preserve",
                    "env": "",
                    "start_block": None,
                    "end_block": None,
                }
            ]
        ),
        encoding="utf-8",
    )
    part_b.write_text(
        json.dumps(
            [
                _record(
                    "u2",
                    action="wrap",
                    env="lemma",
                    start=5,
                    end=6,
                )
            ]
        ),
        encoding="utf-8",
    )
    packet_hash = hashlib.sha256(packet_path.read_bytes()).hexdigest()
    part_hashes = [
        hashlib.sha256(part_a.read_bytes()).hexdigest(),
        hashlib.sha256(part_b.read_bytes()).hexdigest(),
    ]

    assert (
        main(
            [
                "--packets",
                str(packet_path),
                "--prediction",
                str(part_a),
                "--prediction",
                str(part_b),
                "--output",
                str(output_path),
                "--expect-packet-sha256",
                packet_hash,
                "--expect-prediction-sha256",
                part_hashes[0],
                "--expect-prediction-sha256",
                part_hashes[1],
            ]
        )
        == 0
    )

    output = json.loads(output_path.read_text(encoding="utf-8"))
    manifest_path = tmp_path / "normalized.manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert [item["id"] for item in output] == ["u1", "u2"]
    assert manifest["schema"] == MANIFEST_SCHEMA
    assert manifest["output"]["schema"] == OUTPUT_ARRAY_SCHEMA
    assert manifest["output"]["sha256"] == hashlib.sha256(output_path.read_bytes()).hexdigest()
    assert manifest["packet"]["sha256"] == packet_hash
    assert [item["sha256"] for item in manifest["prediction_inputs"]] == part_hashes
    assert [item["record_count"] for item in manifest["prediction_inputs"]] == [1, 1]
    assert manifest["audit"]["semantic_change_count"] == 0
    assert manifest["audit"]["automatic_boundary_repair_count"] == 0


def test_cli_hash_mismatch_fails_before_writing_output(tmp_path):
    packet_path = tmp_path / "release-packets.json"
    part_path = tmp_path / "initial-part.json"
    output_path = tmp_path / "normalized.json"
    packet_path.write_text(
        json.dumps(_packet(_unit("u1", [0], 0))),
        encoding="utf-8",
    )
    part_path.write_text(json.dumps([_record("u1")]), encoding="utf-8")
    part_hash = hashlib.sha256(part_path.read_bytes()).hexdigest()

    with pytest.raises(SystemExit):
        main(
            [
                "--packets",
                str(packet_path),
                "--prediction",
                str(part_path),
                "--output",
                str(output_path),
                "--expect-packet-sha256",
                "0" * 64,
                "--expect-prediction-sha256",
                part_hash,
            ]
        )

    assert not output_path.exists()
    assert not (tmp_path / "normalized.manifest.json").exists()


@pytest.mark.parametrize(
    ("payloads", "match"),
    [
        (
            [
                [
                    {
                        "id": "u1",
                        "unit_id": "different",
                        "action": "preserve",
                        "env": "",
                        "start_block": 0,
                        "end_block": 0,
                    }
                ]
            ],
            "conflicting id/unit_id",
        ),
        ([[_record("unknown")]], "unknown packet id"),
        ([[_record("u1")], [_record("u1")]], "duplicate prediction id"),
        ([[_record("u1")]], "missing 1 packet prediction IDs"),
    ],
)
def test_rejects_conflicting_unknown_duplicate_or_missing_ids(payloads, match):
    packet = _packet(_unit("u1", [0], 0), _unit("u2", [0], 0))

    with pytest.raises(ValueError, match=match):
        normalize_predictions(packet, payloads)


@pytest.mark.parametrize(
    ("record", "match"),
    [
        (
            _record("u1", action="wrap", env="theorem", start=None, end=1),
            "automatic-boundary repair",
        ),
        (
            _record("u1", action="move-boundary", env="theorem", start=0, end=None),
            "automatic-boundary repair",
        ),
        (
            _record("u1", action="wrap", env="", start=0, end=1),
            "invalid or packet-disallowed env",
        ),
        (
            _record("u1", action="wrap", env="custom", start=0, end=1),
            "invalid or packet-disallowed env",
        ),
        (
            _record("u1", action="wrap", env="theorem", start=1, end=1),
            "start_block must equal focus_anchor",
        ),
        (
            _record("u1", action="wrap", env="theorem", start=0, end=99),
            "not a packet block",
        ),
        (
            _record("u1", action="preserve", start=0, end=1),
            "preserve end_block must equal focus_anchor",
        ),
        (
            _record("u1", action="manual", env="theorem"),
            "manual must use an empty env",
        ),
        (_record("u1", action="guess"), "invalid action"),
    ],
)
def test_rejects_invalid_semantics_and_never_repairs_automatic_boundaries(
    record,
    match,
):
    packet = _packet(_unit("u1", [0, 1], 0))

    with pytest.raises(ValueError, match=match):
        normalize_predictions(packet, [[record]])


@pytest.mark.parametrize(
    "name",
    [
        "release-gold.json",
        "release-validation.json",
        "release-score.json",
        "source-corpus.json",
        "fixture-builder.json",
    ],
)
def test_forbidden_inputs_are_rejected_before_file_access(tmp_path, name):
    with pytest.raises(ValueError, match="refusing forbidden"):
        _read_json_input(tmp_path / name, expected_sha256="0" * 64)


def test_rejects_unknown_fields_and_invalid_metadata():
    packet = _packet(_unit("u1", [0], 0))
    unknown = _record("u1", invented="value")
    with pytest.raises(ValueError, match="unsupported fields"):
        normalize_predictions(packet, [[unknown]])

    bad_confidence = _record("u1", confidence=1.01)
    with pytest.raises(ValueError, match="confidence"):
        normalize_predictions(packet, [[bad_confidence]])

    bad_reason = _record("u1", reason=" padded ")
    with pytest.raises(ValueError, match="reason"):
        normalize_predictions(packet, [[bad_reason]])

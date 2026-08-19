# -*- coding: utf-8 -*-
"""Production-safety gate tests for blind external prediction packets."""

import hashlib
import json

import pytest

from latexstruct.core.ai import AUTO_APPLY_CONFIDENCE
from tools.apply_external_safety_gate import (
    MANIFEST_SCHEMA,
    OUTPUT_ARRAY_SCHEMA,
    _read_json_input,
    apply_safety_gate,
    main,
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


def _unit(unit_id, blocks, focus=0):
    return {
        "id": unit_id,
        "document_id": "D01",
        "document_region": "front",
        "focus_anchor": focus,
        "blocks": [
            {"id": block_id, "text": text}
            for block_id, text in enumerate(blocks)
        ],
    }


def _packet(*units):
    return {
        "schema": "latexstruct-external-test-packets-v1",
        "instructions": {"allowed_environments": ALLOWED_ENVS},
        "units": list(units),
    }


def _prediction(unit_id, action, env="", start=0, end=0, confidence=0.9):
    return {
        "id": unit_id,
        "action": action,
        "env": env,
        "start_block": start,
        "end_block": end,
        "reason": "blind model answer",
        "confidence": confidence,
    }


def _one_result(packet, prediction_payloads):
    return apply_safety_gate(packet, prediction_payloads)["predictions"][0]


def test_scanner_negative_focus_forces_preserve_even_for_model_wrap():
    packet = _packet(_unit("u1", ["Ordinary narrative, not a bare structure."]))
    result = _one_result(
        packet,
        [[_prediction("u1", "wrap", "theorem")]],
    )

    assert result["action"] == "preserve"
    assert result["env"] == ""
    assert result["start_block"] == result["end_block"] == 0
    assert result["_safety_gate"]["status"] == "forced-preserve-no-focus-candidate"


def test_malformed_confidence_becomes_manual_instead_of_auto_applying():
    packet = _packet(_unit("u1", ["Theorem.", "A statement.", "Lemma. Next."]))
    prediction = _prediction("u1", "wrap", "theorem", start=0, end=1)
    prediction["confidence"] = {"not": "numeric"}

    result = _one_result(packet, [[prediction]])

    assert result["action"] == "manual"
    assert "confidence" not in result
    assert result["_safety_gate"]["status"] == "manual-invalid-confidence-type"
    assert "finite non-boolean number" in result["reason"]


@pytest.mark.parametrize(
    ("confidence", "status", "reason_part"),
    [
        (None, "manual-missing-confidence", "requires explicit confidence"),
        (True, "manual-invalid-confidence-type", "non-boolean"),
        (float("nan"), "manual-nonfinite-confidence", "must be finite"),
        (float("inf"), "manual-nonfinite-confidence", "must be finite"),
        (float("-inf"), "manual-nonfinite-confidence", "must be finite"),
    ],
)
def test_missing_bool_and_nonfinite_confidence_never_auto_apply(
    confidence, status, reason_part
):
    packet = _packet(_unit("u1", ["Theorem.", "A statement.", "Lemma. Next."]))
    prediction = _prediction("u1", "wrap", "theorem", start=0, end=1)
    if confidence is None:
        prediction.pop("confidence")
    else:
        prediction["confidence"] = confidence

    result = _one_result(packet, [[prediction]])

    assert result["action"] == "manual"
    assert result["_safety_gate"]["status"] == status
    assert reason_part in result["reason"]


def test_exact_production_confidence_threshold_is_accepted():
    packet = _packet(_unit("u1", ["Theorem.", "A statement.", "Lemma. Next."]))
    prediction = _prediction(
        "u1",
        "wrap",
        "theorem",
        start=0,
        end=1,
        confidence=AUTO_APPLY_CONFIDENCE,
    )

    result = _one_result(packet, [[prediction]])

    assert result["action"] == "wrap"
    assert result["confidence"] == AUTO_APPLY_CONFIDENCE
    assert result["_safety_gate"]["status"] == "accepted-wrap"


def test_confidence_below_production_threshold_becomes_manual():
    packet = _packet(_unit("u1", ["Theorem.", "A statement.", "Lemma. Next."]))
    below_threshold = AUTO_APPLY_CONFIDENCE - 0.01
    prediction = _prediction(
        "u1",
        "wrap",
        "theorem",
        start=0,
        end=1,
        confidence=below_threshold,
    )

    result = _one_result(packet, [[prediction]])

    assert result["action"] == "manual"
    assert result["confidence"] == below_threshold
    assert result["_safety_gate"]["status"] == "manual-low-confidence"
    assert f"threshold {AUTO_APPLY_CONFIDENCE:g}" in result["reason"]


@pytest.mark.parametrize("raw_action", ["preserve", "manual"])
def test_scanner_positive_preserve_or_manual_is_production_manual(raw_action):
    packet = _packet(_unit("u1", ["Theorem.", "A statement.", "Lemma. Next."]))
    result = _one_result(packet, [[_prediction("u1", raw_action)]])

    assert result["action"] == "manual"
    assert result["env"] == ""
    assert result["start_block"] == result["end_block"] == 0


def test_valid_wrap_maps_block_boundary_through_production_legalizer():
    packet = _packet(_unit("u1", ["Theorem.", "A complete statement.", "Lemma. Next."]))
    result = _one_result(
        packet,
        [[_prediction("u1", "wrap", "theorem", start=0, end=1)]],
    )

    assert result["action"] == "wrap"
    assert result["env"] == "theorem"
    assert result["start_block"] == 0
    assert result["end_block"] == 1
    assert result["_safety_gate"]["status"] == "accepted-wrap"
    assert result["_safety_gate"]["source_line_span"] == [1, 3]


def test_valid_scope_fix_maps_only_the_scanner_proven_boundary():
    packet = _packet(_unit(
        "u1",
        [
            "\\begin{theorem}\nTheorem.\n\\end{theorem}",
            "The body was left outside the environment.",
        ],
    ))
    result = _one_result(
        packet,
        [[_prediction("u1", "move-boundary", "theorem", start=0, end=1)]],
    )

    assert result["action"] == "move-boundary"
    assert result["env"] == "theorem"
    assert result["start_block"] == 0
    assert result["end_block"] == 1
    assert result["_safety_gate"]["status"] == "accepted-move-boundary"


def test_external_structured_environment_is_available_to_the_gate():
    unit = _unit(
        "u1",
        [
            "Theorem. First part.",
            "Second part.",
            "\\begin{myresult*}\nA separate result.\n\\end{myresult*}",
        ],
    )
    unit["known_structured_environments"] = ["myresult"]
    result = _one_result(
        _packet(unit),
        [[_prediction("u1", "wrap", "theorem", start=0, end=1)]],
    )

    assert result["action"] == "wrap"
    assert result["end_block"] == 1
    assert result["_safety_gate"]["verification"]["content_preserved"] is True


def test_complete_content_inside_existing_proof_is_scanner_negative_preserve():
    packet = _packet(
        _unit("u1", ["\\begin{proof}\nExercise.\n\\end{proof}"])
    )
    result = _one_result(packet, [[_prediction("u1", "preserve")]])

    assert result["action"] == "preserve"
    assert result["_safety_gate"]["status"] == "forced-preserve-no-focus-candidate"


def test_custom_ref_proof_without_hard_end_reaches_manual_gate():
    packet = _packet(
        _unit(
            "u1",
            [
                "Proof of \\thmref{thm:localization}:\n"
                "The argument continues without a machine-verifiable ending."
            ],
        )
    )
    result = _one_result(packet, [[_prediction("u1", "manual")]])

    assert result["action"] == "manual"
    assert result["_safety_gate"]["candidate_count"] == 1
    assert result["_safety_gate"]["status"] == "manual-fail-closed"


def test_named_result_proof_with_qedhere_is_accepted_through_math_closer():
    packet = _packet(
        _unit(
            "u1",
            [
                "Proof of Green's theorem for $U$ of type III.\n"
                "The computation gives\n"
                "\\begin{equation*}\n"
                "a=b. \\qedhere\n"
                "\\end{equation*}"
            ],
        )
    )
    result = _one_result(
        packet,
        [[_prediction("u1", "wrap", "proof", start=0, end=0)]],
    )

    assert result["action"] == "wrap"
    assert result["env"] == "proof"
    assert result["end_block"] == 0
    assert result["_safety_gate"]["status"] == "accepted-wrap"


def test_multiline_named_theorem_reaches_manual_gate():
    packet = _packet(
        _unit(
            "u1",
            [
                "Theorem (Fubini version A%\n"
                "\\footnote{Named after the Italian mathematician\n"
                "\\href{https://example.test}{Guido Fubini}\n"
                "(1879--1943).}):\n"
                "\\label{mv:fubini} Let $R$ be a closed rectangle.\n\n"
                "A second atomic paragraph has no structural successor."
            ],
        )
    )
    result = _one_result(packet, [[_prediction("u1", "manual")]])

    assert result["action"] == "manual"
    assert result["_safety_gate"]["candidate_count"] == 1
    assert result["_safety_gate"]["status"] == "manual-fail-closed"


def test_proof_legalizer_expands_to_qed_and_returns_exact_later_block():
    packet = _packet(
        _unit(
            "u1",
            ["Proof.", "First step.", "Final step. \\qed", "Later discussion."],
        )
    )
    result = _one_result(
        packet,
        [[_prediction("u1", "wrap", "proof", start=0, end=1)]],
    )

    assert result["action"] == "wrap"
    assert result["env"] == "proof"
    assert result["end_block"] == 2
    assert result["_safety_gate"]["source_line_span"] == [1, 5]


@pytest.mark.parametrize(
    ("blocks", "prediction", "reason_part"),
    [
        (
            ["Theorem.", "A statement.", "Lemma. Next."],
            _prediction("u1", "wrap", "lemma", start=0, end=1),
            "conflicts with scanner hint",
        ),
        (
            ["Theorem.", "A statement.", "Lemma. Next."],
            _prediction("u1", "wrap", "theorem", start=1, end=1),
            "not the focus anchor",
        ),
        (
            ["Theorem.", "First part.", "Unstructured trailing discussion."],
            _prediction("u1", "wrap", "theorem", start=0, end=1),
            "完整原子边界",
        ),
    ],
)
def test_illegal_or_unprovable_wrap_fails_closed(blocks, prediction, reason_part):
    result = _one_result(_packet(_unit("u1", blocks)), [[prediction]])

    assert result["action"] == "manual"
    assert result["env"] == ""
    assert result["start_block"] == result["end_block"] == 0
    assert reason_part in result["reason"]


def test_missing_and_duplicate_candidate_answers_are_manual_but_output_is_complete():
    units = (
        _unit("candidate", ["Theorem.", "A statement.", "Lemma. Next."]),
        _unit("narrative", ["Ordinary narrative."]),
    )
    duplicated = _prediction("candidate", "wrap", "theorem", start=0, end=1)
    envelope = apply_safety_gate(
        _packet(*units),
        [[duplicated], [dict(duplicated)]],
    )

    assert [item["id"] for item in envelope["predictions"]] == ["candidate", "narrative"]
    assert [item["action"] for item in envelope["predictions"]] == ["manual", "preserve"]
    assert envelope["audit"]["duplicate_ids"] == ["candidate"]
    assert envelope["audit"]["missing_ids"] == ["narrative"]
    assert envelope["audit"]["duplicate_record_count"] == 1
    assert envelope["audit"]["raw_protocol_error_count"] == 2


def test_cli_writes_score_compatible_array_and_schema_hash_manifest(tmp_path):
    packet_path = tmp_path / "release-packets.json"
    first_path = tmp_path / "predictions-part-1.json"
    second_path = tmp_path / "predictions-part-2.json"
    output_path = tmp_path / "production-predictions.json"
    packet = _packet(
        _unit("u1", ["Theorem.", "A statement.", "Lemma. Next."]),
        _unit("u2", ["Ordinary narrative."]),
    )
    packet_path.write_text(json.dumps(packet), encoding="utf-8")
    first_path.write_text(
        json.dumps([_prediction("u1", "wrap", "theorem", start=0, end=1)]),
        encoding="utf-8",
    )
    second_path.write_text(
        json.dumps([_prediction("u2", "wrap", "theorem")]),
        encoding="utf-8",
    )
    expected_packet_hash = hashlib.sha256(packet_path.read_bytes()).hexdigest()
    expected_prediction_hashes = [
        hashlib.sha256(first_path.read_bytes()).hexdigest(),
        hashlib.sha256(second_path.read_bytes()).hexdigest(),
    ]

    assert main([
        "--packets", str(packet_path),
        "--prediction", str(first_path),
        "--prediction", str(second_path),
        "--output", str(output_path),
        "--expect-packet-sha256", expected_packet_hash,
        "--expect-prediction-sha256", expected_prediction_hashes[0],
        "--expect-prediction-sha256", expected_prediction_hashes[1],
    ]) == 0

    output = json.loads(output_path.read_text(encoding="utf-8"))
    manifest_path = tmp_path / "production-predictions.manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert isinstance(output, list)
    assert [item["action"] for item in output] == ["wrap", "preserve"]
    assert manifest["schema"] == MANIFEST_SCHEMA
    assert manifest["output"]["schema"] == OUTPUT_ARRAY_SCHEMA
    assert manifest["output"]["sha256"] == hashlib.sha256(output_path.read_bytes()).hexdigest()
    assert [item["sha256"] for item in manifest["prediction_inputs"]] == (
        expected_prediction_hashes
    )


def test_answer_bearing_path_is_rejected_before_file_access(tmp_path):
    with pytest.raises(ValueError, match="refusing to read"):
        _read_json_input(tmp_path / "release-gold.json")
    with pytest.raises(ValueError, match="refusing to read"):
        _read_json_input(tmp_path / "release-score.json")


def test_packet_schema_and_duplicate_ids_are_rejected():
    unit = _unit("same", ["Narrative."])
    bad_schema = _packet(unit)
    bad_schema["schema"] = "some-unverified-object"
    with pytest.raises(ValueError, match="unsupported packet schema"):
        apply_safety_gate(bad_schema, [[]])

    with pytest.raises(ValueError, match="duplicated"):
        apply_safety_gate(_packet(unit, dict(unit)), [[]])

    reversed_blocks = _unit("ordered", ["Narrative.", "More narrative."])
    reversed_blocks["blocks"][0]["id"] = 4
    reversed_blocks["blocks"][1]["id"] = 2
    reversed_blocks["focus_anchor"] = 4
    with pytest.raises(ValueError, match="must increase"):
        apply_safety_gate(_packet(reversed_blocks), [[]])

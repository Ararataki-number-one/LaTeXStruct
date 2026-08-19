# -*- coding: utf-8 -*-
"""Release-scorer evidence-chain regressions."""

import hashlib
import json

import pytest

from tools.score_external_release import score_release


def _write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


def _canonical_json_bytes(value):
    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def _json_sha256(value):
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _write_canonical(path, value):
    path.write_bytes(_canonical_json_bytes(value))


def _fixture(tmp_path, *, document_checks):
    packets = {
        "schema": "latexstruct-external-test-packets-v2",
        "units": [{
            "id": "u1",
            "document_id": "D01",
            "focus_anchor": 0,
            "blocks": [{"id": 0, "text": "Ordinary narrative."}],
        }],
    }
    gold = {"units": [{
        "id": "u1",
        "document": "D01",
        "action": "preserve",
        "env": "",
        "start_block": 0,
        "end_block": 0,
    }]}
    _write(tmp_path / "release-packets.json", packets)
    _write(tmp_path / "release-gold.json", gold)
    frozen_checks = None
    if document_checks is not None:
        frozen_checks = [dict(item) for item in document_checks]
        for item in frozen_checks:
            evidence = item.get("evidence")
            if isinstance(evidence, dict) and evidence:
                item["evidence_sha256"] = hashlib.sha256(
                    (json.dumps(
                        evidence, ensure_ascii=False, indent=2, sort_keys=True
                    ) + "\n").encode("utf-8")
                ).hexdigest()
    packet_ids = [item["id"] for item in packets["units"]]
    gold_ids = [item["id"] for item in gold["units"]]
    validation = {
        "schema": "latexstruct-external-release-fixture-v2-validation",
        "passed": True,
        "unit_count": 1,
        "fixture_hashes": {
            "packets_sha256": hashlib.sha256(
                (tmp_path / "release-packets.json").read_bytes()
            ).hexdigest(),
            "gold_sha256": hashlib.sha256(
                (tmp_path / "release-gold.json").read_bytes()
            ).hexdigest(),
            "packet_ids_sha256": _json_sha256(packet_ids),
            "gold_ids_sha256": _json_sha256(gold_ids),
        },
        "id_binding": {
            "packet_ids_sha256": _json_sha256(packet_ids),
            "gold_ids_sha256": _json_sha256(gold_ids),
            "ordered_ids_match": True,
            "unique_id_count": len(set(packet_ids)),
        },
    }
    if frozen_checks is not None:
        validation["document_checks"] = frozen_checks
        validation["fixture_hashes"]["document_checks_sha256"] = _json_sha256(
            frozen_checks
        )
    _write(tmp_path / "release-validation.json", validation)
    return packets


def _convert_fixture_to_v3(tmp_path):
    validation_path = tmp_path / "release-validation.json"
    validation = json.loads(validation_path.read_text(encoding="utf-8"))
    frozen_checks = validation["document_checks"]
    payload = {
        "schema": "latexstruct-external-release-fixture-v3-document-checks",
        "generation": "v3",
        "unit_count": validation["unit_count"],
        "document_checks": frozen_checks,
    }
    payload_sha256 = _json_sha256(payload)
    array_sha256 = _json_sha256(frozen_checks)
    validation.update({
        "schema": "latexstruct-external-release-fixture-v3-validation",
        "generation": "v3",
        "document_checks_artifact": {
            "schema": payload["schema"],
            "sha256": payload_sha256,
            "array_sha256": array_sha256,
            "count": len(frozen_checks),
            "all_passed": True,
        },
    })
    validation["fixture_hashes"].update({
        "document_checks_sha256": payload_sha256,
        "document_checks_array_sha256": array_sha256,
    })
    _write_canonical(tmp_path / "document-checks.json", payload)
    _write(validation_path, validation)


def _write_clean_prediction(tmp_path):
    prediction = tmp_path / "gated.json"
    _write(prediction, [{
        "id": "u1",
        "action": "preserve",
        "env": "",
        "start_block": 0,
        "end_block": 0,
        "_safety_gate": {"status": "forced-preserve-no-focus-candidate"},
    }])
    _write_clean_gate_manifest(tmp_path, prediction)
    return prediction


def _write_clean_gate_manifest(tmp_path, prediction, *, document="D01"):
    packet_path = tmp_path / "release-packets.json"
    _write(tmp_path / f"{prediction.stem}.manifest.json", {
        "schema": "latexstruct-external-safety-gate-manifest-v1",
        "packet": {
            "name": packet_path.name,
            "sha256": hashlib.sha256(packet_path.read_bytes()).hexdigest(),
        },
        "output": {
            "name": prediction.name,
            "sha256": hashlib.sha256(prediction.read_bytes()).hexdigest(),
            "unit_count": 1,
        },
        "audit": {
            "missing_ids": [],
            "unknown_ids": [],
            "duplicate_record_count": 0,
            "invalid_record_count": 0,
            "raw_protocol_error_count": 0,
            "document_verification": [{
                "document": document,
                "unit_count": 1,
                "content_preserved": True,
                "resources_preserved": True,
                "syntax_balanced": True,
                "environments_supported": True,
            }],
        },
    })


def _document_check():
    return {
        "document": "D01",
        "content_preserved": True,
        "resources_complete": True,
        "environments_declared": True,
        "compile_status": "not-required",
        "evidence": {"independent_fixture_validation": True},
    }


def test_v3_document_checks_payload_and_array_bindings_are_valid(tmp_path):
    _fixture(tmp_path, document_checks=[_document_check()])
    _convert_fixture_to_v3(tmp_path)
    prediction = _write_clean_prediction(tmp_path)

    result = score_release(tmp_path, [prediction])

    assert result["score"]["correct"] == 1
    assert result["document_checks"][0]["document"] == "D01"


def test_v3_document_checks_rejects_mismatched_validation_array(tmp_path):
    _fixture(tmp_path, document_checks=[_document_check()])
    _convert_fixture_to_v3(tmp_path)
    validation_path = tmp_path / "release-validation.json"
    validation = json.loads(validation_path.read_text(encoding="utf-8"))
    validation["document_checks"][0]["compile_status"] = "failed"
    _write(validation_path, validation)
    prediction = _write_clean_prediction(tmp_path)

    with pytest.raises(ValueError, match="array hash mismatch"):
        score_release(tmp_path, [prediction])


@pytest.mark.parametrize("mutation", ["payload-file", "payload-hash"])
def test_v3_document_checks_rejects_mismatched_payload_or_hash(
    tmp_path, mutation,
):
    _fixture(tmp_path, document_checks=[_document_check()])
    _convert_fixture_to_v3(tmp_path)
    validation_path = tmp_path / "release-validation.json"
    if mutation == "payload-file":
        payload_path = tmp_path / "document-checks.json"
        payload = json.loads(payload_path.read_text(encoding="utf-8"))
        payload["generation"] = "tampered"
        _write_canonical(payload_path, payload)
        error = "payload file does not match"
    else:
        validation = json.loads(validation_path.read_text(encoding="utf-8"))
        validation["fixture_hashes"]["document_checks_sha256"] = "0" * 64
        validation["document_checks_artifact"]["sha256"] = "0" * 64
        _write(validation_path, validation)
        error = "payload hash mismatch"
    prediction = _write_clean_prediction(tmp_path)

    with pytest.raises(ValueError, match=error):
        score_release(tmp_path, [prediction])


@pytest.mark.parametrize(
    "missing",
    ["document_checks_sha256", "document_checks_array_sha256", "artifact"],
)
def test_v3_document_checks_rejects_missing_expected_binding(
    tmp_path, missing,
):
    _fixture(tmp_path, document_checks=[_document_check()])
    _convert_fixture_to_v3(tmp_path)
    validation_path = tmp_path / "release-validation.json"
    validation = json.loads(validation_path.read_text(encoding="utf-8"))
    if missing == "artifact":
        validation.pop("document_checks_artifact")
        error = "artifact binding"
    else:
        validation["fixture_hashes"].pop(missing)
        error = "hash binding is missing"
    _write(validation_path, validation)
    prediction = _write_clean_prediction(tmp_path)

    with pytest.raises(ValueError, match=error):
        score_release(tmp_path, [prediction])


def test_legacy_v2_document_checks_array_binding_remains_supported(tmp_path):
    _fixture(tmp_path, document_checks=[_document_check()])
    prediction = _write_clean_prediction(tmp_path)

    result = score_release(tmp_path, [prediction])

    assert result["score"]["correct"] == 1


def test_legacy_binding_does_not_accept_a_v3_array_hash_as_fallback(tmp_path):
    _fixture(tmp_path, document_checks=[_document_check()])
    validation_path = tmp_path / "release-validation.json"
    validation = json.loads(validation_path.read_text(encoding="utf-8"))
    validation["fixture_hashes"]["document_checks_sha256"] = "0" * 64
    validation["fixture_hashes"]["document_checks_array_sha256"] = (
        _json_sha256(validation["document_checks"])
    )
    _write(validation_path, validation)
    prediction = _write_clean_prediction(tmp_path)

    with pytest.raises(ValueError, match="legacy.*array hash mismatch"):
        score_release(tmp_path, [prediction])


def test_scorer_refuses_to_fabricate_document_checks(tmp_path):
    _fixture(tmp_path, document_checks=None)
    prediction = tmp_path / "predictions.json"
    _write(prediction, [{
        "id": "u1", "action": "preserve", "env": "",
        "start_block": 0, "end_block": 0,
        "_safety_gate": {"status": "forced-preserve-no-focus-candidate"},
    }])
    _write_clean_gate_manifest(tmp_path, prediction)

    with pytest.raises(ValueError, match="document_checks"):
        score_release(tmp_path, [prediction])


def test_release_scorer_rejects_ungated_prediction_arrays(tmp_path):
    _fixture(tmp_path, document_checks=[{
        "document": "D01",
        "content_preserved": True,
        "resources_complete": True,
        "environments_declared": True,
        "compile_status": "not-required",
        "evidence": {"independent_fixture_validation": True},
    }])
    prediction = tmp_path / "ungated.json"
    _write(prediction, [{
        "id": "u1", "action": "preserve", "env": "",
        "start_block": 0, "end_block": 0,
    }])

    with pytest.raises(ValueError, match="safety-gate|manifest|ungated"):
        score_release(tmp_path, [prediction])


@pytest.mark.parametrize("mutation", ["fixture-hash", "missing-evidence"])
def test_release_scorer_rejects_unbound_or_unevidenced_validation(
    tmp_path, mutation,
):
    _fixture(tmp_path, document_checks=[{
        "document": "D01",
        "content_preserved": True,
        "resources_complete": True,
        "environments_declared": True,
        "compile_status": "not-required",
        "evidence": {"independent_fixture_validation": True},
    }])
    validation_path = tmp_path / "release-validation.json"
    validation = json.loads(validation_path.read_text(encoding="utf-8"))
    packet_path = tmp_path / "release-packets.json"
    gold_path = tmp_path / "release-gold.json"
    validation.update({
        "schema": "latexstruct-external-release-fixture-v2-validation",
        "fixture_hashes": {
            "packets_sha256": hashlib.sha256(packet_path.read_bytes()).hexdigest(),
            "gold_sha256": hashlib.sha256(gold_path.read_bytes()).hexdigest(),
        },
    })
    if mutation == "fixture-hash":
        validation["fixture_hashes"]["packets_sha256"] = "0" * 64
    else:
        validation["document_checks"][0].pop("evidence")
    _write(validation_path, validation)

    prediction = tmp_path / "gated.json"
    _write(prediction, [{
        "id": "u1", "action": "preserve", "env": "",
        "start_block": 0, "end_block": 0,
        "_safety_gate": {"status": "forced-preserve-no-focus-candidate"},
    }])
    _write_clean_gate_manifest(tmp_path, prediction)

    with pytest.raises(ValueError, match="validation|hash|evidence"):
        score_release(tmp_path, [prediction])


def test_gate_manifest_protocol_errors_survive_clean_output(tmp_path):
    packets = _fixture(tmp_path, document_checks=[{
        "document": "D01",
        "content_preserved": True,
        "resources_complete": True,
        "environments_declared": True,
        "compile_status": "not-required",
        "evidence": {"independent_fixture_validation": True},
    }])
    prediction = tmp_path / "gated.json"
    records = [{
        "id": "u1", "action": "preserve", "env": "",
        "start_block": 0, "end_block": 0,
        "_safety_gate": {"status": "forced-preserve-no-focus-candidate"},
    }]
    _write(prediction, records)
    packet_path = tmp_path / "release-packets.json"
    manifest = {
        "schema": "latexstruct-external-safety-gate-manifest-v1",
        "packet": {
            "name": packet_path.name,
            "sha256": hashlib.sha256(packet_path.read_bytes()).hexdigest(),
        },
        "output": {
            "name": prediction.name,
            "sha256": hashlib.sha256(prediction.read_bytes()).hexdigest(),
            "unit_count": 1,
        },
        "audit": {
            "missing_ids": ["u1"],
            "unknown_ids": [],
            "duplicate_record_count": 0,
            "invalid_record_count": 0,
            "raw_protocol_error_count": 1,
            "document_verification": [{
                "document": "D01",
                "unit_count": 1,
                "content_preserved": True,
                "resources_preserved": True,
                "syntax_balanced": True,
                "environments_supported": True,
            }],
        },
    }
    _write(tmp_path / "gated.manifest.json", manifest)

    result = score_release(tmp_path, [prediction])

    assert result["schema"] == "latexstruct-external-release-score-v2"
    policy = result["release_policy"]
    assert policy["overall_exact_accuracy"] == {
        "operator": ">",
        "threshold": 0.98,
    }
    assert policy["wilson_lower_bound_floor"]["threshold"] == 0.95
    assert policy["document_exact_rate"] == {
        "release_gate": False,
        "reported": True,
    }
    assert policy["document_check_coverage"]["threshold"] == 1.0
    assert policy["document_integrity_accuracy"]["threshold"] == 1.0
    assert policy["maximum_critical_errors"] == 0
    assert policy["maximum_protocol_errors"] == 0
    assert result["score"]["correct"] == 1
    assert result["score"]["upstream_protocol_errors"] == 1
    assert result["score"]["protocol_errors"] == 1
    assert result["passes_release_gate"] is False
    assert result["fixture_hashes"]["packets_sha256"] == hashlib.sha256(
        json.dumps(packets, ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def test_safety_verification_is_combined_with_fixture_integrity(tmp_path):
    _fixture(tmp_path, document_checks=[{
        "document": "D01",
        "content_preserved": True,
        "resources_complete": True,
        "environments_declared": True,
        "compile_status": "not-required",
        "evidence": {"independent_fixture_validation": True},
    }])
    prediction = tmp_path / "gated.json"
    _write(prediction, [{
        "id": "u1", "action": "preserve", "env": "",
        "start_block": 0, "end_block": 0,
        "_safety_gate": {"status": "manual-fail-closed"},
    }])
    packet_path = tmp_path / "release-packets.json"
    _write(tmp_path / "gated.manifest.json", {
        "schema": "latexstruct-external-safety-gate-manifest-v1",
        "packet": {"sha256": hashlib.sha256(packet_path.read_bytes()).hexdigest()},
        "output": {
            "name": prediction.name,
            "sha256": hashlib.sha256(prediction.read_bytes()).hexdigest(),
            "unit_count": 1,
        },
        "audit": {
            "missing_ids": [], "unknown_ids": [],
            "duplicate_record_count": 0, "invalid_record_count": 0,
            "raw_protocol_error_count": 0,
            "document_verification": [{
                "document": "D01", "unit_count": 1,
                "content_preserved": True,
                "resources_preserved": False,
                "syntax_balanced": True,
                "environments_supported": True,
            }],
        },
    })

    result = score_release(tmp_path, [prediction])

    assert result["document_checks"][0]["resources_complete"] is False
    assert result["score"]["integrity_errors"] == 1
    assert result["passes_release_gate"] is False

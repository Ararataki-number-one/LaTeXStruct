# -*- coding: utf-8 -*-
"""Adversarial tests for the exact structural accuracy contract."""

import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from latexstruct.accuracy import (  # noqa: E402
    passes_release_gate,
    score_units,
    wilson_lower_bound,
)


GOLD = [
    {"id": "a", "document": "book", "action": "wrap", "env": "theorem",
     "start_block": 3, "end_block": 5},
    {"id": "b", "document": "book", "action": "preserve", "env": "",
     "start_block": 6, "end_block": 6},
    {"id": "c", "document": "paper", "action": "wrap", "env": "proof",
     "start_block": 8, "end_block": 10},
    {"id": "d", "document": "paper", "action": "manual", "env": "",
     "start_block": 12, "end_block": 13},
]


def _checks(documents=("book", "paper")):
    return [
        {
            "document": document,
            "content_preserved": True,
            "resources_complete": True,
            "environments_declared": True,
            "compile_status": "passed",
        }
        for document in documents
    ]


def _release_fixture():
    gold = []
    for index in range(600):
        if index < 250:
            action = "wrap" if index % 2 == 0 else "move-boundary"
            env = "theorem" if index % 3 else "proof"
        elif index < 500:
            action = "preserve"
            env = ""
        else:
            action = "manual"
            env = ""
        gold.append({
            "id": f"unit-{index:03d}",
            "document": f"doc-{index % 6}",
            "action": action,
            "env": env,
            "start_block": index * 2,
            "end_block": index * 2 + (1 if action in {"wrap", "move-boundary"} else 0),
        })
    checks = _checks(tuple(f"doc-{index}" for index in range(6)))
    return gold, [dict(item) for item in gold], checks


def _large_threshold_fixture():
    gold = []
    for index in range(2000):
        if index < 500:
            action = "wrap" if index % 2 == 0 else "move-boundary"
            env = "theorem" if index % 3 else "proof"
        elif index < 1250:
            action = "preserve"
            env = ""
        else:
            action = "manual"
            env = ""
        gold.append({
            "id": f"threshold-{index:04d}",
            "document": f"doc-{index % 6}",
            "action": action,
            "env": env,
            "start_block": index * 2,
            "end_block": index * 2 + (
                1 if action in {"wrap", "move-boundary"} else 0
            ),
        })
    checks = _checks(tuple(f"doc-{index}" for index in range(6)))
    return gold, [dict(item) for item in gold], checks


def _make_conservative_errors(predictions, *, preserve_errors, manual_errors):
    for index in range(500, 500 + preserve_errors):
        predictions[index]["action"] = "manual"
    for index in range(1250, 1250 + manual_errors):
        predictions[index]["action"] = "preserve"


def _assert_raises(error_type, callback):
    try:
        callback()
    except error_type:
        return
    raise AssertionError(f"expected {error_type.__name__}")


def test_exact_small_score_is_correct_but_not_release_evidence():
    report = score_units(GOLD, GOLD, _checks())
    assert report["accuracy"] == 1.0
    assert report["decision_coverage"] == 1.0
    assert report["structural_document_exact_rate"] == 1.0
    assert report["document_exact_rate"] == 1.0
    assert report["critical_errors"] == 0
    assert not passes_release_gate(report)


def test_balanced_release_fixture_passes_wilson_gate():
    gold, predictions, checks = _release_fixture()
    report = score_units(gold, predictions, checks)
    assert report["auto_units"] == 250
    assert report["move_boundary_units"] >= 20
    assert report["preserve_units"] == 250
    assert report["manual_units"] == 100
    assert report["protocol_errors"] == 0
    assert report["confidence_lower_bounds"]["manual_accuracy"] > 0.95
    assert passes_release_gate(report)


def test_noncritical_error_above_98_can_pass_with_nonexact_document():
    gold, predictions, checks = _release_fixture()
    predictions[251]["action"] = "manual"

    report = score_units(gold, predictions, checks)

    assert report["correct"] == 599
    assert report["accuracy"] == 599 / 600
    assert report["documents_exact"] == 5
    assert report["document_exact_rate"] == 5 / 6
    assert report["critical_errors"] == 0
    assert passes_release_gate(report)


def test_overall_exact_accuracy_must_be_strictly_greater_than_98():
    gold, predictions, checks = _large_threshold_fixture()
    _make_conservative_errors(
        predictions,
        preserve_errors=20,
        manual_errors=20,
    )
    exactly_98 = score_units(gold, predictions, checks)

    assert exactly_98["accuracy"] == 0.98
    assert exactly_98["confidence_lower_bounds"]["accuracy"] > 0.95
    assert exactly_98["confidence_lower_bounds"]["preservation_accuracy"] > 0.95
    assert exactly_98["confidence_lower_bounds"]["manual_accuracy"] > 0.95
    assert exactly_98["critical_errors"] == 0
    assert not passes_release_gate(exactly_98)

    predictions = [dict(item) for item in gold]
    _make_conservative_errors(
        predictions,
        preserve_errors=20,
        manual_errors=19,
    )
    above_98 = score_units(gold, predictions, checks)

    assert above_98["accuracy"] == 1961 / 2000
    assert above_98["document_exact_rate"] == 0.0
    assert above_98["critical_errors"] == 0
    assert passes_release_gate(above_98)


def test_high_accuracy_critical_edit_still_fails_release_gate():
    gold, predictions, checks = _release_fixture()
    predictions[251].update(action="wrap", env="theorem")

    report = score_units(gold, predictions, checks)

    assert report["accuracy"] == 599 / 600
    assert report["critical_unit_errors"] == 1
    assert report["confidence_lower_bounds"]["accuracy"] > 0.95
    assert not passes_release_gate(report)


def test_high_accuracy_integrity_failure_still_fails_release_gate():
    gold, predictions, checks = _release_fixture()
    checks[0]["resources_complete"] = False

    report = score_units(gold, predictions, checks)

    assert report["accuracy"] == 1.0
    assert report["integrity_errors"] == 1
    assert report["critical_errors"] == 1
    assert not passes_release_gate(report)


def test_wrong_boundary_is_both_fp_and_fn():
    predicted = [dict(item) for item in GOLD]
    predicted[0]["end_block"] = 4
    report = score_units(GOLD, predicted, _checks())
    assert report["tp"] == 1
    assert report["fp"] == 1
    assert report["fn"] == 1
    assert report["boundary_exact_match"] == 0.5
    assert report["structural_document_exact_rate"] == 0.5
    assert not passes_release_gate(report)


def test_preserve_edit_is_critical():
    predicted = [dict(item) for item in GOLD]
    predicted[1].update(action="wrap", env="lemma")
    report = score_units(GOLD, predicted, _checks())
    assert report["preservation_accuracy"] == 0.0
    assert report["manual_accuracy"] == 1.0
    assert report["critical_unit_errors"] == 1
    assert report["critical_errors"] == 1
    assert not passes_release_gate(report)


def test_manual_and_preserve_are_not_interchangeable():
    predicted = [dict(item) for item in GOLD]
    predicted[1]["action"] = "manual"
    predicted[3]["action"] = "preserve"
    report = score_units(GOLD, predicted, _checks())
    assert report["preservation_accuracy"] == 0.0
    assert report["manual_accuracy"] == 0.0
    assert report["critical_errors"] == 0
    assert report["accuracy"] == 0.5


def test_missing_duplicate_unknown_and_illegal_are_protocol_errors():
    predicted = [dict(GOLD[0]), dict(GOLD[0]), dict(GOLD[1])]
    invalid = dict(GOLD[2])
    invalid["action"] = "none"
    predicted.append(invalid)
    predicted.append({
        "id": "unknown", "action": "wrap", "env": "theorem",
        "start_block": 1, "end_block": 1,
    })
    report = score_units(GOLD, predicted, _checks())
    assert report["decision_coverage"] == 0.25
    assert report["duplicate_ids"] == ["a"]
    assert report["duplicate_counts"] == {"a": 2}
    assert report["missing_ids"] == ["d"]
    assert report["invalid_ids"] == ["c"]
    assert report["unknown_ids"] == ["unknown"]
    assert report["response_protocol_errors"] == 4
    assert not passes_release_gate(report)


def test_incomplete_automatic_record_is_invalid_not_covered():
    predicted = [dict(item) for item in GOLD]
    predicted[0].pop("end_block")
    predicted[2]["env"] = ""
    report = score_units(GOLD, predicted, _checks())
    assert report["decision_coverage"] == 0.5
    assert report["invalid_ids"] == ["a", "c"]
    assert report["fn"] == 2
    assert report["tp"] == 0


def test_preserve_and_manual_require_an_explicit_empty_env():
    predicted = [dict(item) for item in GOLD]
    predicted[1]["env"] = "theorem"
    predicted[3]["env"] = "lemma"

    report = score_units(GOLD, predicted, _checks())

    assert report["invalid_ids"] == ["b", "d"]
    assert report["response_protocol_errors"] == 2
    assert report["decision_coverage"] == 0.5

    invalid_gold = dict(GOLD[1], env="theorem")
    _assert_raises(ValueError, lambda: score_units([invalid_gold], []))


def test_gold_schema_is_strict_and_empty_gold_cannot_score_100():
    _assert_raises(ValueError, lambda: score_units([], []))

    missing_action = dict(GOLD[0])
    missing_action.pop("action")
    _assert_raises(ValueError, lambda: score_units([missing_action], []))

    legacy_none = dict(GOLD[0], action="none")
    _assert_raises(ValueError, lambda: score_units([legacy_none], []))

    reversed_range = dict(GOLD[0], start_block=9, end_block=3)
    _assert_raises(ValueError, lambda: score_units([reversed_range], []))

    boolean_block = dict(GOLD[0], start_block=True)
    _assert_raises(ValueError, lambda: score_units([boolean_block], []))

    duplicate = [dict(GOLD[0]), dict(GOLD[0])]
    _assert_raises(ValueError, lambda: score_units(duplicate, []))


def test_document_exact_requires_independent_integrity_checks():
    no_checks = score_units(GOLD, GOLD)
    assert no_checks["structural_document_exact_rate"] == 1.0
    assert no_checks["document_check_coverage"] == 0.0
    assert no_checks["document_exact_rate"] == 0.0
    assert no_checks["missing_check_documents"] == ["book", "paper"]

    checks = _checks()
    checks[1]["resources_complete"] = False
    checks[1]["environments_declared"] = False
    checks[1]["compile_status"] = "failed"
    failed = score_units(GOLD, GOLD, checks)
    assert failed["document_check_coverage"] == 1.0
    assert failed["document_integrity_accuracy"] == 0.5
    assert failed["document_exact_rate"] == 0.5
    assert failed["integrity_errors"] == 3
    assert failed["critical_errors"] == 3


def test_duplicate_unknown_and_invalid_document_checks_fail_protocol():
    checks = _checks()
    checks.append(dict(checks[0]))
    checks.append({
        "document": "alien", "content_preserved": True,
        "resources_complete": True, "environments_declared": True,
        "compile_status": "passed",
    })
    checks[1]["content_preserved"] = "yes"
    report = score_units(GOLD, GOLD, checks)
    assert report["duplicate_check_documents"] == ["book"]
    assert report["invalid_check_documents"] == ["paper"]
    assert report["unknown_check_documents"] == ["alien"]
    assert report["document_check_protocol_errors"] == 3
    assert report["document_check_coverage"] == 0.0


def test_extra_unknown_cannot_hide_behind_high_point_metrics():
    gold, predictions, checks = _release_fixture()
    predictions.append({
        "id": "hallucinated", "action": "wrap", "env": "theorem",
        "start_block": 9999, "end_block": 9999,
    })
    report = score_units(gold, predictions, checks)
    assert report["precision"] > 0.95
    assert report["confidence_lower_bounds"]["precision"] > 0.95
    assert report["protocol_errors"] == 1
    assert not passes_release_gate(report)


def test_wilson_lower_bound_rejects_tiny_perfect_samples():
    assert wilson_lower_bound(0, 0) == 0.0
    assert 0.96 < wilson_lower_bound(100, 100) < 0.97
    assert wilson_lower_bound(3, 3) < 0.5
    _assert_raises(ValueError, lambda: wilson_lower_bound(2, 1))
    _assert_raises(ValueError, lambda: wilson_lower_bound(True, 1))


def test_release_gate_rejects_nonfinite_or_incomplete_reports():
    gold, predictions, checks = _release_fixture()
    report = score_units(gold, predictions, checks)

    nonfinite = dict(report)
    nonfinite["precision"] = math.inf
    assert not passes_release_gate(nonfinite)

    missing_lower = dict(report)
    missing_lower["confidence_lower_bounds"] = {"precision": 1.0}
    assert not passes_release_gate(missing_lower)

    rounded_bypass = dict(report)
    rounded_bypass["confidence_lower_bounds"] = dict(
        report["confidence_lower_bounds"], accuracy=0.9499999
    )
    assert not passes_release_gate(rounded_bypass)

    fractional_count = dict(report)
    fractional_count["units"] = 600.9
    assert not passes_release_gate(fractional_count)

    contradictory = dict(report)
    contradictory["correct"] -= 1
    assert not passes_release_gate(contradictory)

    forged_document_exact = dict(report)
    forged_document_exact["document_exact_rate"] = 0.0
    assert not passes_release_gate(forged_document_exact)

    forged_lower = dict(report)
    forged_lower["confidence_lower_bounds"] = dict(
        report["confidence_lower_bounds"], manual_accuracy=1.0
    )
    assert not passes_release_gate(forged_lower)

    _assert_raises(ValueError, lambda: passes_release_gate(report, math.nan))
    _assert_raises(ValueError, lambda: passes_release_gate(report, 0))


def main():
    tests = [
        value for name, value in sorted(globals().items())
        if name.startswith("test_") and callable(value)
    ]
    for test in tests:
        test()
        print("PASS", test.__name__)
    print(f"{len(tests)}/{len(tests)} passed")


if __name__ == "__main__":
    main()

# -*- coding: utf-8 -*-
"""Exact, reproducible scoring for structure-analysis experiments.

The legacy benchmark measures scanner recall. This module scores the end-to-end
decision that users care about: action, environment and complete atomic range.
It intentionally has no model or network dependency, so the same scorer can be
used with an API response, a deterministic engine, or a Codex-adjudicated packet.

Release claims use 95% Wilson lower confidence bounds, not only optimistic point
estimates. Response-shape and document-integrity failures are hard failures: a
model cannot improve its score by omitting difficult answers or by returning
extra/duplicate records.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from math import isclose, isfinite, sqrt
from typing import Dict, Iterable, List, Optional, Tuple

AUTO_ACTIONS = frozenset({"wrap", "move-boundary"})
ALLOWED_ACTIONS = AUTO_ACTIONS | {"preserve", "manual"}
REPORT_SCHEMA_VERSION = "2.0"

# A release result must be large and balanced enough for a 95% claim to be
# meaningful. With 100 perfect manual cases, for example, the two-sided 95%
# Wilson lower bound is about 96.3%, rather than an uninformative 100% from a
# handful of cases.
MIN_RELEASE_UNITS = 600
MIN_RELEASE_DOCUMENTS = 6
MIN_RELEASE_AUTO_UNITS = 250
MIN_RELEASE_MOVE_BOUNDARY_UNITS = 20
MIN_RELEASE_PRESERVE_UNITS = 250
MIN_RELEASE_MANUAL_UNITS = 100
MIN_RELEASE_EXACT_ACCURACY = 0.98
MIN_RELEASE_STATISTICAL_FLOOR = 0.95
WILSON_Z_95 = 1.959963984540054


def release_policy() -> Dict:
    """Return the default release policy as self-describing JSON data."""

    return {
        "overall_exact_accuracy": {
            "operator": ">",
            "threshold": MIN_RELEASE_EXACT_ACCURACY,
        },
        "point_metric_floor": {
            "operator": ">=",
            "threshold": MIN_RELEASE_STATISTICAL_FLOOR,
            "metrics": [
                "accuracy",
                "precision",
                "recall",
                "f1",
                "decision_coverage",
                "boundary_exact_match",
                "preservation_accuracy",
                "manual_accuracy",
            ],
        },
        "wilson_lower_bound_floor": {
            "confidence_level": 0.95,
            "operator": ">=",
            "threshold": MIN_RELEASE_STATISTICAL_FLOOR,
            "metrics": [
                "accuracy",
                "precision",
                "recall",
                "f1",
                "decision_coverage",
                "boundary_exact_match",
                "preservation_accuracy",
                "manual_accuracy",
            ],
        },
        "document_check_coverage": {
            "operator": "==",
            "threshold": 1.0,
        },
        "document_integrity_accuracy": {
            "operator": "==",
            "threshold": 1.0,
        },
        "document_exact_rate": {"release_gate": False, "reported": True},
        "maximum_critical_errors": 0,
        "maximum_protocol_errors": 0,
    }


def _round(value: float) -> float:
    # Keep full precision for threshold comparisons. Presentation layers may
    # round later; rounding here could turn 0.9499996 into a passing 0.95.
    return float(value)


def _ratio(numerator: int, denominator: int, empty: float = 1.0) -> float:
    return _round(numerator / denominator) if denominator else float(empty)


def wilson_lower_bound(successes: int, total: int,
                       z: float = WILSON_Z_95) -> float:
    """Return the two-sided 95% Wilson score-interval lower endpoint.

    An empty denominator deliberately returns 0. An absent class therefore
    cannot masquerade as a perfectly measured class in a release report.
    """

    if isinstance(successes, bool) or isinstance(total, bool):
        raise ValueError("Wilson counts must be integers, not booleans")
    if not isinstance(successes, int) or not isinstance(total, int):
        raise ValueError("Wilson counts must be integers")
    if total < 0 or successes < 0 or successes > total:
        raise ValueError("Wilson counts require 0 <= successes <= total")
    if not isfinite(float(z)) or float(z) <= 0:
        raise ValueError("Wilson z must be a finite positive number")
    if total == 0:
        return 0.0
    proportion = successes / total
    z_squared = float(z) ** 2
    denominator = 1.0 + z_squared / total
    centre = proportion + z_squared / (2.0 * total)
    margin = float(z) * sqrt(
        proportion * (1.0 - proportion) / total
        + z_squared / (4.0 * total * total)
    )
    return _round((centre - margin) / denominator)


def _strict_string(value: object) -> Optional[str]:
    if not isinstance(value, str) or not value or value != value.strip():
        return None
    return value


def _strict_block(value: object) -> Optional[int]:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _validation_error(item: Dict, *, require_document: bool) -> Optional[str]:
    """Return why a structural record is illegal, or ``None`` if valid."""

    action = item.get("action")
    if not isinstance(action, str) or action not in ALLOWED_ACTIONS:
        return "action must be one of preserve/wrap/move-boundary/manual"
    env = item.get("env")
    if not isinstance(env, str) or env != env.strip():
        return "env must be a trimmed string (empty is allowed for prose)"
    if action in AUTO_ACTIONS and not env:
        return "automatic actions require a non-empty env"
    if action not in AUTO_ACTIONS and env:
        return "preserve/manual actions require an empty env"
    start = _strict_block(item.get("start_block"))
    end = _strict_block(item.get("end_block"))
    if start is None or end is None:
        return "start_block and end_block must be non-negative integers"
    if start > end:
        return "start_block must not exceed end_block"
    if require_document and _strict_string(item.get("document")) is None:
        return "gold document must be a non-empty trimmed string"
    return None


def _signature(item: Dict) -> Tuple[str, str, int, int]:
    # Callers validate first, so no default may silently turn malformed output
    # into a correct preserve decision.
    return (
        item["action"],
        item["env"],
        item["start_block"],
        item["end_block"],
    )


def _document_check_error(item: Dict) -> Optional[str]:
    if _strict_string(item.get("document")) is None:
        return "document must be a non-empty trimmed string"
    if not isinstance(item.get("content_preserved"), bool):
        return "content_preserved must be boolean"
    if not isinstance(item.get("resources_complete"), bool):
        return "resources_complete must be boolean"
    if not isinstance(item.get("environments_declared"), bool):
        return "environments_declared must be boolean"
    if item.get("compile_status") not in {"passed", "not-required", "failed"}:
        return "compile_status must be passed/not-required/failed"
    return None


def score_units(gold: Iterable[Dict], predictions: Iterable[Dict],
                document_checks: Optional[Iterable[Dict]] = None) -> Dict:
    """Score exact structural units and independent document-integrity checks.

    Unit records require stable string ``id`` and the fields ``action``, ``env``,
    ``start_block`` and ``end_block``. Gold additionally requires ``document``.
    A prediction is correct only when all four semantic fields match. Missing,
    duplicate, unknown and malformed replies are reported as protocol errors.

    ``document_checks`` must contain exactly one record per gold document with
    ``content_preserved`` (bool), ``resources_complete`` (bool),
    ``environments_declared`` (bool), and ``compile_status`` (``passed``,
    ``not-required`` or ``failed``). A missing check never defaults to success.
    ``not-required`` is intended only for a frozen source fragment that was not
    independently compilable before the run.
    """

    gold_items = [dict(item) for item in gold]
    if not gold_items:
        raise ValueError("gold must contain at least one structural unit")
    predicted_items = [dict(item) for item in predictions]
    check_items = [dict(item) for item in (document_checks or [])]

    gold_by_id: Dict[str, Dict] = {}
    for item in gold_items:
        unit_id = _strict_string(item.get("id"))
        if unit_id is None or unit_id in gold_by_id:
            raise ValueError(
                "gold unit id is empty, untrimmed or duplicated: "
                f"{item.get('id')!r}"
            )
        error = _validation_error(item, require_document=True)
        if error:
            raise ValueError(f"invalid gold unit {unit_id}: {error}")
        gold_by_id[unit_id] = item

    predictions_by_id: Dict[str, List[Dict]] = defaultdict(list)
    unknown_ids: List[str] = []
    for item in predicted_items:
        raw_id = item.get("id")
        unit_id = raw_id if isinstance(raw_id, str) else ""
        if unit_id not in gold_by_id:
            unknown_ids.append(unit_id)
            continue
        predictions_by_id[unit_id].append(item)

    valid_unique: Dict[str, Dict] = {}
    duplicates: List[str] = []
    invalid_reasons: Dict[str, str] = {}
    for unit_id, items in predictions_by_id.items():
        if len(items) != 1:
            duplicates.append(unit_id)
            continue
        error = _validation_error(items[0], require_document=False)
        if error:
            invalid_reasons[unit_id] = error
            continue
        valid_unique[unit_id] = items[0]

    exact_ids = {
        unit_id for unit_id, gold_item in gold_by_id.items()
        if unit_id in valid_unique
        and _signature(valid_unique[unit_id]) == _signature(gold_item)
    }
    missing = sorted(set(gold_by_id) - set(predictions_by_id))
    covered = len(valid_unique)

    tp = 0
    fp = len(unknown_ids)
    fn = 0
    boundary_exact = 0
    boundary_total = 0
    move_boundary_total = 0
    preservation_correct = 0
    preservation_total = 0
    manual_correct = 0
    manual_total = 0
    critical_unit_errors = 0
    errors: List[Dict] = []
    per_document = defaultdict(lambda: {"total": 0, "correct": 0})

    for unit_id, gold_item in gold_by_id.items():
        gold_sig = _signature(gold_item)
        gold_action = gold_sig[0]
        prediction = valid_unique.get(unit_id)
        pred_sig = _signature(prediction) if prediction is not None else None
        exact = unit_id in exact_ids
        document = gold_item["document"]
        per_document[document]["total"] += 1
        per_document[document]["correct"] += int(exact)

        if gold_action in AUTO_ACTIONS:
            boundary_total += 1
            move_boundary_total += int(gold_action == "move-boundary")
            if exact:
                tp += 1
                boundary_exact += 1
            else:
                fn += 1
                # A wrong environment, action or boundary is simultaneously a
                # false positive modification and a missed correct modification.
                if pred_sig is not None and pred_sig[0] in AUTO_ACTIONS:
                    fp += 1
        elif gold_action == "preserve":
            preservation_total += 1
            if exact:
                preservation_correct += 1
            elif pred_sig is not None and pred_sig[0] in AUTO_ACTIONS:
                fp += 1
        else:  # manual
            manual_total += 1
            if exact:
                manual_correct += 1
            elif pred_sig is not None and pred_sig[0] in AUTO_ACTIONS:
                fp += 1

        destructive = (
            gold_action not in AUTO_ACTIONS
            and pred_sig is not None
            and pred_sig[0] in AUTO_ACTIONS
        )
        critical_unit_errors += int(destructive)
        if not exact:
            errors.append({
                "id": unit_id,
                "document": document,
                "gold": gold_sig,
                "prediction": pred_sig,
                "critical": destructive,
            })

    documents = set(per_document)
    checks_by_document: Dict[str, List[Dict]] = defaultdict(list)
    unknown_check_documents: List[str] = []
    for item in check_items:
        raw_document = item.get("document")
        document = raw_document if isinstance(raw_document, str) else ""
        if document not in documents:
            unknown_check_documents.append(document)
            continue
        checks_by_document[document].append(item)

    valid_checks: Dict[str, Dict] = {}
    duplicate_check_documents: List[str] = []
    invalid_check_reasons: Dict[str, str] = {}
    for document, items in checks_by_document.items():
        if len(items) != 1:
            duplicate_check_documents.append(document)
            continue
        error = _document_check_error(items[0])
        if error:
            invalid_check_reasons[document] = error
            continue
        valid_checks[document] = items[0]

    missing_check_documents = sorted(documents - set(checks_by_document))
    integrity_failures: List[Dict] = []
    integrity_ok_documents = set()
    for document, item in valid_checks.items():
        failed = []
        if not item["content_preserved"]:
            failed.append("content-not-preserved")
        if not item["resources_complete"]:
            failed.append("resources-incomplete")
        if not item["environments_declared"]:
            failed.append("environment-undeclared")
        if item["compile_status"] == "failed":
            failed.append("compile-failed")
        if failed:
            integrity_failures.append({"document": document, "failures": failed})
        else:
            integrity_ok_documents.add(document)

    structurally_exact_documents = {
        document for document, values in per_document.items()
        if values["total"] == values["correct"]
    }
    exact_documents = structurally_exact_documents & integrity_ok_documents

    precision_denominator = tp + fp
    recall_denominator = tp + fn
    precision = _ratio(tp, precision_denominator)
    recall = _ratio(tp, recall_denominator)
    f1_denominator = 2 * tp + fp + fn
    f1 = _ratio(2 * tp, f1_denominator, empty=0.0)
    precision_lower = wilson_lower_bound(tp, precision_denominator)
    recall_lower = wilson_lower_bound(tp, recall_denominator)
    f1_lower = (
        _round(2 * precision_lower * recall_lower
               / (precision_lower + recall_lower))
        if precision_lower + recall_lower else 0.0
    )

    duplicate_counts = Counter(
        item.get("id") for item in predicted_items
        if isinstance(item.get("id"), str) and item.get("id") in gold_by_id
    )
    duplicate_check_counts = Counter(
        item.get("document") for item in check_items
        if (isinstance(item.get("document"), str)
            and item.get("document") in documents)
    )

    response_protocol_errors = (
        len(missing)
        + len(unknown_ids)
        + len(invalid_reasons)
        + sum(max(0, duplicate_counts[unit_id] - 1)
              for unit_id in duplicates)
    )
    document_check_protocol_errors = (
        len(missing_check_documents)
        + len(unknown_check_documents)
        + len(invalid_check_reasons)
        + sum(max(0, duplicate_check_counts[document] - 1)
              for document in duplicate_check_documents)
    )
    protocol_errors = response_protocol_errors + document_check_protocol_errors
    integrity_error_count = sum(
        len(item["failures"]) for item in integrity_failures
    )
    critical_errors = critical_unit_errors + integrity_error_count

    units = len(gold_by_id)
    document_count = len(per_document)
    correct = len(exact_ids)
    structural_document_exact = len(structurally_exact_documents)
    integrity_correct = len(integrity_ok_documents)
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "confidence_level": 0.95,
        "units": units,
        "auto_units": boundary_total,
        "move_boundary_units": move_boundary_total,
        "preserve_units": preservation_total,
        "manual_units": manual_total,
        "correct": correct,
        "covered": covered,
        "boundary_exact": boundary_exact,
        "preservation_correct": preservation_correct,
        "manual_correct": manual_correct,
        "accuracy": _ratio(correct, units),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "decision_coverage": _ratio(covered, units),
        "boundary_exact_match": _ratio(boundary_exact, boundary_total),
        "preservation_accuracy": _ratio(
            preservation_correct, preservation_total
        ),
        "manual_accuracy": _ratio(manual_correct, manual_total),
        "documents": document_count,
        "structural_documents_exact": structural_document_exact,
        "document_checks_valid": len(valid_checks),
        "document_integrity_correct": integrity_correct,
        "documents_exact": len(exact_documents),
        "structural_document_exact_rate": _ratio(
            structural_document_exact, document_count
        ),
        "document_check_coverage": _ratio(len(valid_checks), document_count),
        "document_integrity_accuracy": _ratio(
            integrity_correct, document_count
        ),
        "document_exact_rate": _ratio(len(exact_documents), document_count),
        "confidence_lower_bounds": {
            "accuracy": wilson_lower_bound(correct, units),
            "precision": precision_lower,
            "recall": recall_lower,
            "f1": f1_lower,
            "decision_coverage": wilson_lower_bound(covered, units),
            "boundary_exact_match": wilson_lower_bound(
                boundary_exact, boundary_total
            ),
            "preservation_accuracy": wilson_lower_bound(
                preservation_correct, preservation_total
            ),
            "manual_accuracy": wilson_lower_bound(
                manual_correct, manual_total
            ),
        },
        "critical_errors": critical_errors,
        "critical_unit_errors": critical_unit_errors,
        "integrity_errors": integrity_error_count,
        "protocol_errors": protocol_errors,
        "response_protocol_errors": response_protocol_errors,
        "document_check_protocol_errors": document_check_protocol_errors,
        "missing_ids": missing,
        "duplicate_ids": sorted(duplicates),
        "duplicate_counts": {
            unit_id: duplicate_counts[unit_id]
            for unit_id in sorted(duplicates)
        },
        "invalid_ids": sorted(invalid_reasons),
        "invalid_reasons": dict(sorted(invalid_reasons.items())),
        "unknown_ids": sorted(unknown_ids),
        "missing_check_documents": missing_check_documents,
        "duplicate_check_documents": sorted(duplicate_check_documents),
        "invalid_check_documents": sorted(invalid_check_reasons),
        "invalid_check_reasons": dict(sorted(invalid_check_reasons.items())),
        "unknown_check_documents": sorted(unknown_check_documents),
        "integrity_failures": integrity_failures,
        "errors": errors,
    }


def _finite_rate(report: Dict, name: str) -> Optional[float]:
    try:
        value = float(report[name])
    except (KeyError, TypeError, ValueError):
        return None
    if not isfinite(value) or not 0.0 <= value <= 1.0:
        return None
    return value


def _nonnegative_int(report: Dict, name: str) -> Optional[int]:
    value = report.get(name)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _same_rate(actual: Optional[float], expected: float) -> bool:
    return actual is not None and isclose(
        actual, expected, rel_tol=1e-12, abs_tol=1e-12
    )


def passes_release_gate(
    report: Dict,
    threshold: float = MIN_RELEASE_STATISTICAL_FLOOR,
) -> bool:
    """Return whether a score satisfies the published accuracy contract.

    The gate rejects small or unbalanced datasets, malformed model response
    sets, missing integrity checks and non-finite/fabricated rates.
    """

    try:
        threshold_value = float(threshold)
    except (TypeError, ValueError):
        raise ValueError("threshold must be a finite number in (0, 1]")
    if not isfinite(threshold_value) or not 0.0 < threshold_value <= 1.0:
        raise ValueError("threshold must be a finite number in (0, 1]")
    if report.get("schema_version") != REPORT_SCHEMA_VERSION:
        return False

    point_names = (
        "accuracy",
        "precision",
        "recall",
        "f1",
        "decision_coverage",
        "boundary_exact_match",
        "preservation_accuracy",
        "manual_accuracy",
        "document_check_coverage",
        "document_integrity_accuracy",
        "document_exact_rate",
    )
    point_rates = {name: _finite_rate(report, name) for name in point_names}
    if any(value is None for value in point_rates.values()):
        return False
    thresholded_point_names = tuple(
        name for name in point_names if name != "document_exact_rate"
    )

    lower_report = report.get("confidence_lower_bounds")
    if not isinstance(lower_report, dict):
        return False
    lower_names = (
        "accuracy",
        "precision",
        "recall",
        "f1",
        "decision_coverage",
        "boundary_exact_match",
        "preservation_accuracy",
        "manual_accuracy",
    )
    lower_rates = {
        name: _finite_rate(lower_report, name) for name in lower_names
    }
    if any(value is None for value in lower_rates.values()):
        return False

    count_names = (
        "units",
        "documents",
        "auto_units",
        "move_boundary_units",
        "preserve_units",
        "manual_units",
        "correct",
        "covered",
        "boundary_exact",
        "preservation_correct",
        "manual_correct",
        "tp",
        "fp",
        "fn",
        "structural_documents_exact",
        "document_checks_valid",
        "document_integrity_correct",
        "documents_exact",
        "critical_unit_errors",
        "integrity_errors",
        "response_protocol_errors",
        "document_check_protocol_errors",
        "critical_errors",
        "protocol_errors",
    )
    counts = {name: _nonnegative_int(report, name) for name in count_names}
    if any(value is None for value in counts.values()):
        return False
    units = counts["units"]
    documents = counts["documents"]
    auto_units = counts["auto_units"]
    move_boundary_units = counts["move_boundary_units"]
    preserve_units = counts["preserve_units"]
    manual_units = counts["manual_units"]
    critical_errors = counts["critical_errors"]
    protocol_errors = counts["protocol_errors"]

    correct = counts["correct"]
    covered = counts["covered"]
    boundary_exact = counts["boundary_exact"]
    preservation_correct = counts["preservation_correct"]
    manual_correct = counts["manual_correct"]
    tp = counts["tp"]
    fp = counts["fp"]
    fn = counts["fn"]
    structural_documents_exact = counts["structural_documents_exact"]
    document_checks_valid = counts["document_checks_valid"]
    document_integrity_correct = counts["document_integrity_correct"]
    documents_exact = counts["documents_exact"]

    # Do not accept a hand-edited report whose attractive rates contradict its
    # raw counts.  Release evidence is derived from ``score_units``; every
    # relationship below is deterministic and therefore independently
    # recomputable at the final gate.
    count_consistent = (
        move_boundary_units <= auto_units
        and boundary_exact == tp
        and fn == auto_units - boundary_exact
        and correct == boundary_exact + preservation_correct + manual_correct
        and 0 <= correct <= covered <= units
        and preservation_correct <= preserve_units
        and manual_correct <= manual_units
        and structural_documents_exact <= documents
        and document_checks_valid <= documents
        and document_integrity_correct <= document_checks_valid
        and documents_exact <= min(
            structural_documents_exact, document_integrity_correct
        )
        and critical_errors
        == counts["critical_unit_errors"] + counts["integrity_errors"]
        and protocol_errors
        == counts["response_protocol_errors"]
        + counts["document_check_protocol_errors"]
    )
    if not count_consistent:
        return False

    expected_points = {
        "accuracy": _ratio(correct, units),
        "precision": _ratio(tp, tp + fp),
        "recall": _ratio(tp, tp + fn),
        "f1": _ratio(2 * tp, 2 * tp + fp + fn, empty=0.0),
        "decision_coverage": _ratio(covered, units),
        "boundary_exact_match": _ratio(boundary_exact, auto_units),
        "preservation_accuracy": _ratio(preservation_correct, preserve_units),
        "manual_accuracy": _ratio(manual_correct, manual_units),
        "document_check_coverage": _ratio(document_checks_valid, documents),
        "document_integrity_accuracy": _ratio(
            document_integrity_correct, documents
        ),
        "document_exact_rate": _ratio(documents_exact, documents),
    }
    if any(
        not _same_rate(point_rates[name], expected)
        for name, expected in expected_points.items()
    ):
        return False

    precision_lower = wilson_lower_bound(tp, tp + fp)
    recall_lower = wilson_lower_bound(tp, tp + fn)
    expected_lowers = {
        "accuracy": wilson_lower_bound(correct, units),
        "precision": precision_lower,
        "recall": recall_lower,
        "f1": (
            2 * precision_lower * recall_lower
            / (precision_lower + recall_lower)
            if precision_lower + recall_lower else 0.0
        ),
        "decision_coverage": wilson_lower_bound(covered, units),
        "boundary_exact_match": wilson_lower_bound(
            boundary_exact, auto_units
        ),
        "preservation_accuracy": wilson_lower_bound(
            preservation_correct, preserve_units
        ),
        "manual_accuracy": wilson_lower_bound(manual_correct, manual_units),
    }
    if any(
        not _same_rate(lower_rates[name], expected)
        for name, expected in expected_lowers.items()
    ):
        return False

    balanced_sample = (
        units >= MIN_RELEASE_UNITS
        and documents >= MIN_RELEASE_DOCUMENTS
        and auto_units >= MIN_RELEASE_AUTO_UNITS
        and move_boundary_units >= MIN_RELEASE_MOVE_BOUNDARY_UNITS
        and preserve_units >= MIN_RELEASE_PRESERVE_UNITS
        and manual_units >= MIN_RELEASE_MANUAL_UNITS
        and auto_units + preserve_units + manual_units == units
    )
    return (
        balanced_sample
        and point_rates["accuracy"] > MIN_RELEASE_EXACT_ACCURACY
        and all(
            point_rates[name] >= threshold_value
            for name in thresholded_point_names
        )
        and all(value >= threshold_value for value in lower_rates.values())
        # Unit-level conservative classification errors may make a document
        # non-exact while the aggregate result remains above 98%.  Document
        # exactness is therefore reported and count-checked, but it is not a
        # release veto.  Integrity and evidence coverage remain zero-tolerance.
        and point_rates["document_check_coverage"] == 1.0
        and point_rates["document_integrity_accuracy"] == 1.0
        and critical_errors == 0
        and protocol_errors == 0
    )

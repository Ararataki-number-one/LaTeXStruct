# -*- coding: utf-8 -*-
"""Concurrency, accounting, and recovery contracts for analysis budgets."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError

import pytest

from latexstruct.core.analysis_budget import (
    ActualUsage,
    AnalysisBudget,
    BudgetClaim,
    BudgetDecision,
    BudgetExhaustedError,
    BudgetLimits,
    BudgetPriority,
    BudgetUsage,
    LowPriorityBudgetStop,
    UnknownReservationError,
)


class ManualClock:
    def __init__(self, seconds: float = 0.0) -> None:
        self.seconds = seconds

    def __call__(self) -> float:
        return self.seconds


def _limits(**changes) -> BudgetLimits:
    values = {
        "max_input_tokens": 1_000,
        "max_output_tokens": 500,
        "max_cost": 10.0,
        "max_requests": 10,
        "max_strong_model_calls": 3,
        "max_wall_time_minutes": 120.0,
    }
    values.update(changes)
    return BudgetLimits(**values)


def _claim(**changes) -> BudgetClaim:
    values = {
        "input_tokens": 50,
        "output_tokens": 20,
        "cost": 0.5,
        "requests": 1,
        "strong_model_calls": 0,
    }
    values.update(changes)
    return BudgetClaim(**values)


def test_limits_are_frozen_and_zero_only_disables_non_wall_limits():
    limits = _limits(
        max_input_tokens=0,
        max_output_tokens=0,
        max_cost=0,
        max_requests=0,
        max_strong_model_calls=0,
    )
    assert limits.max_wall_time_minutes == 120.0
    with pytest.raises(FrozenInstanceError):
        limits.max_requests = 5
    with pytest.raises(ValueError, match="greater than zero"):
        _limits(max_wall_time_minutes=0)


def test_usage_rejects_more_committed_reservations_than_accounted_requests():
    with pytest.raises(ValueError, match="committed_reservations"):
        BudgetUsage(requests=0, committed_reservations=1)
    with pytest.raises(ValueError, match="non-negative integer"):
        _limits(max_requests=-1)
    with pytest.raises(ValueError, match="finite non-negative"):
        _limits(max_cost=float("nan"))


def test_cancel_releases_capacity_and_commit_records_known_and_unknown_usage():
    budget = AnalysisBudget(_limits(max_requests=2), clock=ManualClock())
    cancelled = budget.reserve(_claim(), priority=BudgetPriority.HIGH).reservation
    assert cancelled is not None
    usage = budget.cancel(cancelled)
    assert usage.cancelled_reservations == 1
    assert usage.requests == 0

    first = budget.reserve(_claim(input_tokens=100, output_tokens=40, cost=1.0)).reservation
    assert first is not None
    usage = budget.commit(first, ActualUsage(input_tokens=80, output_tokens=None, cost=None))
    assert usage.input_tokens == 80
    assert usage.output_tokens is None
    assert usage.cost is None
    assert usage.observed_input_tokens == 80
    assert usage.accounted_input_tokens == 80
    assert usage.accounted_output_tokens == 40
    assert usage.accounted_cost == pytest.approx(1.0)
    assert usage.unknown_output_token_requests == 1
    assert usage.unknown_cost_requests == 1
    assert usage.requests == 1

    second = budget.reserve(_claim(), priority=BudgetPriority.HIGH).reservation
    assert second is not None
    budget.commit(second, ActualUsage(input_tokens=10, output_tokens=5, cost=0.1))
    with pytest.raises(UnknownReservationError):
        budget.commit(second, ActualUsage(input_tokens=1, output_tokens=1, cost=0.01))


def test_low_and_medium_stop_near_limit_but_high_priority_can_finish_atomically():
    budget = AnalysisBudget(
        _limits(max_requests=10, max_input_tokens=100, max_output_tokens=0, max_cost=0),
        clock=ManualClock(),
    )
    initial = budget.reserve(
        _claim(input_tokens=85, output_tokens=0, cost=0),
        priority=BudgetPriority.HIGH,
    ).reservation
    assert initial is not None
    budget.commit(initial, ActualUsage(input_tokens=85, output_tokens=0, cost=0))

    for priority in (BudgetPriority.LOW, BudgetPriority.MEDIUM):
        stopped = budget.reserve(
            _claim(input_tokens=5, output_tokens=0, cost=0),
            priority=priority,
        )
        assert stopped.decision is BudgetDecision.STOP_LOW_PRIORITY
        assert stopped.reasons == ("near_limit:input_tokens",)
        assert stopped.reservation is None
    assert budget.stop_reason == "STOP_LOW_PRIORITY"

    high = budget.reserve(
        _claim(input_tokens=10, output_tokens=0, cost=0),
        priority=BudgetPriority.HIGH,
    ).reservation
    assert high is not None
    # The provider may exceed its estimate.  This call is still committed as an
    # atomic unit, then all subsequent calls are rejected.
    usage = budget.commit(high, ActualUsage(input_tokens=20, output_tokens=0, cost=0))
    assert usage.accounted_input_tokens == 105
    assert budget.stop_reason == "LIMIT_EXCEEDED"
    assert "limit_exceeded:input_tokens" in budget.stop_details

    rejected = budget.reserve(
        _claim(input_tokens=1, output_tokens=0, cost=0),
        priority=BudgetPriority.HIGH,
    )
    assert rejected.decision is BudgetDecision.REJECTED
    assert "limit_reached:input_tokens" in rejected.reasons
    assert budget.stop_reason == "LIMIT_EXCEEDED"
    assert budget.stop_details == (
        "near_limit:input_tokens",
        "limit_exceeded:input_tokens",
        "limit_reached:input_tokens",
    )


def test_reserve_or_raise_distinguishes_graceful_stop_from_hard_exhaustion():
    budget = AnalysisBudget(
        _limits(max_requests=10, max_input_tokens=100, max_output_tokens=0, max_cost=0),
        clock=ManualClock(),
    )
    initial = budget.reserve_or_raise(
        _claim(input_tokens=85, output_tokens=0, cost=0),
        priority=BudgetPriority.HIGH,
    )
    budget.commit(initial, ActualUsage(input_tokens=85, output_tokens=0, cost=0))

    with pytest.raises(LowPriorityBudgetStop) as stopped:
        budget.reserve_or_raise(
            _claim(input_tokens=5, output_tokens=0, cost=0),
            priority=BudgetPriority.LOW,
        )
    assert stopped.value.retryable is False
    assert stopped.value.reasons == ("near_limit:input_tokens",)

    final = budget.reserve_or_raise(
        _claim(input_tokens=15, output_tokens=0, cost=0),
        priority=BudgetPriority.HIGH,
    )
    budget.commit(final, ActualUsage(input_tokens=15, output_tokens=0, cost=0))
    with pytest.raises(BudgetExhaustedError) as exhausted:
        budget.reserve_or_raise(
            _claim(input_tokens=1, output_tokens=0, cost=0),
            priority=BudgetPriority.HIGH,
        )
    assert exhausted.value.retryable is False
    assert exhausted.value.reasons == ("limit_reached:input_tokens",)


def test_existing_reservations_can_commit_after_another_call_exceeds_limit():
    budget = AnalysisBudget(
        _limits(max_input_tokens=100, max_output_tokens=0, max_cost=0),
        clock=ManualClock(),
    )
    left = budget.reserve(
        _claim(input_tokens=50, output_tokens=0, cost=0),
        priority=BudgetPriority.HIGH,
    ).reservation
    right = budget.reserve(
        _claim(input_tokens=50, output_tokens=0, cost=0),
        priority=BudgetPriority.HIGH,
    ).reservation
    assert left is not None and right is not None

    budget.commit(left, ActualUsage(input_tokens=70, output_tokens=0, cost=0))
    assert budget.reserve(
        _claim(input_tokens=1, output_tokens=0, cost=0),
        priority=BudgetPriority.HIGH,
    ).decision is BudgetDecision.REJECTED
    final = budget.commit(right, ActualUsage(input_tokens=45, output_tokens=0, cost=0))
    assert final.accounted_input_tokens == 115
    assert final.committed_reservations == 2


def test_parallel_reservations_do_not_oversell_request_capacity():
    budget = AnalysisBudget(
        _limits(
            max_input_tokens=0,
            max_output_tokens=0,
            max_cost=0,
            max_requests=10,
            max_strong_model_calls=0,
        ),
        clock=ManualClock(),
    )
    claim = _claim(input_tokens=0, output_tokens=0, cost=0)

    def attempt():
        return budget.reserve(claim, priority=BudgetPriority.HIGH)

    with ThreadPoolExecutor(max_workers=32) as pool:
        results = list(pool.map(lambda _: attempt(), range(100)))

    accepted = [item.reservation for item in results if item.allowed]
    assert len(accepted) == 10
    assert sum(item.decision is BudgetDecision.REJECTED for item in results) == 90
    assert len(budget.active_reservations) == 10
    for reservation in accepted:
        assert reservation is not None
        budget.commit(reservation, ActualUsage(input_tokens=0, output_tokens=0, cost=0))
    assert budget.usage.requests == 10
    assert not budget.active_reservations


def test_wall_time_stops_low_priority_near_limit_and_all_new_work_at_limit():
    clock = ManualClock()
    budget = AnalysisBudget(
        _limits(
            max_input_tokens=0,
            max_output_tokens=0,
            max_cost=0,
            max_requests=0,
            max_strong_model_calls=0,
            max_wall_time_minutes=10,
        ),
        clock=clock,
    )
    claim = _claim(input_tokens=0, output_tokens=0, cost=0)
    clock.seconds = 9 * 60
    assert budget.reserve(claim, priority=BudgetPriority.LOW).decision is (
        BudgetDecision.STOP_LOW_PRIORITY
    )
    active = budget.reserve(claim, priority=BudgetPriority.HIGH).reservation
    assert active is not None

    clock.seconds = 11 * 60
    assert budget.reserve(claim, priority=BudgetPriority.HIGH).decision is (
        BudgetDecision.REJECTED
    )
    # A reservation made before the deadline still finishes atomically.
    usage = budget.commit(active, ActualUsage(input_tokens=0, output_tokens=0, cost=0))
    assert usage.wall_time_minutes == pytest.approx(11)
    assert budget.stop_reason == "LIMIT_REACHED"


def test_unknown_usage_is_preserved_and_zero_bound_fails_closed():
    budget = AnalysisBudget(
        _limits(max_input_tokens=100, max_output_tokens=0, max_cost=0),
        clock=ManualClock(),
    )
    reservation = budget.reserve(
        _claim(input_tokens=0, output_tokens=0, cost=0),
        priority=BudgetPriority.HIGH,
    ).reservation
    assert reservation is not None
    usage = budget.commit(reservation, ActualUsage(input_tokens=None, output_tokens=0, cost=0))
    assert usage.input_tokens is None
    assert usage.observed_input_tokens == 0
    assert usage.accounted_input_tokens == 0
    assert usage.unknown_input_token_requests == 1
    assert budget.stop_reason == "UNKNOWN_USAGE"

    rejected = budget.reserve(
        _claim(input_tokens=1, output_tokens=0, cost=0),
        priority=BudgetPriority.HIGH,
    )
    assert rejected.decision is BudgetDecision.REJECTED
    assert rejected.reasons == ("unknown_usage:input_tokens",)

    usage_only = BudgetUsage.from_dict(usage.to_dict())
    resumed = AnalysisBudget.from_usage(_limits(), usage_only, clock=ManualClock())
    assert resumed.reserve(_claim(), priority=BudgetPriority.HIGH).decision is (
        BudgetDecision.REJECTED
    )
    assert resumed.stop_reason == "UNKNOWN_USAGE"


def test_state_and_usage_round_trip_restore_capacity_and_elapsed_time():
    clock = ManualClock(60)
    budget = AnalysisBudget(_limits(max_requests=2), clock=clock)
    committed = budget.reserve(_claim(), priority=BudgetPriority.HIGH).reservation
    assert committed is not None
    budget.commit(committed, ActualUsage(input_tokens=40, output_tokens=None, cost=None))
    pending = budget.reserve(_claim(), priority=BudgetPriority.HIGH).reservation
    assert pending is not None
    clock.seconds = 180

    persisted = json.loads(json.dumps(budget.to_dict(), sort_keys=True))
    restored_clock = ManualClock(1_000)
    restored = AnalysisBudget.from_dict(persisted, clock=restored_clock)
    assert restored.usage.wall_time_minutes == pytest.approx(2)
    assert restored.usage.to_dict() == BudgetUsage.from_dict(persisted["usage"]).to_dict()
    assert restored.active_reservations == (pending,)
    assert restored.reserve(_claim(), priority=BudgetPriority.HIGH).decision is (
        BudgetDecision.REJECTED
    )

    restored.commit(pending, ActualUsage(input_tokens=30, output_tokens=10, cost=0.2))
    assert restored.usage.requests == 2
    assert restored.usage.input_tokens == 70
    assert restored.usage.output_tokens is None

    restored_clock.seconds += 60
    usage_only = BudgetUsage.from_dict(restored.usage.to_dict())
    resumed = AnalysisBudget.from_usage(_limits(max_requests=3), usage_only, clock=ManualClock())
    assert resumed.usage.wall_time_minutes == pytest.approx(3)
    assert resumed.usage.requests == 2


def test_persisted_usage_rejects_tampered_actual_projection():
    value = BudgetUsage(
        observed_input_tokens=10,
        accounted_input_tokens=20,
        unknown_input_token_requests=1,
        requests=1,
    ).to_dict()
    value["actual"]["input_tokens"] = 10
    with pytest.raises(ValueError, match="conflicts"):
        BudgetUsage.from_dict(value)


def test_stop_history_escalates_from_low_priority_to_limit_and_survives_round_trip():
    budget = AnalysisBudget(
        _limits(max_input_tokens=100, max_output_tokens=0, max_cost=0),
        clock=ManualClock(),
    )
    initial = budget.reserve(
        _claim(input_tokens=85, output_tokens=0, cost=0),
        priority=BudgetPriority.HIGH,
    ).reservation
    assert initial is not None
    budget.commit(initial, ActualUsage(input_tokens=85, output_tokens=0, cost=0))

    stopped = budget.reserve(
        _claim(input_tokens=5, output_tokens=0, cost=0),
        priority=BudgetPriority.LOW,
    )
    assert stopped.decision is BudgetDecision.STOP_LOW_PRIORITY
    assert budget.stop_reason == "STOP_LOW_PRIORITY"
    assert budget.stop_details == ("near_limit:input_tokens",)

    terminal = budget.reserve(
        _claim(input_tokens=15, output_tokens=0, cost=0),
        priority=BudgetPriority.HIGH,
    ).reservation
    assert terminal is not None
    budget.commit(terminal, ActualUsage(input_tokens=15, output_tokens=0, cost=0))
    assert budget.stop_reason == "LIMIT_REACHED"
    assert budget.stop_details == (
        "near_limit:input_tokens",
        "limit_reached:input_tokens",
    )

    # A later hard rejection repeats the terminal fact without replacing the
    # earlier low-priority stop or downgrading the derived reason.
    assert budget.reserve(
        _claim(input_tokens=1, output_tokens=0, cost=0),
        priority=BudgetPriority.HIGH,
    ).decision is BudgetDecision.REJECTED
    assert budget.stop_details == (
        "near_limit:input_tokens",
        "limit_reached:input_tokens",
    )

    persisted = json.loads(json.dumps(budget.to_dict(), sort_keys=True))
    restored = AnalysisBudget.from_dict(persisted, clock=ManualClock())
    assert restored.stop_reason == "LIMIT_REACHED"
    assert restored.stop_details == budget.stop_details
    assert restored.to_dict()["stop_reason"] == persisted["stop_reason"]
    assert restored.to_dict()["stop_details"] == persisted["stop_details"]


def test_stop_history_escalates_from_low_priority_to_unknown_usage():
    budget = AnalysisBudget(
        _limits(max_input_tokens=100, max_output_tokens=0, max_cost=0),
        clock=ManualClock(),
    )
    initial = budget.reserve(
        _claim(input_tokens=85, output_tokens=0, cost=0),
        priority=BudgetPriority.HIGH,
    ).reservation
    assert initial is not None
    budget.commit(initial, ActualUsage(input_tokens=85, output_tokens=0, cost=0))
    assert budget.reserve(
        _claim(input_tokens=5, output_tokens=0, cost=0),
        priority=BudgetPriority.MEDIUM,
    ).decision is BudgetDecision.STOP_LOW_PRIORITY

    unknown = budget.reserve(
        _claim(input_tokens=0, output_tokens=0, cost=0),
        priority=BudgetPriority.HIGH,
    ).reservation
    assert unknown is not None
    budget.commit(unknown, ActualUsage(input_tokens=None, output_tokens=0, cost=0))

    assert budget.stop_reason == "UNKNOWN_USAGE"
    assert budget.stop_details == (
        "near_limit:input_tokens",
        "unknown_usage:input_tokens",
    )
    rejected = budget.reserve(
        _claim(input_tokens=1, output_tokens=0, cost=0),
        priority=BudgetPriority.HIGH,
    )
    assert rejected.reasons == ("unknown_usage:input_tokens",)
    assert budget.stop_details == (
        "near_limit:input_tokens",
        "unknown_usage:input_tokens",
    )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda state: state.update(stop_reason="STOP_LOW_PRIORITY"),
            "most severe persisted stop detail",
        ),
        (
            lambda state: state["stop_details"].append("unknown_usage:not_a_dimension"),
            "invalid budget stop detail",
        ),
        (
            lambda state: state["stop_details"].append(state["stop_details"][0]),
            "must not contain duplicates",
        ),
    ],
)
def test_state_restore_rejects_tampered_terminal_stop_semantics(mutation, message):
    budget = AnalysisBudget(
        _limits(max_input_tokens=100, max_output_tokens=0, max_cost=0),
        clock=ManualClock(),
    )
    reservation = budget.reserve(
        _claim(input_tokens=0, output_tokens=0, cost=0),
        priority=BudgetPriority.HIGH,
    ).reservation
    assert reservation is not None
    budget.commit(reservation, ActualUsage(input_tokens=None, output_tokens=0, cost=0))
    state = json.loads(json.dumps(budget.to_dict(), sort_keys=True))

    mutation(state)
    with pytest.raises(ValueError, match=message):
        AnalysisBudget.from_dict(state, clock=ManualClock())

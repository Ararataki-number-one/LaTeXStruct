# -*- coding: utf-8 -*-
"""Thread-safe, persistent budgets for atomic analysis model calls.

The host reserves a conservative upper bound before starting a transport.  A
successful reservation owns that capacity until it is committed or cancelled.
Commit always succeeds for an existing reservation, even when another in-flight
call has already exhausted the budget; this lets the host finish and persist an
atomic call without permitting any new work after the hard limit is reached.

Provider usage may be unavailable.  Unknown values remain unknown in the
reported actual usage and are charged at their reserved upper bound for budget
enforcement.  A caller that cannot supply a positive upper bound for a limited
dimension fails closed after committing unknown usage for that dimension.
"""

from __future__ import annotations

import math
import threading
import time
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Mapping


ANALYSIS_BUDGET_SCHEMA_VERSION = "analysis-budget-v1"


def _require_non_negative_int(name: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")


def _require_non_negative_number(name: str, value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a finite non-negative number")
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise ValueError(f"{name} must be a finite non-negative number")
    return result


def _require_exact_keys(value: Mapping[str, object], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ValueError(f"invalid {label} keys; missing={missing}, extra={extra}")


def _coerce_mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be a mapping")
    return value


def _exceeds(value: float, maximum: float) -> bool:
    # A false-positive stop caused by floating-point rounding is safer than
    # admitting work beyond a hard monetary limit.
    return value > maximum


@dataclass(frozen=True, slots=True)
class BudgetLimits:
    """Immutable limits captured by an analysis run snapshot.

    Zero disables token, cost, request, or strong-model limits.  Wall time is
    always bounded and therefore must be finite and strictly positive.
    """

    max_input_tokens: int
    max_output_tokens: int
    max_cost: float
    max_requests: int
    max_strong_model_calls: int
    max_wall_time_minutes: float

    def __post_init__(self) -> None:
        for name in (
            "max_input_tokens",
            "max_output_tokens",
            "max_requests",
            "max_strong_model_calls",
        ):
            _require_non_negative_int(name, getattr(self, name))
        object.__setattr__(self, "max_cost", _require_non_negative_number("max_cost", self.max_cost))
        wall_time = _require_non_negative_number(
            "max_wall_time_minutes", self.max_wall_time_minutes
        )
        if wall_time <= 0:
            raise ValueError("max_wall_time_minutes must be greater than zero")
        object.__setattr__(self, "max_wall_time_minutes", wall_time)

    def to_dict(self) -> dict[str, int | float]:
        return {
            "max_input_tokens": self.max_input_tokens,
            "max_output_tokens": self.max_output_tokens,
            "max_cost": self.max_cost,
            "max_requests": self.max_requests,
            "max_strong_model_calls": self.max_strong_model_calls,
            "max_wall_time_minutes": self.max_wall_time_minutes,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> BudgetLimits:
        expected = {
            "max_input_tokens",
            "max_output_tokens",
            "max_cost",
            "max_requests",
            "max_strong_model_calls",
            "max_wall_time_minutes",
        }
        _require_exact_keys(value, expected, "budget limits")
        return cls(**dict(value))  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class BudgetClaim:
    """Conservative upper bounds reserved for one atomic transport unit."""

    input_tokens: int = 0
    output_tokens: int = 0
    cost: float = 0.0
    requests: int = 1
    strong_model_calls: int = 0

    def __post_init__(self) -> None:
        for name in ("input_tokens", "output_tokens", "requests", "strong_model_calls"):
            _require_non_negative_int(name, getattr(self, name))
        if self.requests <= 0:
            raise ValueError("requests must be greater than zero for an atomic call")
        if self.strong_model_calls > self.requests:
            raise ValueError("strong_model_calls cannot exceed requests")
        object.__setattr__(self, "cost", _require_non_negative_number("cost", self.cost))

    def to_dict(self) -> dict[str, int | float]:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cost": self.cost,
            "requests": self.requests,
            "strong_model_calls": self.strong_model_calls,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> BudgetClaim:
        expected = {
            "input_tokens",
            "output_tokens",
            "cost",
            "requests",
            "strong_model_calls",
        }
        _require_exact_keys(value, expected, "budget claim")
        return cls(**dict(value))  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class ActualUsage:
    """Provider-reported usage for a committed reservation.

    ``None`` is preserved as unknown and is never silently converted to zero.
    Request and strong-model counts are host-owned and come from the claim.
    """

    input_tokens: int | None = None
    output_tokens: int | None = None
    cost: float | None = None

    def __post_init__(self) -> None:
        for name in ("input_tokens", "output_tokens"):
            value = getattr(self, name)
            if value is not None:
                _require_non_negative_int(name, value)
        if self.cost is not None:
            object.__setattr__(self, "cost", _require_non_negative_number("cost", self.cost))

    def to_dict(self) -> dict[str, int | float | None]:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cost": self.cost,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> ActualUsage:
        expected = {"input_tokens", "output_tokens", "cost"}
        _require_exact_keys(value, expected, "actual usage")
        return cls(**dict(value))  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class BudgetUsage:
    """Immutable, JSON-serializable committed usage snapshot."""

    observed_input_tokens: int = 0
    observed_output_tokens: int = 0
    observed_cost: float = 0.0
    accounted_input_tokens: int = 0
    accounted_output_tokens: int = 0
    accounted_cost: float = 0.0
    requests: int = 0
    strong_model_calls: int = 0
    unknown_input_token_requests: int = 0
    unknown_output_token_requests: int = 0
    unknown_cost_requests: int = 0
    committed_reservations: int = 0
    cancelled_reservations: int = 0
    wall_time_minutes: float = 0.0

    def __post_init__(self) -> None:
        integer_names = (
            "observed_input_tokens",
            "observed_output_tokens",
            "accounted_input_tokens",
            "accounted_output_tokens",
            "requests",
            "strong_model_calls",
            "unknown_input_token_requests",
            "unknown_output_token_requests",
            "unknown_cost_requests",
            "committed_reservations",
            "cancelled_reservations",
        )
        for name in integer_names:
            _require_non_negative_int(name, getattr(self, name))
        object.__setattr__(
            self,
            "observed_cost",
            _require_non_negative_number("observed_cost", self.observed_cost),
        )
        object.__setattr__(
            self,
            "accounted_cost",
            _require_non_negative_number("accounted_cost", self.accounted_cost),
        )
        object.__setattr__(
            self,
            "wall_time_minutes",
            _require_non_negative_number("wall_time_minutes", self.wall_time_minutes),
        )
        if self.accounted_input_tokens < self.observed_input_tokens:
            raise ValueError("accounted_input_tokens cannot be below observed usage")
        if self.accounted_output_tokens < self.observed_output_tokens:
            raise ValueError("accounted_output_tokens cannot be below observed usage")
        if self.accounted_cost + 1e-12 < self.observed_cost:
            raise ValueError("accounted_cost cannot be below observed usage")
        if self.strong_model_calls > self.requests:
            raise ValueError("strong_model_calls cannot exceed requests")
        if self.committed_reservations > self.requests:
            raise ValueError("committed_reservations cannot exceed requests")
        for name in (
            "unknown_input_token_requests",
            "unknown_output_token_requests",
            "unknown_cost_requests",
        ):
            if getattr(self, name) > self.requests:
                raise ValueError(f"{name} cannot exceed requests")

    @property
    def input_tokens(self) -> int | None:
        if self.unknown_input_token_requests:
            return None
        return self.observed_input_tokens

    @property
    def output_tokens(self) -> int | None:
        if self.unknown_output_token_requests:
            return None
        return self.observed_output_tokens

    @property
    def cost(self) -> float | None:
        if self.unknown_cost_requests:
            return None
        return self.observed_cost

    def to_dict(self) -> dict[str, object]:
        return {
            "observed": {
                "input_tokens": self.observed_input_tokens,
                "output_tokens": self.observed_output_tokens,
                "cost": self.observed_cost,
            },
            "actual": {
                "input_tokens": self.input_tokens,
                "output_tokens": self.output_tokens,
                "cost": self.cost,
            },
            "accounted": {
                "input_tokens": self.accounted_input_tokens,
                "output_tokens": self.accounted_output_tokens,
                "cost": self.accounted_cost,
            },
            "requests": self.requests,
            "strong_model_calls": self.strong_model_calls,
            "unknown": {
                "input_token_requests": self.unknown_input_token_requests,
                "output_token_requests": self.unknown_output_token_requests,
                "cost_requests": self.unknown_cost_requests,
            },
            "committed_reservations": self.committed_reservations,
            "cancelled_reservations": self.cancelled_reservations,
            "wall_time_minutes": self.wall_time_minutes,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> BudgetUsage:
        expected = {
            "observed",
            "actual",
            "accounted",
            "requests",
            "strong_model_calls",
            "unknown",
            "committed_reservations",
            "cancelled_reservations",
            "wall_time_minutes",
        }
        _require_exact_keys(value, expected, "budget usage")
        observed = _coerce_mapping(value["observed"], "observed usage")
        actual = _coerce_mapping(value["actual"], "actual usage")
        accounted = _coerce_mapping(value["accounted"], "accounted usage")
        unknown = _coerce_mapping(value["unknown"], "unknown usage")
        _require_exact_keys(observed, {"input_tokens", "output_tokens", "cost"}, "observed usage")
        _require_exact_keys(actual, {"input_tokens", "output_tokens", "cost"}, "actual usage")
        _require_exact_keys(
            accounted, {"input_tokens", "output_tokens", "cost"}, "accounted usage"
        )
        _require_exact_keys(
            unknown,
            {"input_token_requests", "output_token_requests", "cost_requests"},
            "unknown usage",
        )
        result = cls(
            observed_input_tokens=observed["input_tokens"],  # type: ignore[arg-type]
            observed_output_tokens=observed["output_tokens"],  # type: ignore[arg-type]
            observed_cost=observed["cost"],  # type: ignore[arg-type]
            accounted_input_tokens=accounted["input_tokens"],  # type: ignore[arg-type]
            accounted_output_tokens=accounted["output_tokens"],  # type: ignore[arg-type]
            accounted_cost=accounted["cost"],  # type: ignore[arg-type]
            requests=value["requests"],  # type: ignore[arg-type]
            strong_model_calls=value["strong_model_calls"],  # type: ignore[arg-type]
            unknown_input_token_requests=unknown["input_token_requests"],  # type: ignore[arg-type]
            unknown_output_token_requests=unknown["output_token_requests"],  # type: ignore[arg-type]
            unknown_cost_requests=unknown["cost_requests"],  # type: ignore[arg-type]
            committed_reservations=value["committed_reservations"],  # type: ignore[arg-type]
            cancelled_reservations=value["cancelled_reservations"],  # type: ignore[arg-type]
            wall_time_minutes=value["wall_time_minutes"],  # type: ignore[arg-type]
        )
        expected_actual = {
            "input_tokens": result.input_tokens,
            "output_tokens": result.output_tokens,
            "cost": result.cost,
        }
        if dict(actual) != expected_actual:
            raise ValueError("persisted actual usage conflicts with unknown-usage counters")
        return result


class BudgetPriority(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class BudgetDecision(str, Enum):
    RESERVED = "RESERVED"
    STOP_LOW_PRIORITY = "STOP_LOW_PRIORITY"
    REJECTED = "REJECTED"


@dataclass(frozen=True, slots=True)
class BudgetReservation:
    reservation_id: str
    claim: BudgetClaim
    priority: BudgetPriority
    created_wall_time_minutes: float

    def __post_init__(self) -> None:
        if not self.reservation_id.strip():
            raise ValueError("reservation_id cannot be empty")
        object.__setattr__(
            self,
            "created_wall_time_minutes",
            _require_non_negative_number(
                "created_wall_time_minutes", self.created_wall_time_minutes
            ),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "reservation_id": self.reservation_id,
            "claim": self.claim.to_dict(),
            "priority": self.priority.value,
            "created_wall_time_minutes": self.created_wall_time_minutes,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> BudgetReservation:
        expected = {"reservation_id", "claim", "priority", "created_wall_time_minutes"}
        _require_exact_keys(value, expected, "budget reservation")
        return cls(
            reservation_id=str(value["reservation_id"]),
            claim=BudgetClaim.from_dict(_coerce_mapping(value["claim"], "claim")),
            priority=BudgetPriority(str(value["priority"])),
            created_wall_time_minutes=value["created_wall_time_minutes"],  # type: ignore[arg-type]
        )


@dataclass(frozen=True, slots=True)
class ReservationResult:
    decision: BudgetDecision
    reservation: BudgetReservation | None = None
    reasons: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (self.decision is BudgetDecision.RESERVED) != (self.reservation is not None):
            raise ValueError("only RESERVED decisions may contain a reservation")

    @property
    def allowed(self) -> bool:
        return self.decision is BudgetDecision.RESERVED


class UnknownReservationError(KeyError):
    """Raised when a reservation was already committed, cancelled, or never existed."""


class BudgetExhaustedError(RuntimeError):
    """Non-retryable hard budget rejection for orchestrator failure routing."""

    retryable = False

    def __init__(self, reasons: tuple[str, ...]) -> None:
        self.reasons = tuple(reasons)
        detail = ", ".join(self.reasons) or "unspecified budget limit"
        super().__init__(f"analysis budget exhausted: {detail}")


class LowPriorityBudgetStop(RuntimeError):
    """Control-flow signal for a graceful LOW/MEDIUM queue stop near a limit."""

    retryable = False

    def __init__(self, reasons: tuple[str, ...]) -> None:
        self.reasons = tuple(reasons)
        detail = ", ".join(self.reasons) or "near budget limit"
        super().__init__(f"stop low-priority analysis work: {detail}")


class AnalysisBudget:
    """Concurrency-safe reservation and accounting authority for one run."""

    _LIMIT_FIELDS = (
        ("input_tokens", "max_input_tokens"),
        ("output_tokens", "max_output_tokens"),
        ("cost", "max_cost"),
        ("requests", "max_requests"),
        ("strong_model_calls", "max_strong_model_calls"),
    )
    _UNKNOWN_DIMENSIONS = frozenset({"input_tokens", "output_tokens", "cost"})
    _STOP_REASON_SEVERITY = {
        "STOP_LOW_PRIORITY": 1,
        "LIMIT_REACHED": 2,
        "LIMIT_EXCEEDED": 3,
        "UNKNOWN_USAGE": 4,
    }
    _STOP_DETAIL_REASON = {
        "near_limit": "STOP_LOW_PRIORITY",
        "limit_reached": "LIMIT_REACHED",
        "reservation_exceeds": "LIMIT_REACHED",
        "limit_exceeded": "LIMIT_EXCEEDED",
        "unknown_usage": "UNKNOWN_USAGE",
    }
    _STOP_DETAIL_DIMENSIONS = {
        "near_limit": frozenset(
            {
                "input_tokens",
                "output_tokens",
                "cost",
                "requests",
                "strong_model_calls",
                "wall_time_minutes",
            }
        ),
        "limit_reached": frozenset(
            {
                "input_tokens",
                "output_tokens",
                "cost",
                "requests",
                "strong_model_calls",
                "wall_time_minutes",
            }
        ),
        "reservation_exceeds": frozenset(
            {
                "input_tokens",
                "output_tokens",
                "cost",
                "requests",
                "strong_model_calls",
            }
        ),
        "limit_exceeded": frozenset(
            {
                "input_tokens",
                "output_tokens",
                "cost",
                "requests",
                "strong_model_calls",
            }
        ),
        "unknown_usage": _UNKNOWN_DIMENSIONS,
    }

    def __init__(
        self,
        limits: BudgetLimits,
        *,
        usage: BudgetUsage | None = None,
        low_priority_threshold: float = 0.90,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if (
            isinstance(low_priority_threshold, bool)
            or not isinstance(low_priority_threshold, (int, float))
            or not math.isfinite(float(low_priority_threshold))
            or not 0 < float(low_priority_threshold) <= 1
        ):
            raise ValueError("low_priority_threshold must be within (0, 1]")
        if not callable(clock):
            raise ValueError("clock must be callable")
        initial_usage = usage or BudgetUsage()
        started_at = float(clock())
        if not math.isfinite(started_at):
            raise ValueError("clock must return a finite number")

        self._limits = limits
        self._threshold = float(low_priority_threshold)
        self._clock = clock
        self._clock_started_at = started_at
        self._persisted_wall_time = initial_usage.wall_time_minutes
        self._lock = threading.RLock()
        self._reservations: dict[str, BudgetReservation] = {}
        self._stop_reason: str | None = None
        self._stop_details: tuple[str, ...] = ()
        self._unbounded_unknown_dimensions: set[str] = set()

        self._observed_input_tokens = initial_usage.observed_input_tokens
        self._observed_output_tokens = initial_usage.observed_output_tokens
        self._observed_cost = initial_usage.observed_cost
        self._accounted_input_tokens = initial_usage.accounted_input_tokens
        self._accounted_output_tokens = initial_usage.accounted_output_tokens
        self._accounted_cost = initial_usage.accounted_cost
        self._requests = initial_usage.requests
        self._strong_model_calls = initial_usage.strong_model_calls
        self._unknown_input_token_requests = initial_usage.unknown_input_token_requests
        self._unknown_output_token_requests = initial_usage.unknown_output_token_requests
        self._unknown_cost_requests = initial_usage.unknown_cost_requests
        self._committed_reservations = initial_usage.committed_reservations
        self._cancelled_reservations = initial_usage.cancelled_reservations
        # A usage-only checkpoint no longer carries each reservation's upper
        # bound.  Unknown provider usage must therefore resume fail-closed for
        # every limited dimension.  Full-state restoration below replaces this
        # conservative projection with its persisted per-run uncertainty set.
        if self._unknown_input_token_requests and limits.max_input_tokens > 0:
            self._unbounded_unknown_dimensions.add("input_tokens")
        if self._unknown_output_token_requests and limits.max_output_tokens > 0:
            self._unbounded_unknown_dimensions.add("output_tokens")
        if self._unknown_cost_requests and limits.max_cost > 0:
            self._unbounded_unknown_dimensions.add("cost")

    @property
    def limits(self) -> BudgetLimits:
        return self._limits

    @property
    def low_priority_threshold(self) -> float:
        return self._threshold

    @property
    def stop_reason(self) -> str | None:
        with self._lock:
            return self._stop_reason

    @property
    def stop_details(self) -> tuple[str, ...]:
        with self._lock:
            return self._stop_details

    @property
    def active_reservations(self) -> tuple[BudgetReservation, ...]:
        with self._lock:
            return tuple(self._reservations[key] for key in sorted(self._reservations))

    def _wall_time_unlocked(self) -> float:
        now = float(self._clock())
        if not math.isfinite(now) or now < self._clock_started_at:
            raise RuntimeError("clock moved backwards or returned a non-finite value")
        return self._persisted_wall_time + (now - self._clock_started_at) / 60.0

    def _usage_unlocked(self) -> BudgetUsage:
        return BudgetUsage(
            observed_input_tokens=self._observed_input_tokens,
            observed_output_tokens=self._observed_output_tokens,
            observed_cost=self._observed_cost,
            accounted_input_tokens=self._accounted_input_tokens,
            accounted_output_tokens=self._accounted_output_tokens,
            accounted_cost=self._accounted_cost,
            requests=self._requests,
            strong_model_calls=self._strong_model_calls,
            unknown_input_token_requests=self._unknown_input_token_requests,
            unknown_output_token_requests=self._unknown_output_token_requests,
            unknown_cost_requests=self._unknown_cost_requests,
            committed_reservations=self._committed_reservations,
            cancelled_reservations=self._cancelled_reservations,
            wall_time_minutes=self._wall_time_unlocked(),
        )

    @property
    def usage(self) -> BudgetUsage:
        with self._lock:
            return self._usage_unlocked()

    def _accounted_values_unlocked(self) -> dict[str, int | float]:
        return {
            "input_tokens": self._accounted_input_tokens,
            "output_tokens": self._accounted_output_tokens,
            "cost": self._accounted_cost,
            "requests": self._requests,
            "strong_model_calls": self._strong_model_calls,
        }

    def _reserved_values_unlocked(self) -> dict[str, int | float]:
        result: dict[str, int | float] = {
            "input_tokens": 0,
            "output_tokens": 0,
            "cost": 0.0,
            "requests": 0,
            "strong_model_calls": 0,
        }
        for reservation in self._reservations.values():
            for name in result:
                result[name] += getattr(reservation.claim, name)
        return result

    def _capacity_reasons_unlocked(self, claim: BudgetClaim) -> tuple[str, ...]:
        reasons: list[str] = []
        for dimension in sorted(self._unbounded_unknown_dimensions):
            limit_name = dict(self._LIMIT_FIELDS)[dimension]
            if getattr(self._limits, limit_name) > 0:
                reasons.append(f"unknown_usage:{dimension}")

        wall_time = self._wall_time_unlocked()
        if wall_time >= self._limits.max_wall_time_minutes:
            reasons.append("limit_reached:wall_time_minutes")

        accounted = self._accounted_values_unlocked()
        reserved = self._reserved_values_unlocked()
        for dimension, limit_name in self._LIMIT_FIELDS:
            maximum = getattr(self._limits, limit_name)
            if maximum <= 0:
                continue
            current = accounted[dimension] + reserved[dimension]
            projected = current + getattr(claim, dimension)
            if current >= maximum:
                reasons.append(f"limit_reached:{dimension}")
            elif _exceeds(float(projected), float(maximum)):
                reasons.append(f"reservation_exceeds:{dimension}")
        return tuple(reasons)

    def _near_limit_reasons_unlocked(self, claim: BudgetClaim) -> tuple[str, ...]:
        reasons: list[str] = []
        wall_ratio = self._wall_time_unlocked() / self._limits.max_wall_time_minutes
        if wall_ratio >= self._threshold:
            reasons.append("near_limit:wall_time_minutes")

        accounted = self._accounted_values_unlocked()
        reserved = self._reserved_values_unlocked()
        for dimension, limit_name in self._LIMIT_FIELDS:
            maximum = getattr(self._limits, limit_name)
            if maximum <= 0:
                continue
            projected = accounted[dimension] + reserved[dimension] + getattr(claim, dimension)
            if float(projected) / float(maximum) >= self._threshold:
                reasons.append(f"near_limit:{dimension}")
        return tuple(reasons)

    @classmethod
    def _reason_for_stop_details(cls, details: tuple[str, ...]) -> str | None:
        """Validate stop details and derive their most severe terminal reason."""

        most_severe_reason: str | None = None
        most_severe_rank = 0
        for detail in details:
            prefix, separator, dimension = detail.partition(":")
            if (
                not separator
                or prefix not in cls._STOP_DETAIL_REASON
                or dimension not in cls._STOP_DETAIL_DIMENSIONS[prefix]
            ):
                raise ValueError(f"invalid budget stop detail: {detail!r}")
            reason = cls._STOP_DETAIL_REASON[prefix]
            rank = cls._STOP_REASON_SEVERITY[reason]
            if rank > most_severe_rank:
                most_severe_reason = reason
                most_severe_rank = rank
        return most_severe_reason

    @classmethod
    def _validate_stop_state(
        cls,
        reason: str | None,
        details: tuple[str, ...],
    ) -> None:
        if reason is not None and reason not in cls._STOP_REASON_SEVERITY:
            raise ValueError(f"invalid budget stop_reason: {reason!r}")
        if len(set(details)) != len(details):
            raise ValueError("stop_details must not contain duplicates")
        derived_reason = cls._reason_for_stop_details(details)
        if reason != derived_reason:
            raise ValueError(
                "stop_reason does not match the most severe persisted stop detail"
            )

    def _record_stop_unlocked(self, reason: str, details: tuple[str, ...]) -> None:
        incoming_reason = self._reason_for_stop_details(details)
        if incoming_reason != reason:
            raise RuntimeError("internal budget stop reason conflicts with its details")

        # Preserve the first-seen order so each new stop produces an auditable,
        # append-only history.  The current terminal reason is always derived
        # from the complete history and therefore can escalate but never
        # silently downgrade after a later reserve or commit.
        merged_details = tuple(dict.fromkeys((*self._stop_details, *details)))
        merged_reason = self._reason_for_stop_details(merged_details)
        self._stop_details = merged_details
        self._stop_reason = merged_reason

    def reserve(
        self,
        claim: BudgetClaim,
        *,
        priority: BudgetPriority | str = BudgetPriority.MEDIUM,
    ) -> ReservationResult:
        """Atomically reserve capacity or return an auditable stop decision."""

        resolved_priority = BudgetPriority(priority)
        with self._lock:
            hard_reasons = self._capacity_reasons_unlocked(claim)
            if hard_reasons:
                reason = (
                    "UNKNOWN_USAGE" if any(item.startswith("unknown_usage:") for item in hard_reasons)
                    else "LIMIT_REACHED"
                )
                self._record_stop_unlocked(reason, hard_reasons)
                return ReservationResult(BudgetDecision.REJECTED, reasons=hard_reasons)

            near_reasons = self._near_limit_reasons_unlocked(claim)
            if resolved_priority in {BudgetPriority.LOW, BudgetPriority.MEDIUM} and near_reasons:
                self._record_stop_unlocked("STOP_LOW_PRIORITY", near_reasons)
                return ReservationResult(
                    BudgetDecision.STOP_LOW_PRIORITY,
                    reasons=near_reasons,
                )

            reservation = BudgetReservation(
                reservation_id=uuid.uuid4().hex,
                claim=claim,
                priority=resolved_priority,
                created_wall_time_minutes=self._wall_time_unlocked(),
            )
            self._reservations[reservation.reservation_id] = reservation
            return ReservationResult(BudgetDecision.RESERVED, reservation=reservation)

    def reserve_or_raise(
        self,
        claim: BudgetClaim,
        *,
        priority: BudgetPriority | str = BudgetPriority.MEDIUM,
    ) -> BudgetReservation:
        """Reserve capacity or raise an explicit, non-retryable control signal."""

        result = self.reserve(claim, priority=priority)
        if result.decision is BudgetDecision.REJECTED:
            raise BudgetExhaustedError(result.reasons)
        if result.decision is BudgetDecision.STOP_LOW_PRIORITY:
            raise LowPriorityBudgetStop(result.reasons)
        if result.reservation is None:  # Defensive against an invalid future result variant.
            raise RuntimeError("reserved budget result is missing its reservation")
        return result.reservation

    def _resolve_reservation_unlocked(
        self, reservation: BudgetReservation | str
    ) -> BudgetReservation:
        reservation_id = (
            reservation.reservation_id
            if isinstance(reservation, BudgetReservation)
            else str(reservation)
        )
        try:
            stored = self._reservations[reservation_id]
        except KeyError as exc:
            raise UnknownReservationError(reservation_id) from exc
        if isinstance(reservation, BudgetReservation) and reservation != stored:
            raise ValueError("reservation payload does not match the stored reservation")
        return stored

    def _record_terminal_limit_unlocked(self) -> None:
        reasons: list[str] = []
        exceeded = False
        if self._wall_time_unlocked() >= self._limits.max_wall_time_minutes:
            reasons.append("limit_reached:wall_time_minutes")
        accounted = self._accounted_values_unlocked()
        for dimension, limit_name in self._LIMIT_FIELDS:
            maximum = getattr(self._limits, limit_name)
            if maximum <= 0:
                continue
            current = float(accounted[dimension])
            if _exceeds(current, float(maximum)):
                reasons.append(f"limit_exceeded:{dimension}")
                exceeded = True
            elif current >= maximum:
                reasons.append(f"limit_reached:{dimension}")
        for dimension in sorted(self._unbounded_unknown_dimensions):
            reasons.append(f"unknown_usage:{dimension}")
        if reasons:
            reason = "UNKNOWN_USAGE" if self._unbounded_unknown_dimensions else (
                "LIMIT_EXCEEDED" if exceeded else "LIMIT_REACHED"
            )
            self._record_stop_unlocked(reason, tuple(reasons))

    def commit(
        self,
        reservation: BudgetReservation | str,
        actual: ActualUsage | None = None,
    ) -> BudgetUsage:
        """Commit an in-flight atomic call, even if the budget is now exhausted."""

        actual_usage = actual or ActualUsage()
        with self._lock:
            stored = self._resolve_reservation_unlocked(reservation)
            del self._reservations[stored.reservation_id]
            claim = stored.claim

            self._requests += claim.requests
            self._strong_model_calls += claim.strong_model_calls
            self._committed_reservations += 1

            if actual_usage.input_tokens is None:
                self._accounted_input_tokens += claim.input_tokens
                self._unknown_input_token_requests += claim.requests
                if claim.input_tokens == 0 and self._limits.max_input_tokens > 0:
                    self._unbounded_unknown_dimensions.add("input_tokens")
            else:
                self._observed_input_tokens += actual_usage.input_tokens
                self._accounted_input_tokens += actual_usage.input_tokens

            if actual_usage.output_tokens is None:
                self._accounted_output_tokens += claim.output_tokens
                self._unknown_output_token_requests += claim.requests
                if claim.output_tokens == 0 and self._limits.max_output_tokens > 0:
                    self._unbounded_unknown_dimensions.add("output_tokens")
            else:
                self._observed_output_tokens += actual_usage.output_tokens
                self._accounted_output_tokens += actual_usage.output_tokens

            if actual_usage.cost is None:
                self._accounted_cost += claim.cost
                self._unknown_cost_requests += claim.requests
                if claim.cost == 0 and self._limits.max_cost > 0:
                    self._unbounded_unknown_dimensions.add("cost")
            else:
                self._observed_cost += actual_usage.cost
                self._accounted_cost += actual_usage.cost

            self._record_terminal_limit_unlocked()
            return self._usage_unlocked()

    def cancel(self, reservation: BudgetReservation | str) -> BudgetUsage:
        """Release a reservation only when its transport never started."""

        with self._lock:
            stored = self._resolve_reservation_unlocked(reservation)
            del self._reservations[stored.reservation_id]
            self._cancelled_reservations += 1
            return self._usage_unlocked()

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible checkpoint, including in-flight reservations."""

        with self._lock:
            return {
                "schema_version": ANALYSIS_BUDGET_SCHEMA_VERSION,
                "limits": self._limits.to_dict(),
                "usage": self._usage_unlocked().to_dict(),
                "low_priority_threshold": self._threshold,
                "stop_reason": self._stop_reason,
                "stop_details": list(self._stop_details),
                "unbounded_unknown_dimensions": sorted(
                    self._unbounded_unknown_dimensions
                ),
                "reservations": [
                    self._reservations[key].to_dict() for key in sorted(self._reservations)
                ],
            }

    @classmethod
    def from_usage(
        cls,
        limits: BudgetLimits,
        usage: BudgetUsage,
        *,
        low_priority_threshold: float = 0.90,
        clock: Callable[[], float] = time.monotonic,
    ) -> AnalysisBudget:
        """Resume cumulative accounting from a persisted atomic usage snapshot."""

        return cls(
            limits,
            usage=usage,
            low_priority_threshold=low_priority_threshold,
            clock=clock,
        )

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, object],
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> AnalysisBudget:
        expected = {
            "schema_version",
            "limits",
            "usage",
            "low_priority_threshold",
            "stop_reason",
            "stop_details",
            "unbounded_unknown_dimensions",
            "reservations",
        }
        _require_exact_keys(value, expected, "analysis budget state")
        if value["schema_version"] != ANALYSIS_BUDGET_SCHEMA_VERSION:
            raise ValueError("unsupported analysis budget schema_version")
        limits = BudgetLimits.from_dict(_coerce_mapping(value["limits"], "limits"))
        usage = BudgetUsage.from_dict(_coerce_mapping(value["usage"], "usage"))
        budget = cls(
            limits,
            usage=usage,
            low_priority_threshold=value["low_priority_threshold"],  # type: ignore[arg-type]
            clock=clock,
        )
        stop_reason = value["stop_reason"]
        if stop_reason is not None and not isinstance(stop_reason, str):
            raise ValueError("stop_reason must be a string or null")
        stop_details = value["stop_details"]
        dimensions = value["unbounded_unknown_dimensions"]
        reservations = value["reservations"]
        if not isinstance(stop_details, list) or not all(
            isinstance(item, str) for item in stop_details
        ):
            raise ValueError("stop_details must be a list of strings")
        if not isinstance(dimensions, list) or not all(
            isinstance(item, str) for item in dimensions
        ):
            raise ValueError("unbounded_unknown_dimensions must be a list of strings")
        if not set(dimensions).issubset(cls._UNKNOWN_DIMENSIONS):
            raise ValueError("unknown unbounded usage dimension")
        if not isinstance(reservations, list):
            raise ValueError("reservations must be a list")

        persisted_stop_details = tuple(stop_details)
        cls._validate_stop_state(stop_reason, persisted_stop_details)

        with budget._lock:
            budget._stop_reason = stop_reason
            budget._stop_details = persisted_stop_details
            budget._unbounded_unknown_dimensions = set(dimensions)
            for item in reservations:
                reservation = BudgetReservation.from_dict(
                    _coerce_mapping(item, "reservation")
                )
                if reservation.reservation_id in budget._reservations:
                    raise ValueError("duplicate persisted reservation_id")
                budget._reservations[reservation.reservation_id] = reservation
        return budget


__all__ = [
    "ANALYSIS_BUDGET_SCHEMA_VERSION",
    "ActualUsage",
    "AnalysisBudget",
    "BudgetClaim",
    "BudgetDecision",
    "BudgetExhaustedError",
    "BudgetLimits",
    "BudgetPriority",
    "BudgetReservation",
    "BudgetUsage",
    "LowPriorityBudgetStop",
    "ReservationResult",
    "UnknownReservationError",
]

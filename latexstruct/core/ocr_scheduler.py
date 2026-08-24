# -*- coding: utf-8 -*-
"""Bounded scheduling contracts for the staged OCR pipeline.

The objects in this module describe capacity and make scheduling decisions;
they deliberately do not start workers, render pages, or call a model.  Keeping
that boundary makes the host responsible for page identity, persistence, and
all external side effects while still giving every execution backend the same
bounded/back-pressure behaviour.
"""

from __future__ import annotations

import math
import threading
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Mapping, Sequence


class OcrQualityMode(str, Enum):
    FAST = "fast"
    RECOMMENDED = "recommended"
    HIGH = "high"


class OcrStage(str, Enum):
    OBJECT_EXTRACTION = "object_extraction"
    RENDERING = "rendering"
    VISUAL_VERIFICATION = "visual_verification"
    FULL_OCR = "full_ocr"
    PERSISTENCE = "persistence"
    COMPILATION = "compilation"


MODEL_STAGES = frozenset({OcrStage.VISUAL_VERIFICATION, OcrStage.FULL_OCR})
MIN_OBJECT_EXTRACTION_WORKERS = 4
DEFAULT_OBJECT_EXTRACTION_WORKERS = 6
MAX_OBJECT_EXTRACTION_WORKERS = 8


def _quality_mode(value: OcrQualityMode | str) -> OcrQualityMode:
    if isinstance(value, OcrQualityMode):
        return value
    try:
        return OcrQualityMode(str(value or "").strip().lower())
    except ValueError as exc:
        raise ValueError("OCR quality mode must be fast, recommended, or high") from exc


def _stage(value: OcrStage | str) -> OcrStage:
    if isinstance(value, OcrStage):
        return value
    try:
        return OcrStage(str(value or "").strip().lower())
    except ValueError as exc:
        raise ValueError(f"unknown OCR stage: {value!r}") from exc


@dataclass(frozen=True, slots=True)
class StageCapacity:
    """Immutable upper bounds and starting values for one stage.

    ``preferred_batch_min`` is the healthy operating floor.  A verifier may
    fall below it only after an explicit degraded signal or a failed-batch
    split; it can never fall below ``fallback_batch_min``.
    """

    initial_workers: int
    max_workers: int
    queue_capacity: int
    initial_batch_size: int = 1
    preferred_batch_min: int = 1
    max_batch_size: int = 1
    fallback_batch_min: int = 1

    def __post_init__(self) -> None:
        integer_fields = (
            self.initial_workers,
            self.max_workers,
            self.queue_capacity,
            self.initial_batch_size,
            self.preferred_batch_min,
            self.max_batch_size,
            self.fallback_batch_min,
        )
        if any(isinstance(value, bool) or int(value) != value or value < 1 for value in integer_fields):
            raise ValueError("stage capacity values must be positive integers")
        if self.initial_workers > self.max_workers:
            raise ValueError("initial workers cannot exceed max workers")
        if self.queue_capacity < self.initial_workers:
            raise ValueError("queue capacity cannot be smaller than initial workers")
        if not (
            self.fallback_batch_min
            <= self.preferred_batch_min
            <= self.initial_batch_size
            <= self.max_batch_size
        ):
            raise ValueError("batch limits are not ordered")

    def to_dict(self) -> dict:
        return {
            "initial_workers": self.initial_workers,
            "max_workers": self.max_workers,
            "queue_capacity": self.queue_capacity,
            "initial_batch_size": self.initial_batch_size,
            "preferred_batch_min": self.preferred_batch_min,
            "max_batch_size": self.max_batch_size,
            "fallback_batch_min": self.fallback_batch_min,
        }


@dataclass(frozen=True, slots=True)
class SchedulerProfile:
    quality: OcrQualityMode
    verification_dpi: int
    full_ocr_dpi: int
    retry_dpi: int
    memory_soft_limit_bytes: int
    pools: Mapping[OcrStage, StageCapacity]
    stable_windows_to_recover: int = 3
    p95_latency_soft_limit_ms: float = 45_000.0
    truncation_rate_soft_limit: float = 0.02
    batch_miss_rate_soft_limit: float = 0.0

    def __post_init__(self) -> None:
        object.__setattr__(self, "quality", _quality_mode(self.quality))
        if any(
            isinstance(value, bool) or int(value) != value or int(value) < 72
            for value in (self.verification_dpi, self.full_ocr_dpi, self.retry_dpi)
        ):
            raise ValueError("DPI values must be integers of at least 72")
        if self.verification_dpi > self.full_ocr_dpi or self.full_ocr_dpi > self.retry_dpi:
            raise ValueError("DPI values must increase from verification to retry")
        if isinstance(self.memory_soft_limit_bytes, bool) or self.memory_soft_limit_bytes < 1:
            raise ValueError("memory soft limit must be positive")
        if self.stable_windows_to_recover < 1:
            raise ValueError("stable recovery window count must be positive")
        if not math.isfinite(self.p95_latency_soft_limit_ms) or self.p95_latency_soft_limit_ms <= 0:
            raise ValueError("p95 latency soft limit must be finite and positive")
        for rate in (self.truncation_rate_soft_limit, self.batch_miss_rate_soft_limit):
            if not math.isfinite(rate) or not 0.0 <= rate <= 1.0:
                raise ValueError("scheduler rate thresholds must be within [0, 1]")

        normalized = {_stage(stage): capacity for stage, capacity in dict(self.pools).items()}
        if set(normalized) != set(OcrStage):
            missing = sorted(stage.value for stage in set(OcrStage) - set(normalized))
            extra = sorted(str(stage) for stage in set(normalized) - set(OcrStage))
            raise ValueError(f"scheduler pools must cover every stage; missing={missing}, extra={extra}")
        extraction = normalized[OcrStage.OBJECT_EXTRACTION]
        rendering = normalized[OcrStage.RENDERING]
        verifier = normalized[OcrStage.VISUAL_VERIFICATION]
        full_ocr = normalized[OcrStage.FULL_OCR]
        compiler = normalized[OcrStage.COMPILATION]
        if not (
            MIN_OBJECT_EXTRACTION_WORKERS
            <= extraction.initial_workers
            <= extraction.max_workers
            <= MAX_OBJECT_EXTRACTION_WORKERS
        ):
            raise ValueError("object extraction pool must remain within 4-8 workers")
        if not 2 <= rendering.initial_workers <= rendering.max_workers <= 4:
            raise ValueError("render pool must remain within 2-4 workers")
        if not 4 <= verifier.preferred_batch_min <= verifier.max_batch_size <= 8:
            raise ValueError("healthy visual-verification batches must remain within 4-8 pages")
        if not 1 <= full_ocr.preferred_batch_min <= full_ocr.max_batch_size <= 3:
            raise ValueError("full OCR batches must remain within 1-3 pages")
        if compiler.initial_workers != 1 or compiler.max_workers != 1:
            raise ValueError("the final compilation pool must contain exactly one worker")
        if compiler.queue_capacity != 1 or compiler.max_batch_size != 1:
            raise ValueError("the final compilation pool must accept one task at a time")
        # Rendering is the bitmap pressure point specified by the pipeline.
        if rendering.queue_capacity > rendering.max_workers * 3:
            raise ValueError("render queue cannot exceed three times its worker maximum")
        object.__setattr__(self, "pools", MappingProxyType(normalized))

    def pool(self, stage: OcrStage | str) -> StageCapacity:
        return self.pools[_stage(stage)]

    def to_dict(self) -> dict:
        return {
            "quality": self.quality.value,
            "verification_dpi": self.verification_dpi,
            "full_ocr_dpi": self.full_ocr_dpi,
            "retry_dpi": self.retry_dpi,
            "memory_soft_limit_bytes": self.memory_soft_limit_bytes,
            "stable_windows_to_recover": self.stable_windows_to_recover,
            "p95_latency_soft_limit_ms": self.p95_latency_soft_limit_ms,
            "truncation_rate_soft_limit": self.truncation_rate_soft_limit,
            "batch_miss_rate_soft_limit": self.batch_miss_rate_soft_limit,
            "pools": {stage.value: self.pools[stage].to_dict() for stage in OcrStage},
        }


def scheduler_profile(
    quality: OcrQualityMode | str = OcrQualityMode.RECOMMENDED,
    *,
    memory_soft_limit_bytes: int = 2 * 1024**3,
) -> SchedulerProfile:
    """Return the audited capacity contract for a user-facing quality mode."""

    mode = _quality_mode(quality)
    shared = {
        OcrStage.OBJECT_EXTRACTION: StageCapacity(
            DEFAULT_OBJECT_EXTRACTION_WORKERS,
            MAX_OBJECT_EXTRACTION_WORKERS,
            24,
        ),
        OcrStage.RENDERING: StageCapacity(3, 4, 12),
        OcrStage.PERSISTENCE: StageCapacity(1, 2, 32),
        OcrStage.COMPILATION: StageCapacity(1, 1, 1),
    }
    if mode is OcrQualityMode.FAST:
        dpi = (144, 160, 200)
        shared.update({
            OcrStage.VISUAL_VERIFICATION: StageCapacity(4, 6, 36, 8, 4, 8, 1),
            OcrStage.FULL_OCR: StageCapacity(2, 3, 9, 3, 1, 3, 1),
        })
    elif mode is OcrQualityMode.RECOMMENDED:
        dpi = (160, 200, 300)
        shared.update({
            OcrStage.VISUAL_VERIFICATION: StageCapacity(4, 6, 36, 6, 4, 8, 1),
            OcrStage.FULL_OCR: StageCapacity(3, 3, 9, 2, 1, 3, 1),
        })
    else:
        dpi = (200, 300, 300)
        shared.update({
            OcrStage.VISUAL_VERIFICATION: StageCapacity(4, 6, 32, 4, 4, 8, 1),
            OcrStage.FULL_OCR: StageCapacity(3, 3, 9, 1, 1, 3, 1),
        })
    return SchedulerProfile(
        quality=mode,
        verification_dpi=dpi[0],
        full_ocr_dpi=dpi[1],
        retry_dpi=dpi[2],
        memory_soft_limit_bytes=memory_soft_limit_bytes,
        pools=shared,
    )


@dataclass(frozen=True, slots=True)
class RuntimeSignals:
    """A measured control window.  Missing measurements remain ``None``."""

    request_count: int = 0
    http_429_count: int = 0
    http_5xx_count: int = 0
    p50_latency_ms: float | None = None
    p95_latency_ms: float | None = None
    truncation_rate: float | None = None
    batch_miss_rate: float | None = None
    memory_bytes: int | None = None
    cpu_percent: float | None = None
    backend_concurrency_limit: int | None = None

    def __post_init__(self) -> None:
        counts = (self.request_count, self.http_429_count, self.http_5xx_count)
        if any(isinstance(value, bool) or int(value) != value or value < 0 for value in counts):
            raise ValueError("request and error counts must be non-negative integers")
        if self.http_429_count + self.http_5xx_count > self.request_count:
            raise ValueError("HTTP error counts cannot exceed the measured request count")
        for latency in (self.p50_latency_ms, self.p95_latency_ms):
            if latency is not None and (not math.isfinite(latency) or latency < 0):
                raise ValueError("latency measurements must be finite and non-negative")
        if (
            self.p50_latency_ms is not None
            and self.p95_latency_ms is not None
            and self.p50_latency_ms > self.p95_latency_ms
        ):
            raise ValueError("p50 latency cannot exceed p95 latency")
        for rate in (self.truncation_rate, self.batch_miss_rate):
            if rate is not None and (not math.isfinite(rate) or not 0.0 <= rate <= 1.0):
                raise ValueError("measured rates must be within [0, 1]")
        if self.memory_bytes is not None and self.memory_bytes < 0:
            raise ValueError("memory measurement cannot be negative")
        if self.cpu_percent is not None and (
            not math.isfinite(self.cpu_percent) or self.cpu_percent < 0.0
        ):
            raise ValueError("CPU measurement must be finite and non-negative")
        if self.backend_concurrency_limit is not None and self.backend_concurrency_limit < 1:
            raise ValueError("backend concurrency limit must be positive")


@dataclass(frozen=True, slots=True)
class StagePolicy:
    workers: int
    queue_capacity: int
    batch_size: int
    degraded: bool

    def to_dict(self) -> dict:
        return {
            "workers": self.workers,
            "queue_capacity": self.queue_capacity,
            "batch_size": self.batch_size,
            "degraded": self.degraded,
        }


@dataclass(frozen=True, slots=True)
class SchedulerDecision:
    sequence: int
    action: str
    reasons: tuple[str, ...]
    stable_windows: int
    memory_backpressure: bool
    policies: Mapping[OcrStage, StagePolicy]

    def __post_init__(self) -> None:
        object.__setattr__(self, "policies", MappingProxyType(dict(self.policies)))

    def to_dict(self) -> dict:
        return {
            "sequence": self.sequence,
            "action": self.action,
            "reasons": list(self.reasons),
            "stable_windows": self.stable_windows,
            "memory_backpressure": self.memory_backpressure,
            "policies": {stage.value: self.policies[stage].to_dict() for stage in OcrStage},
        }


class AdaptiveOcrScheduler:
    """A thread-safe additive-increase/multiplicative-decrease controller."""

    def __init__(self, profile: SchedulerProfile):
        self.profile = profile
        self._workers = {
            stage: capacity.initial_workers for stage, capacity in profile.pools.items()
        }
        self._batches = {
            stage: capacity.initial_batch_size for stage, capacity in profile.pools.items()
        }
        self._stable_windows = 0
        self._sequence = 0
        self._memory_backpressure = False
        self._degraded_stages: set[OcrStage] = set()
        self._lock = threading.RLock()

    def _queue_capacity(self, stage: OcrStage) -> int:
        capacity = self.profile.pool(stage)
        # Queue bounds shrink with workers during back-pressure.  Persistence
        # remains independently drainable so completed pages can still commit.
        if stage is OcrStage.PERSISTENCE:
            return capacity.queue_capacity
        per_worker = max(1, math.ceil(capacity.queue_capacity / capacity.max_workers))
        return min(capacity.queue_capacity, max(1, self._workers[stage] * per_worker))

    def _policies(self) -> dict[OcrStage, StagePolicy]:
        return {
            stage: StagePolicy(
                workers=self._workers[stage],
                queue_capacity=self._queue_capacity(stage),
                batch_size=self._batches[stage],
                degraded=stage in self._degraded_stages,
            )
            for stage in OcrStage
        }

    def snapshot(self) -> SchedulerDecision:
        with self._lock:
            return SchedulerDecision(
                sequence=self._sequence,
                action="hold",
                reasons=(),
                stable_windows=self._stable_windows,
                memory_backpressure=self._memory_backpressure,
                policies=self._policies(),
            )

    def observe(self, signals: RuntimeSignals) -> SchedulerDecision:
        """Apply one measured control window and return the bounded policy."""

        with self._lock:
            self._sequence += 1
            reasons: list[str] = []
            if signals.http_429_count:
                reasons.append("http_429")
            if signals.http_5xx_count:
                reasons.append("http_5xx")
            if (
                signals.p95_latency_ms is not None
                and signals.p95_latency_ms > self.profile.p95_latency_soft_limit_ms
            ):
                reasons.append("p95_latency")
            if (
                signals.truncation_rate is not None
                and signals.truncation_rate > self.profile.truncation_rate_soft_limit
            ):
                reasons.append("output_truncation")
            if (
                signals.batch_miss_rate is not None
                and signals.batch_miss_rate > self.profile.batch_miss_rate_soft_limit
            ):
                reasons.append("batch_integrity")
            self._memory_backpressure = bool(
                signals.memory_bytes is not None
                and signals.memory_bytes >= self.profile.memory_soft_limit_bytes
            )
            if self._memory_backpressure:
                reasons.append("memory_soft_limit")

            if reasons:
                self._stable_windows = 0
                severe = "http_429" in reasons or "memory_soft_limit" in reasons
                for stage in MODEL_STAGES:
                    current = self._workers[stage]
                    self._workers[stage] = max(1, current // 2 if severe else current - 1)
                    batch = self._batches[stage]
                    floor = self.profile.pool(stage).fallback_batch_min
                    self._batches[stage] = max(floor, math.ceil(batch / 2))
                    self._degraded_stages.add(stage)
                if self._memory_backpressure:
                    render = OcrStage.RENDERING
                    self._workers[render] = max(1, self._workers[render] - 1)
                    self._degraded_stages.add(render)
                action = "decrease"
            else:
                action = "hold"
                # Idle polling is not evidence that a provider is stable.  A
                # recovery window must contain at least one real request.
                if signals.request_count:
                    self._stable_windows += 1
                if (
                    signals.request_count
                    and self._stable_windows >= self.profile.stable_windows_to_recover
                ):
                    self._stable_windows = 0
                    action = "increase"
                    for stage in (*MODEL_STAGES, OcrStage.RENDERING):
                        capacity = self.profile.pool(stage)
                        if self._workers[stage] < capacity.max_workers:
                            self._workers[stage] += 1
                        if self._batches[stage] < capacity.initial_batch_size:
                            self._batches[stage] += 1
                        if (
                            self._workers[stage] >= capacity.initial_workers
                            and self._batches[stage] >= capacity.initial_batch_size
                        ):
                            self._degraded_stages.discard(stage)

            if signals.backend_concurrency_limit is not None:
                for stage in MODEL_STAGES:
                    limited = min(self._workers[stage], signals.backend_concurrency_limit)
                    if limited != self._workers[stage]:
                        self._workers[stage] = limited
                        self._degraded_stages.add(stage)
                        if "backend_concurrency_limit" not in reasons:
                            reasons.append("backend_concurrency_limit")
                        action = "decrease"

            return SchedulerDecision(
                sequence=self._sequence,
                action=action,
                reasons=tuple(reasons),
                stable_windows=self._stable_windows,
                memory_backpressure=self._memory_backpressure,
                policies=self._policies(),
            )

    def can_enqueue(
        self,
        stage: OcrStage | str,
        *,
        queued: int,
        paused: bool = False,
        memory_bytes: int | None = None,
    ) -> bool:
        """Return whether one new task fits without bypassing back-pressure."""

        target = _stage(stage)
        if isinstance(queued, bool) or queued < 0:
            raise ValueError("queued task count must be a non-negative integer")
        if memory_bytes is not None and memory_bytes < 0:
            raise ValueError("memory measurement cannot be negative")
        with self._lock:
            if paused:
                return False
            measured_pressure = (
                memory_bytes is not None
                and memory_bytes >= self.profile.memory_soft_limit_bytes
            )
            if target is OcrStage.RENDERING and (
                measured_pressure or self._memory_backpressure
            ):
                return False
            return queued < self._queue_capacity(target)

    def batch_size_for(
        self,
        stage: OcrStage | str,
        *,
        math_dense: bool = False,
        complex_layout: bool = False,
        crop_retry: bool = False,
    ) -> int:
        """Choose a bounded batch; risky OCR and crops are always single-page."""

        target = _stage(stage)
        with self._lock:
            size = self._batches[target]
        if target is OcrStage.FULL_OCR and (math_dense or complex_layout or crop_retry):
            return 1
        return size


def split_failed_batch(page_ids: Sequence[str]) -> tuple[tuple[str, ...], ...]:
    """Bisect only the failed batch, preserving every page identity."""

    values = tuple(str(page_id).strip() for page_id in page_ids)
    if not values or any(not value for value in values):
        raise ValueError("failed batch must contain non-empty page IDs")
    if len(set(values)) != len(values):
        raise ValueError("failed batch contains duplicate page IDs")
    if len(values) == 1:
        return (values,)
    midpoint = (len(values) + 1) // 2
    return (values[:midpoint], values[midpoint:])


@dataclass(frozen=True, slots=True)
class BudgetLimits:
    max_input_tokens: int | None = None
    max_output_tokens: int | None = None
    max_requests: int | None = None
    max_strong_model_calls: int | None = None
    max_cost: float | None = None
    max_wall_time_minutes: float | None = None

    def __post_init__(self) -> None:
        integer_values = (
            self.max_input_tokens,
            self.max_output_tokens,
            self.max_requests,
            self.max_strong_model_calls,
        )
        for value in integer_values:
            if value is not None and (
                isinstance(value, bool) or int(value) != value or value <= 0
            ):
                raise ValueError("integer budget limits must be positive")
        for value in (self.max_cost, self.max_wall_time_minutes):
            if value is not None and (not math.isfinite(value) or value <= 0):
                raise ValueError("cost and wall-time budgets must be finite and positive")

    def to_dict(self) -> dict:
        return {
            "max_input_tokens": self.max_input_tokens,
            "max_output_tokens": self.max_output_tokens,
            "max_requests": self.max_requests,
            "max_strong_model_calls": self.max_strong_model_calls,
            "max_cost": self.max_cost,
            "max_wall_time_minutes": self.max_wall_time_minutes,
        }


@dataclass(frozen=True, slots=True)
class BudgetUsage:
    input_tokens: int | None = None
    output_tokens: int | None = None
    requests: int | None = None
    strong_model_calls: int | None = None
    cost: float | None = None
    wall_time_minutes: float | None = None

    def __post_init__(self) -> None:
        integer_values = (
            self.input_tokens,
            self.output_tokens,
            self.requests,
            self.strong_model_calls,
        )
        for value in integer_values:
            if value is not None and (
                isinstance(value, bool) or int(value) != value or value < 0
            ):
                raise ValueError("integer budget usage must be non-negative")
        for value in (self.cost, self.wall_time_minutes):
            if value is not None and (not math.isfinite(value) or value < 0):
                raise ValueError("cost and wall-time usage must be finite and non-negative")


@dataclass(frozen=True, slots=True)
class BudgetAdvice:
    should_pause_new_model_tasks: bool
    finish_current_atomic_task: bool
    leave_unstarted_pages_pending: bool
    threshold: float
    reasons: tuple[str, ...]
    ratios: Mapping[str, float | None] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "ratios", MappingProxyType(dict(self.ratios)))

    def to_dict(self) -> dict:
        return {
            "should_pause_new_model_tasks": self.should_pause_new_model_tasks,
            "finish_current_atomic_task": self.finish_current_atomic_task,
            "leave_unstarted_pages_pending": self.leave_unstarted_pages_pending,
            "threshold": self.threshold,
            "reasons": list(self.reasons),
            "ratios": dict(self.ratios),
        }


def advise_budget_pause(
    limits: BudgetLimits,
    usage: BudgetUsage,
    *,
    threshold: float = 0.90,
) -> BudgetAdvice:
    """Advise a safe pause using only caller-supplied measurements.

    Unknown usage remains unknown and never becomes an assumed zero.  The host
    should finish the current atomic page write before acting on a pause.
    """

    if not math.isfinite(threshold) or not 0.0 < threshold <= 1.0:
        raise ValueError("budget threshold must be within (0, 1]")
    pairs = {
        "input_tokens": (usage.input_tokens, limits.max_input_tokens),
        "output_tokens": (usage.output_tokens, limits.max_output_tokens),
        "requests": (usage.requests, limits.max_requests),
        "strong_model_calls": (usage.strong_model_calls, limits.max_strong_model_calls),
        "cost": (usage.cost, limits.max_cost),
        "wall_time_minutes": (usage.wall_time_minutes, limits.max_wall_time_minutes),
    }
    ratios: dict[str, float | None] = {}
    reasons: list[str] = []
    for name, (used, maximum) in pairs.items():
        ratio = None if used is None or maximum is None else float(used) / float(maximum)
        ratios[name] = ratio
        if ratio is not None and ratio >= threshold:
            reasons.append(name)
    should_pause = bool(reasons)
    return BudgetAdvice(
        should_pause_new_model_tasks=should_pause,
        finish_current_atomic_task=should_pause,
        leave_unstarted_pages_pending=should_pause,
        threshold=threshold,
        reasons=tuple(reasons),
        ratios=ratios,
    )


__all__ = [
    "AdaptiveOcrScheduler",
    "BudgetAdvice",
    "BudgetLimits",
    "BudgetUsage",
    "DEFAULT_OBJECT_EXTRACTION_WORKERS",
    "MAX_OBJECT_EXTRACTION_WORKERS",
    "MIN_OBJECT_EXTRACTION_WORKERS",
    "MODEL_STAGES",
    "OcrQualityMode",
    "OcrStage",
    "RuntimeSignals",
    "SchedulerDecision",
    "SchedulerProfile",
    "StageCapacity",
    "StagePolicy",
    "advise_budget_pause",
    "scheduler_profile",
    "split_failed_batch",
]

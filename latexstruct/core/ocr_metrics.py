# -*- coding: utf-8 -*-
"""Measured OCR performance and cost reports.

The collector accepts observations from the host and derives only arithmetic
facts such as percentiles, throughput, and ETA.  Provider usage, money, CPU,
and memory are never estimated: when the caller did not supply a measurement,
the corresponding report value remains ``null`` and its coverage flag is
false.
"""

from __future__ import annotations

import json
import math
import os
import threading
import time
import uuid
from collections import Counter
from dataclasses import dataclass, field
from decimal import Decimal
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Callable, Iterable, Mapping

from .ocr_scheduler import BudgetLimits, OcrStage


PERFORMANCE_METRICS_SCHEMA = "latexstruct-ocr-performance-metrics-v1"
COST_REPORT_SCHEMA = "latexstruct-ocr-cost-report-v1"


def canonical_metrics_json_bytes(value: Mapping[str, object]) -> bytes:
    """Encode one collector report in its stable, hashable JSON form."""

    if not isinstance(value, Mapping):
        raise TypeError("metrics report must be a mapping")
    return (
        json.dumps(
            dict(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


class OcrStrategy(str, Enum):
    OBJECT_LAYER_VERIFIED = "object_layer_verified"
    FULL_VISUAL_OCR = "full_visual_ocr"
    HIGH_RESOLUTION_RETRY = "high_resolution_retry"
    CROP_REVIEW = "crop_review"


class PageFinalStatus(str, Enum):
    SUCCESS = "SUCCESS"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    FAILED = "FAILED"


class RequestKind(str, Enum):
    VISUAL_VERIFICATION = "visual_verification"
    FULL_OCR = "full_ocr"
    HIGH_RESOLUTION_RETRY = "high_resolution_retry"
    CROP_RECOGNITION = "crop_recognition"


def _enum_value(value, enum_type, label: str):
    if isinstance(value, enum_type):
        return value
    text = str(value or "").strip()
    try:
        return enum_type(text)
    except ValueError as exc:
        raise ValueError(f"unknown {label}: {value!r}") from exc


def _finite_nonnegative(value: float, label: str) -> float:
    number = float(value)
    if not math.isfinite(number) or number < 0:
        raise ValueError(f"{label} must be finite and non-negative")
    return number


def _nonnegative_int(value: int, label: str) -> int:
    if isinstance(value, bool) or int(value) != value or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return int(value)


def _nearest_rank(values: Iterable[float], percentile: float) -> float | None:
    ordered = sorted(float(value) for value in values)
    if not ordered:
        return None
    rank = max(1, math.ceil(percentile * len(ordered)))
    return ordered[rank - 1]


@dataclass(slots=True)
class _StageAccumulator:
    submitted: int = 0
    started: int = 0
    completed: int = 0
    failed: int = 0
    duration_ms: list[float] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "submitted": self.submitted,
            "started": self.started,
            "completed": self.completed,
            "failed": self.failed,
            "queued": self.submitted - self.started,
            "in_flight": self.started - self.completed - self.failed,
            "latency_ms": {
                "samples": len(self.duration_ms),
                "p50": _nearest_rank(self.duration_ms, 0.50),
                "p95": _nearest_rank(self.duration_ms, 0.95),
            },
        }


@dataclass(frozen=True, slots=True)
class _PageObservation:
    page_id: str
    status: PageFinalStatus
    strategy: OcrStrategy | None
    completed_at_seconds: float
    dpi_history: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class _RequestObservation:
    call_id: str
    kind: RequestKind
    latency_ms: float
    status_code: int | None
    input_tokens: int | None
    output_tokens: int | None
    cost: Decimal | None
    currency: str | None
    dpi: int | None
    retry: bool | None
    truncated: bool | None
    strong_model: bool | None
    page_count: int


class OcrMetricsCollector:
    """Thread-safe, append-only measurements for one immutable OCR run."""

    def __init__(
        self,
        run_id: str,
        *,
        selected_pages: int | None,
        started_at_seconds: float | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.run_id = str(run_id or "").strip()
        if not self.run_id:
            raise ValueError("run_id is required")
        if selected_pages is not None:
            selected_pages = _nonnegative_int(selected_pages, "selected page count")
        self.selected_pages = selected_pages
        self._clock = clock
        measured_start = clock() if started_at_seconds is None else float(started_at_seconds)
        if not math.isfinite(measured_start):
            raise ValueError("start time must be finite")
        self.started_at_seconds = measured_start
        self._stages = {stage: _StageAccumulator() for stage in OcrStage}
        self._pages: dict[str, _PageObservation] = {}
        self._requests: dict[str, _RequestObservation] = {}
        self._peak_memory_bytes: int | None = None
        self._peak_cpu_percent: float | None = None
        self._resource_sample_count = 0
        self._memory_sample_count = 0
        self._cpu_sample_count = 0
        self._lock = threading.RLock()

    @staticmethod
    def _stage(value: OcrStage | str) -> OcrStage:
        return _enum_value(value, OcrStage, "OCR stage")

    def submit_stage(self, stage: OcrStage | str, *, items: int = 1) -> None:
        count = _nonnegative_int(items, "submitted item count")
        with self._lock:
            self._stages[self._stage(stage)].submitted += count

    def start_stage(self, stage: OcrStage | str, *, items: int = 1) -> None:
        count = _nonnegative_int(items, "started item count")
        target = self._stage(stage)
        with self._lock:
            metric = self._stages[target]
            if metric.started + count > metric.submitted:
                raise ValueError("cannot start more stage items than were submitted")
            metric.started += count

    def finish_stage(
        self,
        stage: OcrStage | str,
        *,
        duration_ms: float,
        items: int = 1,
        succeeded: bool = True,
    ) -> None:
        count = _nonnegative_int(items, "finished item count")
        duration = _finite_nonnegative(duration_ms, "stage duration")
        target = self._stage(stage)
        with self._lock:
            metric = self._stages[target]
            if metric.completed + metric.failed + count > metric.started:
                raise ValueError("cannot finish more stage items than were started")
            if succeeded:
                metric.completed += count
            else:
                metric.failed += count
            # A batch duration is one measured latency sample, not a fabricated
            # per-item duration repeated ``items`` times.
            metric.duration_ms.append(duration)

    def record_stage_execution(
        self,
        stage: OcrStage | str,
        *,
        duration_ms: float,
        items: int = 1,
        succeeded: bool = True,
    ) -> None:
        """Record an already-completed atomic execution in one operation."""

        count = _nonnegative_int(items, "stage item count")
        if count < 1:
            raise ValueError("stage item count must be positive")
        duration = _finite_nonnegative(duration_ms, "stage duration")
        target = self._stage(stage)
        with self._lock:
            metric = self._stages[target]
            metric.submitted += count
            metric.started += count
            if succeeded:
                metric.completed += count
            else:
                metric.failed += count
            metric.duration_ms.append(duration)

    def record_page_result(
        self,
        page_id: str,
        *,
        status: PageFinalStatus | str,
        strategy: OcrStrategy | str | None,
        completed_at_seconds: float | None = None,
        dpi_history: Iterable[int] = (),
    ) -> None:
        page = str(page_id or "").strip()
        if not page:
            raise ValueError("page_id is required")
        final_status = _enum_value(status, PageFinalStatus, "page final status")
        final_strategy = (
            None if strategy is None else _enum_value(strategy, OcrStrategy, "OCR strategy")
        )
        timestamp = self._clock() if completed_at_seconds is None else float(completed_at_seconds)
        if not math.isfinite(timestamp) or timestamp < self.started_at_seconds:
            raise ValueError("page completion time must be finite and not precede the run")
        dpi_values: list[int] = []
        for dpi in dpi_history:
            if isinstance(dpi, bool) or int(dpi) != dpi or dpi < 1:
                raise ValueError("page DPI history must contain positive integers")
            dpi_values.append(int(dpi))
        observation = _PageObservation(
            page_id=page,
            status=final_status,
            strategy=final_strategy,
            completed_at_seconds=timestamp,
            dpi_history=tuple(dict.fromkeys(dpi_values)),
        )
        with self._lock:
            if page in self._pages:
                raise ValueError(f"page result is append-only and already exists: {page}")
            if self.selected_pages is not None and len(self._pages) >= self.selected_pages:
                raise ValueError("recorded page results exceed the selected page count")
            self._pages[page] = observation

    def record_request(
        self,
        call_id: str,
        *,
        kind: RequestKind | str,
        latency_ms: float,
        page_count: int = 1,
        status_code: int | None = None,
        input_tokens: int | None = None,
        output_tokens: int | None = None,
        cost: float | str | Decimal | None = None,
        currency: str | None = None,
        dpi: int | None = None,
        retry: bool | None = None,
        truncated: bool | None = None,
        strong_model: bool | None = None,
    ) -> None:
        call = str(call_id or "").strip()
        if not call:
            raise ValueError("call_id is required")
        request_kind = _enum_value(kind, RequestKind, "request kind")
        latency = _finite_nonnegative(latency_ms, "request latency")
        pages = _nonnegative_int(page_count, "request page count")
        if pages < 1:
            raise ValueError("request page count must be positive")
        if status_code is not None:
            if (
                isinstance(status_code, bool)
                or int(status_code) != status_code
                or not 100 <= int(status_code) <= 599
            ):
                raise ValueError("HTTP status code must be an integer within 100-599")
        if input_tokens is not None:
            input_tokens = _nonnegative_int(input_tokens, "input token count")
        if output_tokens is not None:
            output_tokens = _nonnegative_int(output_tokens, "output token count")
        exact_cost: Decimal | None = None
        normalized_currency: str | None = None
        if cost is not None:
            try:
                exact_cost = Decimal(str(cost))
            except Exception as exc:
                raise ValueError("provider-reported cost must be numeric") from exc
            if not exact_cost.is_finite() or exact_cost < 0:
                raise ValueError("provider-reported cost must be finite and non-negative")
            normalized_currency = str(currency or "").strip().upper()
            if not normalized_currency:
                raise ValueError("currency is required when an actual cost is recorded")
        elif currency is not None:
            raise ValueError("currency cannot be recorded without an actual cost")
        if dpi is not None and (isinstance(dpi, bool) or int(dpi) != dpi or dpi < 1):
            raise ValueError("request DPI must be a positive integer")
        for label, value in (
            ("retry", retry),
            ("truncated", truncated),
            ("strong_model", strong_model),
        ):
            if value is not None and not isinstance(value, bool):
                raise ValueError(f"{label} observation must be boolean or null")
        observation = _RequestObservation(
            call_id=call,
            kind=request_kind,
            latency_ms=latency,
            status_code=None if status_code is None else int(status_code),
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost=exact_cost,
            currency=normalized_currency,
            dpi=None if dpi is None else int(dpi),
            retry=retry,
            truncated=truncated,
            strong_model=strong_model,
            page_count=pages,
        )
        with self._lock:
            if call in self._requests:
                raise ValueError(f"request metrics are append-only and already exist: {call}")
            currencies = {
                item.currency for item in self._requests.values() if item.currency is not None
            }
            if normalized_currency is not None and currencies and normalized_currency not in currencies:
                raise ValueError("one cost report cannot mix currencies")
            self._requests[call] = observation

    def record_resource_sample(
        self,
        *,
        memory_bytes: int | None = None,
        cpu_percent: float | None = None,
    ) -> None:
        if memory_bytes is None and cpu_percent is None:
            raise ValueError("a resource sample must contain memory or CPU")
        if memory_bytes is not None:
            memory_bytes = _nonnegative_int(memory_bytes, "memory sample")
        if cpu_percent is not None:
            cpu_percent = _finite_nonnegative(cpu_percent, "CPU sample")
            # Some process-level samplers report one fully occupied core as
            # 100%, so a multi-core process may honestly exceed 100%.
        with self._lock:
            self._resource_sample_count += 1
            if memory_bytes is not None:
                self._memory_sample_count += 1
                self._peak_memory_bytes = max(self._peak_memory_bytes or 0, memory_bytes)
            if cpu_percent is not None:
                self._cpu_sample_count += 1
                self._peak_cpu_percent = max(self._peak_cpu_percent or 0.0, cpu_percent)

    def _captured_now(self, now_seconds: float | None) -> float:
        now = self._clock() if now_seconds is None else float(now_seconds)
        if not math.isfinite(now) or now < self.started_at_seconds:
            raise ValueError("capture time must be finite and not precede the run")
        return now

    @staticmethod
    def _complete_sum(values: list[int | None]) -> tuple[int | None, int, int]:
        observed = [value for value in values if value is not None]
        observed_sum = sum(observed)
        complete = len(observed) == len(values) and bool(values)
        return (observed_sum if complete else None, observed_sum, len(observed))

    def _request_summary(self) -> dict:
        requests = list(self._requests.values())
        status_observed = [request for request in requests if request.status_code is not None]
        retry_observed = [request.retry for request in requests if request.retry is not None]
        truncation_observed = [
            request.truncated for request in requests if request.truncated is not None
        ]
        strong_observed = [
            request.strong_model for request in requests if request.strong_model is not None
        ]
        total = len(requests)
        return {
            "total": total,
            "pages_in_requests": sum(request.page_count for request in requests),
            "by_kind": dict(sorted(Counter(request.kind.value for request in requests).items())),
            "by_dpi": {
                str(dpi): count
                for dpi, count in sorted(
                    Counter(request.dpi for request in requests if request.dpi is not None).items()
                )
            },
            "http_429": sum(request.status_code == 429 for request in status_observed),
            "http_5xx": sum(
                request.status_code is not None and 500 <= request.status_code <= 599
                for request in status_observed
            ),
            "status_code_coverage": {
                "measured": len(status_observed),
                "total": total,
                "complete": len(status_observed) == total and bool(total),
            },
            "automatic_retries": (
                sum(value is True for value in retry_observed)
                if len(retry_observed) == total and total
                else None
            ),
            "observed_automatic_retries": sum(value is True for value in retry_observed),
            "retry_coverage": {
                "measured": len(retry_observed),
                "total": total,
                "complete": len(retry_observed) == total and bool(total),
            },
            "output_truncations": (
                sum(value is True for value in truncation_observed)
                if len(truncation_observed) == total and total
                else None
            ),
            "observed_output_truncations": sum(
                value is True for value in truncation_observed
            ),
            "truncation_rate": (
                sum(value is True for value in truncation_observed) / total
                if len(truncation_observed) == total and total
                else None
            ),
            "truncation_coverage": {
                "measured": len(truncation_observed),
                "total": total,
                "complete": len(truncation_observed) == total and bool(total),
            },
            "strong_model_calls": (
                sum(value is True for value in strong_observed)
                if len(strong_observed) == total and total
                else None
            ),
            "observed_strong_model_calls": sum(value is True for value in strong_observed),
            "strong_model_coverage": {
                "measured": len(strong_observed),
                "total": total,
                "complete": len(strong_observed) == total and bool(total),
            },
            "latency_ms": {
                "samples": total,
                "p50": _nearest_rank((request.latency_ms for request in requests), 0.50),
                "p95": _nearest_rank((request.latency_ms for request in requests), 0.95),
            },
        }

    def _usage_summary(self) -> dict:
        requests = list(self._requests.values())
        input_total, input_observed, input_measured = self._complete_sum(
            [request.input_tokens for request in requests]
        )
        output_total, output_observed, output_measured = self._complete_sum(
            [request.output_tokens for request in requests]
        )
        costs = [request.cost for request in requests]
        measured_costs = [cost for cost in costs if cost is not None]
        cost_complete = len(measured_costs) == len(costs) and bool(costs)
        observed_cost = sum(measured_costs, Decimal("0"))
        currency_values = {
            request.currency for request in requests if request.currency is not None
        }
        currency = next(iter(currency_values)) if len(currency_values) == 1 else None
        return {
            "input_tokens": input_total,
            "observed_input_tokens": input_observed,
            "input_token_coverage": {
                "measured": input_measured,
                "total": len(requests),
                "complete": input_measured == len(requests) and bool(requests),
            },
            "output_tokens": output_total,
            "observed_output_tokens": output_observed,
            "output_token_coverage": {
                "measured": output_measured,
                "total": len(requests),
                "complete": output_measured == len(requests) and bool(requests),
            },
            "cost": float(observed_cost) if cost_complete else None,
            "observed_cost": float(observed_cost),
            "currency": currency,
            "cost_coverage": {
                "measured": len(measured_costs),
                "total": len(requests),
                "complete": cost_complete,
            },
        }

    def performance_metrics(self, *, now_seconds: float | None = None) -> dict:
        with self._lock:
            now = self._captured_now(now_seconds)
            elapsed = now - self.started_at_seconds
            pages = list(self._pages.values())
            completed = len(pages)
            remaining = (
                None
                if self.selected_pages is None
                else max(0, self.selected_pages - completed)
            )
            average_ppm = completed * 60.0 / elapsed if elapsed > 0 and completed else None
            recent_window = min(60.0, elapsed)
            recent_count = sum(
                now - recent_window <= page.completed_at_seconds <= now for page in pages
            )
            recent_ppm = (
                recent_count * 60.0 / recent_window if recent_window > 0 else None
            )
            if remaining == 0:
                eta_seconds = 0.0
            elif remaining is not None and average_ppm is not None and average_ppm > 0:
                eta_seconds = remaining / (average_ppm / 60.0)
            else:
                eta_seconds = None
            strategy_count = Counter(
                page.strategy.value for page in pages if page.strategy is not None
            )
            dpi_pages: Counter[int] = Counter()
            for page in pages:
                for dpi in page.dpi_history:
                    dpi_pages[dpi] += 1
            status_count = Counter(page.status.value for page in pages)
            request_summary = self._request_summary()
            usage = self._usage_summary()
            return {
                "schema_version": PERFORMANCE_METRICS_SCHEMA,
                "run_id": self.run_id,
                "elapsed_ms": elapsed * 1000.0,
                "pages": {
                    "selected": self.selected_pages,
                    "coverage_completed": completed,
                    "remaining": remaining,
                    "by_final_status": dict(sorted(status_count.items())),
                },
                "stages": {
                    stage.value: self._stages[stage].to_dict() for stage in OcrStage
                },
                "throughput": {
                    "average_pages_per_minute": average_ppm,
                    "recent_pages_per_minute": recent_ppm,
                    "recent_window_seconds": recent_window,
                    "eta_seconds": eta_seconds,
                    "eta_basis": (
                        "complete"
                        if remaining == 0
                        else "measured_average_throughput"
                        if eta_seconds is not None
                        else None
                    ),
                },
                "strategy_distribution": dict(sorted(strategy_count.items())),
                "strategy_measurement": {
                    "classified": sum(strategy_count.values()),
                    "total_completed": completed,
                    "complete": sum(strategy_count.values()) == completed and bool(completed),
                },
                "dpi_pages": {
                    str(dpi): count for dpi, count in sorted(dpi_pages.items())
                },
                "requests": request_summary,
                "usage": usage,
                "resources": {
                    "peak_memory_bytes": self._peak_memory_bytes,
                    "peak_cpu_percent": self._peak_cpu_percent,
                    "samples": self._resource_sample_count,
                    "memory_samples": self._memory_sample_count,
                    "cpu_samples": self._cpu_sample_count,
                },
            }

    @staticmethod
    def _budget_ratio(used, limit) -> float | None:
        if used is None or limit is None:
            return None
        return float(used) / float(limit)

    def cost_report(self, *, budget_limits: BudgetLimits | None = None) -> dict:
        with self._lock:
            usage = self._usage_summary()
            requests = self._request_summary()
            limits = budget_limits or BudgetLimits()
            actual = {
                "requests": requests["total"],
                "strong_model_calls": requests["strong_model_calls"],
                "input_tokens": usage["input_tokens"],
                "output_tokens": usage["output_tokens"],
                "cost": usage["cost"],
                "currency": usage["currency"],
            }
            return {
                "schema_version": COST_REPORT_SCHEMA,
                "run_id": self.run_id,
                "actual": actual,
                "observed_partial": {
                    "strong_model_calls": requests["observed_strong_model_calls"],
                    "input_tokens": usage["observed_input_tokens"],
                    "output_tokens": usage["observed_output_tokens"],
                    "cost": usage["observed_cost"],
                    "currency": usage["currency"],
                },
                "measurement_coverage": {
                    "strong_model_calls": requests["strong_model_coverage"],
                    "input_tokens": usage["input_token_coverage"],
                    "output_tokens": usage["output_token_coverage"],
                    "cost": usage["cost_coverage"],
                },
                "limits": limits.to_dict(),
                "ratios": {
                    "requests": self._budget_ratio(
                        actual["requests"], limits.max_requests
                    ),
                    "strong_model_calls": self._budget_ratio(
                        actual["strong_model_calls"], limits.max_strong_model_calls
                    ),
                    "input_tokens": self._budget_ratio(
                        actual["input_tokens"], limits.max_input_tokens
                    ),
                    "output_tokens": self._budget_ratio(
                        actual["output_tokens"], limits.max_output_tokens
                    ),
                    "cost": self._budget_ratio(actual["cost"], limits.max_cost),
                },
            }

    def canonical_reports(
        self,
        *,
        budget_limits: BudgetLimits | None = None,
        now_seconds: float | None = None,
    ) -> Mapping[str, bytes]:
        """Return one internally consistent pair of immutable report bytes.

        Unknown provider usage, money, and machine measurements remain JSON
        ``null``.  The canonical encoding is shared with the OCR baseline
        manifest so the exact bytes can be hash-bound without reformatting.
        """

        with self._lock:
            performance = self.performance_metrics(now_seconds=now_seconds)
            cost = self.cost_report(budget_limits=budget_limits)
        return MappingProxyType({
            "performance_metrics": canonical_metrics_json_bytes(performance),
            "cost_report": canonical_metrics_json_bytes(cost),
        })

    @staticmethod
    def _write_json(path: Path, payload: Mapping) -> None:
        if path.exists():
            raise FileExistsError(f"refusing to overwrite immutable metrics report: {path.name}")
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        data = canonical_metrics_json_bytes(payload)
        try:
            with temporary.open("xb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            if temporary.exists():
                temporary.unlink()

    def write_reports(
        self,
        reports_directory: str | Path,
        *,
        budget_limits: BudgetLimits | None = None,
        now_seconds: float | None = None,
    ) -> dict[str, Path]:
        """Atomically write the two real reports, refusing overwrite by default."""

        directory = Path(reports_directory)
        performance_path = directory / "performance_metrics.json"
        cost_path = directory / "cost_report.json"
        for path in (performance_path, cost_path):
            if path.exists():
                raise FileExistsError(
                    f"refusing to overwrite immutable metrics report: {path.name}"
                )
        with self._lock:
            performance = self.performance_metrics(now_seconds=now_seconds)
            cost = self.cost_report(budget_limits=budget_limits)
        self._write_json(performance_path, performance)
        try:
            self._write_json(cost_path, cost)
        except Exception:
            # A paired report must not be presented as complete when its second
            # atomic commit failed.  This only removes the file created by this
            # call; pre-existing files are never touched.
            if performance_path.exists():
                performance_path.unlink()
            raise
        return {"performance_metrics": performance_path, "cost_report": cost_path}


__all__ = [
    "COST_REPORT_SCHEMA",
    "OcrMetricsCollector",
    "OcrStrategy",
    "PERFORMANCE_METRICS_SCHEMA",
    "PageFinalStatus",
    "RequestKind",
    "canonical_metrics_json_bytes",
]

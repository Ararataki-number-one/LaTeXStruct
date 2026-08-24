from __future__ import annotations

import json

import pytest

from latexstruct.core.ocr_metrics import (
    COST_REPORT_SCHEMA,
    PERFORMANCE_METRICS_SCHEMA,
    OcrMetricsCollector,
    OcrStrategy,
    PageFinalStatus,
    RequestKind,
)
from latexstruct.core.ocr_scheduler import (
    AdaptiveOcrScheduler,
    BudgetLimits,
    BudgetUsage,
    DEFAULT_OBJECT_EXTRACTION_WORKERS,
    MAX_OBJECT_EXTRACTION_WORKERS,
    MIN_OBJECT_EXTRACTION_WORKERS,
    OcrQualityMode,
    OcrStage,
    RuntimeSignals,
    advise_budget_pause,
    scheduler_profile,
    split_failed_batch,
)


def test_quality_profiles_keep_dpi_workers_batches_and_queues_bounded():
    expected_dpi = {
        OcrQualityMode.FAST: (144, 160, 200),
        OcrQualityMode.RECOMMENDED: (160, 200, 300),
        OcrQualityMode.HIGH: (200, 300, 300),
    }
    for mode, dpi in expected_dpi.items():
        profile = scheduler_profile(mode, memory_soft_limit_bytes=512 * 1024**2)
        assert (
            profile.verification_dpi,
            profile.full_ocr_dpi,
            profile.retry_dpi,
        ) == dpi
        assert set(profile.pools) == set(OcrStage)

        extraction = profile.pool(OcrStage.OBJECT_EXTRACTION)
        rendering = profile.pool(OcrStage.RENDERING)
        verifier = profile.pool(OcrStage.VISUAL_VERIFICATION)
        full = profile.pool(OcrStage.FULL_OCR)
        compiler = profile.pool(OcrStage.COMPILATION)
        assert (
            MIN_OBJECT_EXTRACTION_WORKERS
            <= extraction.initial_workers
            == DEFAULT_OBJECT_EXTRACTION_WORKERS
            <= extraction.max_workers
            == MAX_OBJECT_EXTRACTION_WORKERS
        )
        assert 2 <= rendering.initial_workers <= rendering.max_workers <= 4
        assert rendering.queue_capacity <= rendering.max_workers * 3
        assert (verifier.preferred_batch_min, verifier.max_batch_size) == (4, 8)
        assert 4 <= verifier.initial_batch_size <= 8
        assert 1 <= full.initial_batch_size <= full.max_batch_size <= 3
        assert compiler.initial_workers == compiler.max_workers == 1
        assert compiler.queue_capacity == 1
        for capacity in profile.pools.values():
            assert capacity.queue_capacity >= capacity.initial_workers
            assert capacity.initial_workers <= capacity.max_workers


def test_scheduler_applies_backpressure_and_recovers_only_after_stable_windows():
    profile = scheduler_profile("recommended", memory_soft_limit_bytes=1_000)
    scheduler = AdaptiveOcrScheduler(profile)
    initial = scheduler.snapshot()
    assert initial.policies[OcrStage.VISUAL_VERIFICATION].workers == 4
    assert initial.policies[OcrStage.VISUAL_VERIFICATION].batch_size == 6
    assert scheduler.can_enqueue(OcrStage.RENDERING, queued=0, memory_bytes=999)

    throttled = scheduler.observe(
        RuntimeSignals(
            request_count=10,
            http_429_count=1,
            p50_latency_ms=1_000,
            p95_latency_ms=2_000,
            memory_bytes=1_001,
        )
    )
    assert throttled.action == "decrease"
    assert set(throttled.reasons) == {"http_429", "memory_soft_limit"}
    assert throttled.memory_backpressure is True
    assert throttled.policies[OcrStage.VISUAL_VERIFICATION].workers == 2
    assert throttled.policies[OcrStage.VISUAL_VERIFICATION].batch_size == 3
    assert throttled.policies[OcrStage.FULL_OCR].workers == 1
    assert not scheduler.can_enqueue(OcrStage.RENDERING, queued=0)
    assert scheduler.can_enqueue(OcrStage.PERSISTENCE, queued=0)

    idle = scheduler.observe(RuntimeSignals())
    assert idle.action == "hold"
    assert idle.stable_windows == 0
    assert idle.policies[OcrStage.VISUAL_VERIFICATION].workers == 2

    stable = RuntimeSignals(request_count=10, p50_latency_ms=1_000, p95_latency_ms=2_000)
    assert scheduler.observe(stable).action == "hold"
    assert scheduler.observe(stable).action == "hold"
    recovered = scheduler.observe(stable)
    assert recovered.action == "increase"
    assert recovered.memory_backpressure is False
    assert recovered.policies[OcrStage.VISUAL_VERIFICATION].workers == 3
    assert recovered.policies[OcrStage.VISUAL_VERIFICATION].batch_size == 4
    assert recovered.policies[OcrStage.VISUAL_VERIFICATION].degraded is True

    # Recovery is additive and remains within the immutable profile maximum.
    for _ in range(20):
        recovered = scheduler.observe(stable)
    verifier = recovered.policies[OcrStage.VISUAL_VERIFICATION]
    assert verifier.workers == profile.pool(OcrStage.VISUAL_VERIFICATION).max_workers
    assert verifier.batch_size == profile.pool(OcrStage.VISUAL_VERIFICATION).initial_batch_size
    assert verifier.degraded is False
    assert verifier.queue_capacity <= profile.pool(OcrStage.VISUAL_VERIFICATION).queue_capacity


def test_scheduler_shrinks_on_5xx_latency_truncation_and_batch_miss():
    scheduler = AdaptiveOcrScheduler(scheduler_profile("fast"))
    decision = scheduler.observe(
        RuntimeSignals(
            request_count=20,
            http_5xx_count=1,
            p50_latency_ms=10_000,
            p95_latency_ms=50_000,
            truncation_rate=0.10,
            batch_miss_rate=0.05,
        )
    )
    assert decision.action == "decrease"
    assert set(decision.reasons) == {
        "http_5xx",
        "p95_latency",
        "output_truncation",
        "batch_integrity",
    }
    verifier = decision.policies[OcrStage.VISUAL_VERIFICATION]
    assert verifier.workers == 3
    assert verifier.batch_size == 4
    assert verifier.queue_capacity <= scheduler.profile.pool(
        OcrStage.VISUAL_VERIFICATION
    ).queue_capacity
    assert scheduler.batch_size_for(OcrStage.FULL_OCR, math_dense=True) == 1
    assert scheduler.batch_size_for(OcrStage.FULL_OCR, complex_layout=True) == 1
    assert scheduler.batch_size_for(OcrStage.FULL_OCR, crop_retry=True) == 1


def test_failed_batch_is_bisected_without_changing_page_ids():
    pages = tuple(f"ocr-page-{number:06d}" for number in range(1, 8))
    parts = split_failed_batch(pages)
    assert parts == (pages[:4], pages[4:])
    assert parts[0] + parts[1] == pages
    assert split_failed_batch((pages[0],)) == ((pages[0],),)
    with pytest.raises(ValueError, match="duplicate"):
        split_failed_batch((pages[0], pages[0]))


def test_budget_advice_pauses_new_model_work_near_real_limit_only():
    limits = BudgetLimits(
        max_input_tokens=1_000,
        max_requests=100,
        max_cost=10.0,
        max_wall_time_minutes=30,
    )
    advice = advise_budget_pause(
        limits,
        BudgetUsage(input_tokens=None, requests=90, cost=8.5, wall_time_minutes=12),
    )
    assert advice.should_pause_new_model_tasks is True
    assert advice.finish_current_atomic_task is True
    assert advice.leave_unstarted_pages_pending is True
    assert advice.reasons == ("requests",)
    assert advice.ratios["requests"] == pytest.approx(0.9)
    assert advice.ratios["input_tokens"] is None

    unknown = advise_budget_pause(limits, BudgetUsage())
    assert unknown.should_pause_new_model_tasks is False
    assert all(value is None for value in unknown.ratios.values())


def test_metrics_report_exact_stage_latency_throughput_requests_usage_and_resources():
    collector = OcrMetricsCollector(
        "run-real-measurements",
        selected_pages=4,
        started_at_seconds=0.0,
        clock=lambda: 60.0,
    )
    for duration in (10.0, 20.0, 30.0, 100.0):
        collector.record_stage_execution(
            OcrStage.VISUAL_VERIFICATION,
            duration_ms=duration,
        )
    collector.record_stage_execution(OcrStage.PERSISTENCE, duration_ms=5.0, items=3)
    collector.record_page_result(
        "ocr-page-000001",
        status=PageFinalStatus.SUCCESS,
        strategy=OcrStrategy.OBJECT_LAYER_VERIFIED,
        completed_at_seconds=10.0,
        dpi_history=(160,),
    )
    collector.record_page_result(
        "ocr-page-000002",
        status=PageFinalStatus.NEEDS_REVIEW,
        strategy=OcrStrategy.FULL_VISUAL_OCR,
        completed_at_seconds=20.0,
        dpi_history=(200, 300),
    )
    collector.record_page_result(
        "ocr-page-000003",
        status=PageFinalStatus.FAILED,
        strategy=OcrStrategy.HIGH_RESOLUTION_RETRY,
        completed_at_seconds=30.0,
        dpi_history=(200, 300),
    )
    collector.record_request(
        "call-1",
        kind=RequestKind.VISUAL_VERIFICATION,
        latency_ms=100.0,
        page_count=4,
        status_code=200,
        input_tokens=1_000,
        output_tokens=100,
        cost="0.25",
        currency="USD",
        dpi=160,
        retry=False,
        truncated=False,
        strong_model=False,
    )
    collector.record_request(
        "call-2",
        kind=RequestKind.HIGH_RESOLUTION_RETRY,
        latency_ms=500.0,
        status_code=429,
        input_tokens=200,
        output_tokens=20,
        cost="0.05",
        currency="USD",
        dpi=300,
        retry=True,
        truncated=True,
        strong_model=True,
    )
    collector.record_resource_sample(memory_bytes=100, cpu_percent=20.0)
    collector.record_resource_sample(memory_bytes=250, cpu_percent=80.0)

    report = collector.performance_metrics(now_seconds=60.0)
    assert report["schema_version"] == PERFORMANCE_METRICS_SCHEMA
    assert report["pages"] == {
        "selected": 4,
        "coverage_completed": 3,
        "remaining": 1,
        "by_final_status": {"FAILED": 1, "NEEDS_REVIEW": 1, "SUCCESS": 1},
    }
    verifier = report["stages"]["visual_verification"]
    assert verifier["completed"] == 4
    assert verifier["latency_ms"] == {"samples": 4, "p50": 20.0, "p95": 100.0}
    assert report["throughput"]["average_pages_per_minute"] == pytest.approx(3.0)
    assert report["throughput"]["recent_pages_per_minute"] == pytest.approx(3.0)
    assert report["throughput"]["eta_seconds"] == pytest.approx(20.0)
    assert report["strategy_distribution"] == {
        "full_visual_ocr": 1,
        "high_resolution_retry": 1,
        "object_layer_verified": 1,
    }
    assert report["dpi_pages"] == {"160": 1, "200": 2, "300": 2}
    assert report["requests"]["total"] == 2
    assert report["requests"]["http_429"] == 1
    assert report["requests"]["http_5xx"] == 0
    assert report["requests"]["automatic_retries"] == 1
    assert report["requests"]["output_truncations"] == 1
    assert report["requests"]["latency_ms"] == {
        "samples": 2,
        "p50": 100.0,
        "p95": 500.0,
    }
    assert report["usage"]["input_tokens"] == 1_200
    assert report["usage"]["output_tokens"] == 120
    assert report["usage"]["cost"] == pytest.approx(0.30)
    assert report["usage"]["currency"] == "USD"
    assert report["resources"] == {
        "peak_memory_bytes": 250,
        "peak_cpu_percent": 80.0,
        "samples": 2,
        "memory_samples": 2,
        "cpu_samples": 2,
    }

    cost = collector.cost_report(
        budget_limits=BudgetLimits(
            max_input_tokens=2_400,
            max_output_tokens=240,
            max_requests=4,
            max_strong_model_calls=2,
            max_cost=0.60,
        )
    )
    assert cost["schema_version"] == COST_REPORT_SCHEMA
    assert cost["actual"] == {
        "requests": 2,
        "strong_model_calls": 1,
        "input_tokens": 1_200,
        "output_tokens": 120,
        "cost": pytest.approx(0.30),
        "currency": "USD",
    }
    assert all(value == pytest.approx(0.5) for value in cost["ratios"].values())


def test_metrics_keep_unprovided_provider_and_machine_values_null():
    collector = OcrMetricsCollector(
        "run-unknown-measurements",
        selected_pages=2,
        started_at_seconds=0.0,
        clock=lambda: 10.0,
    )
    collector.record_request(
        "call-without-provider-usage",
        kind=RequestKind.FULL_OCR,
        latency_ms=250.0,
    )
    collector.record_page_result(
        "ocr-page-000001",
        status=PageFinalStatus.SUCCESS,
        strategy=None,
        completed_at_seconds=5.0,
    )

    performance = collector.performance_metrics(now_seconds=10.0)
    assert performance["usage"]["input_tokens"] is None
    assert performance["usage"]["output_tokens"] is None
    assert performance["usage"]["cost"] is None
    assert performance["usage"]["observed_input_tokens"] == 0
    assert performance["usage"]["input_token_coverage"]["complete"] is False
    assert performance["requests"]["automatic_retries"] is None
    assert performance["requests"]["output_truncations"] is None
    assert performance["requests"]["http_429"] == 0
    assert performance["requests"]["status_code_coverage"]["complete"] is False
    assert performance["resources"]["peak_memory_bytes"] is None
    assert performance["resources"]["peak_cpu_percent"] is None
    assert performance["strategy_measurement"]["complete"] is False

    cost = collector.cost_report(
        budget_limits=BudgetLimits(
            max_input_tokens=1_000,
            max_output_tokens=1_000,
            max_cost=10.0,
        )
    )
    assert cost["actual"]["input_tokens"] is None
    assert cost["actual"]["output_tokens"] is None
    assert cost["actual"]["cost"] is None
    assert cost["ratios"]["input_tokens"] is None
    assert cost["ratios"]["output_tokens"] is None
    assert cost["ratios"]["cost"] is None


def test_metrics_reports_are_real_json_and_refuse_silent_overwrite(tmp_path):
    collector = OcrMetricsCollector(
        "run-report-files",
        selected_pages=1,
        started_at_seconds=0.0,
        clock=lambda: 60.0,
    )
    collector.record_page_result(
        "ocr-page-000001",
        status="SUCCESS",
        strategy="object_layer_verified",
        completed_at_seconds=60.0,
        dpi_history=(160,),
    )
    canonical = collector.canonical_reports(now_seconds=60.0)
    paths = collector.write_reports(tmp_path, now_seconds=60.0)
    assert set(paths) == {"performance_metrics", "cost_report"}
    assert paths["performance_metrics"].read_bytes() == canonical["performance_metrics"]
    assert paths["cost_report"].read_bytes() == canonical["cost_report"]
    assert json.loads(paths["performance_metrics"].read_text(encoding="utf-8"))[
        "schema_version"
    ] == PERFORMANCE_METRICS_SCHEMA
    assert json.loads(paths["cost_report"].read_text(encoding="utf-8"))[
        "schema_version"
    ] == COST_REPORT_SCHEMA
    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        collector.write_reports(tmp_path, now_seconds=60.0)


def test_metrics_reject_duplicate_identity_and_impossible_stage_counts():
    collector = OcrMetricsCollector(
        "run-integrity",
        selected_pages=1,
        started_at_seconds=0.0,
        clock=lambda: 1.0,
    )
    collector.submit_stage(OcrStage.RENDERING)
    with pytest.raises(ValueError, match="submitted"):
        collector.start_stage(OcrStage.RENDERING, items=2)
    collector.start_stage(OcrStage.RENDERING)
    collector.finish_stage(OcrStage.RENDERING, duration_ms=5.0)
    collector.record_page_result(
        "ocr-page-000001",
        status="SUCCESS",
        strategy="object_layer_verified",
        completed_at_seconds=1.0,
    )
    with pytest.raises(ValueError, match="append-only"):
        collector.record_page_result(
            "ocr-page-000001",
            status="SUCCESS",
            strategy="object_layer_verified",
            completed_at_seconds=1.0,
        )
    collector.record_request(
        "call-unique",
        kind="visual_verification",
        latency_ms=10.0,
    )
    with pytest.raises(ValueError, match="append-only"):
        collector.record_request(
            "call-unique",
            kind="visual_verification",
            latency_ms=10.0,
        )

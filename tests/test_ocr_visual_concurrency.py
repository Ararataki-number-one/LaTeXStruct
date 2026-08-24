from __future__ import annotations

import threading
import time

from latexstruct.server import app as srv


def test_visual_pool_is_truly_concurrent_bounded_and_commits_in_frozen_order():
    groups = tuple(
        tuple(range(batch * 4, batch * 4 + 4))
        for batch in range(12)
    )
    lock = threading.Lock()
    first_wave_ready = threading.Event()
    active = 0
    max_active = 0
    first_wave_count = 0
    finish_order: list[int] = []
    commit_order: list[int] = []

    def prepare(group_index, group):
        return group_index, group

    def verify(group_index, _group, prepared):
        nonlocal active, max_active, first_wave_count
        with lock:
            active += 1
            max_active = max(max_active, active)
            if group_index < 4:
                first_wave_count += 1
                if first_wave_count == 4:
                    first_wave_ready.set()
        assert first_wave_ready.wait(5.0)
        if group_index == 0:
            time.sleep(0.03)
        with lock:
            finish_order.append(group_index)
            active -= 1
        return prepared

    def commit(group_index, _group, result, error):
        assert error is None
        assert result[0] == group_index
        commit_order.append(group_index)
        # Missing latency is not affirmative evidence for promotion.
        return {"had_error": False, "successful_requests": 1, "latency_ms": []}

    stats = srv._run_bounded_visual_pool(
        groups,
        prepare_group=prepare,
        verify_group=verify,
        commit_group=commit,
        control=lambda: None,
    )

    assert max_active == 4
    assert finish_order[0] != 0
    assert commit_order == list(range(len(groups)))
    assert stats["promoted"] is False
    assert stats["max_in_flight_batches"] == 4
    assert stats["max_in_flight_pages"] == 16
    assert stats["max_outstanding_batches"] <= 4


def test_visual_pool_promotes_to_six_only_after_four_low_latency_clean_requests():
    groups = tuple(
        tuple(range(batch * 4, batch * 4 + 4))
        for batch in range(12)
    )
    lock = threading.Lock()
    first_wave_ready = threading.Event()
    promoted_wave_ready = threading.Event()
    active = 0
    max_active = 0
    first_wave_count = 0

    def verify(group_index, _group, prepared):
        nonlocal active, max_active, first_wave_count
        with lock:
            active += 1
            max_active = max(max_active, active)
            if group_index < 4:
                first_wave_count += 1
                if first_wave_count == 4:
                    first_wave_ready.set()
            if group_index >= 4 and active == 6:
                promoted_wave_ready.set()
        if group_index < 4:
            assert first_wave_ready.wait(5.0)
        else:
            assert promoted_wave_ready.wait(5.0)
        with lock:
            active -= 1
        return prepared

    def commit(_group_index, _group, _result, error):
        assert error is None
        return {
            "had_error": False,
            "successful_requests": 1,
            "latency_ms": [5.0],
        }

    stats = srv._run_bounded_visual_pool(
        groups,
        prepare_group=lambda group_index, group: (group_index, group),
        verify_group=verify,
        commit_group=commit,
        control=lambda: None,
    )

    assert promoted_wave_ready.is_set()
    assert max_active == 6
    assert stats["promoted"] is True
    assert stats["final_workers"] == 6
    assert stats["successful_requests"] == len(groups)
    assert stats["latency_p95_ms"] == 5.0
    assert stats["max_in_flight_batches"] == 6
    assert stats["max_in_flight_pages"] == 24
    assert stats["max_outstanding_batches"] <= 6


def test_visual_pool_worker_exception_is_group_local_and_permanently_blocks_boost():
    groups = tuple((f"ocr-page-{index:06d}",) for index in range(1, 13))
    failed: list[tuple[int, tuple[str, ...], str]] = []
    committed: list[int] = []

    def verify(group_index, _group, prepared):
        if group_index == 1:
            raise RuntimeError("verifier transport failed")
        return prepared

    def commit(group_index, group, _result, error):
        committed.append(group_index)
        if error is not None:
            failed.append((group_index, group, str(error)))
        return {
            "had_error": error is not None,
            "successful_requests": 0 if error is not None else 1,
            "latency_ms": [] if error is not None else [1.0],
        }

    stats = srv._run_bounded_visual_pool(
        groups,
        prepare_group=lambda _group_index, group: group,
        verify_group=verify,
        commit_group=commit,
        control=lambda: None,
    )

    assert committed == list(range(len(groups)))
    assert failed == [(1, groups[1], "verifier transport failed")]
    assert stats["promotion_blocked"] is True
    assert stats["promoted"] is False
    assert stats["max_in_flight_batches"] <= 4
    assert stats["max_outstanding_batches"] <= 4

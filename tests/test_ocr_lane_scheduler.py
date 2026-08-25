import threading

import pytest

from latexstruct.core.ocr_lane_scheduler import run_overlapping_ocr_lanes


INDEX = {"p1": 1, "p2": 2, "p3": 3}


def _run(initial, *, visual, process, recover=lambda: (), limit=lambda: 3):
    return run_overlapping_ocr_lanes(
        initial,
        run_visual_lane=visual,
        process_full_ocr_batch=process,
        selected_index=INDEX.__getitem__,
        batch_limit=limit,
        recoverable_full_ocr_page_ids=recover,
        idle_poll_seconds=0.01,
    )


def test_first_visual_escalation_starts_full_ocr_while_later_verifier_is_blocked():
    full_started = threading.Event()
    release_later_verifier = threading.Event()
    observations = []

    def visual(enqueue):
        enqueue("p1")
        assert full_started.wait(2)
        observations.append("later-verifier-still-open")
        assert release_later_verifier.wait(2)

    def process(page_ids):
        assert page_ids == ("p1",)
        full_started.set()
        release_later_verifier.set()
        return {"pages": list(page_ids)}

    result = _run([], visual=visual, process=process, limit=lambda: 1)

    assert observations == ["later-verifier-still-open"]
    assert result["processed_page_ids"] == ["p1"]


def test_duplicate_live_publication_fails_closed():
    def visual(enqueue):
        enqueue("p1")
        enqueue("p1")

    with pytest.raises(ValueError, match="duplicate full OCR lane publication"):
        _run([], visual=visual, process=lambda _items: {})


def test_initial_pages_are_claimed_once_in_frozen_order():
    seen = []
    result = _run(
        ["p3", "p1", "p2"],
        visual=lambda _enqueue: None,
        process=lambda items: seen.extend(items) or {"count": len(items)},
    )

    assert seen == ["p1", "p2", "p3"]
    assert result["claimed_pages"] == 3


def test_durable_route_written_before_missing_callback_is_recovered_once():
    durable = []

    def visual(_enqueue):
        durable.append("p2")  # crash window: sidecar exists, callback did not run

    result = _run(
        [],
        visual=visual,
        process=lambda items: {"pages": list(items)},
        recover=lambda: tuple(durable),
    )

    assert result["processed_page_ids"] == ["p2"]
    assert result["claimed_pages"] == 1

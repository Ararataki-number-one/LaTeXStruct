from __future__ import annotations

import threading

import pytest

from latexstruct.server import app as srv


def _pages(count: int = 12) -> tuple[dict[str, object], ...]:
    return tuple(
        {
            "selected_index": index,
            "page_id": f"ocr-page-{index:06d}",
        }
        for index in range(1, count + 1)
    )


def test_render_prepare_pool_is_bounded_concurrent_and_consumes_in_frozen_order():
    lock = threading.Lock()
    first_wave_ready = threading.Event()
    later_page_finished = threading.Event()
    active = 0
    max_active = 0
    first_wave_count = 0
    finish_order: list[int] = []
    consumed_order: list[int] = []

    def prepare(page):
        nonlocal active, max_active, first_wave_count
        index = int(page["selected_index"])
        with lock:
            active += 1
            max_active = max(max_active, active)
            if index <= 3:
                first_wave_count += 1
                if first_wave_count == 3:
                    first_wave_ready.set()
        assert first_wave_ready.wait(2.0)
        if index == 1:
            assert later_page_finished.wait(2.0)
        elif index == 2:
            later_page_finished.set()
        with lock:
            finish_order.append(index)
            active -= 1
        return f"prepared-{index}"

    def consume(batch):
        consumed_order.extend(int(page["selected_index"]) for page, _value in batch)

    stats = srv._run_bounded_page_prepare_pool(
        tuple(reversed(_pages())),
        selected_index=lambda page: page["selected_index"],
        page_id=lambda page: page["page_id"],
        prepare_page=prepare,
        consume_batch=consume,
        batch_limit=2,
        control=lambda: None,
        workers=3,
    )

    assert max_active == 3
    assert finish_order[0] != 1
    assert consumed_order == list(range(1, 13))
    assert stats == {
        "workers": 3,
        "outstanding_limit": 6,
        "submitted_pages": 12,
        "prepared_pages": 12,
        "failed_pages": 0,
        "skipped_pages": 0,
        "consumed_pages": 12,
        "consumed_batches": 6,
        "max_in_flight": 6,
        "max_outstanding": 6,
    }


def test_render_prepare_pool_isolates_one_page_failure_and_keeps_order():
    failures: list[tuple[int, str]] = []
    consumed: list[int] = []

    def prepare(page):
        index = int(page["selected_index"])
        if index == 3:
            raise RuntimeError("page-local render failure")
        return index

    stats = srv._run_bounded_page_prepare_pool(
        _pages(7),
        selected_index=lambda page: page["selected_index"],
        page_id=lambda page: page["page_id"],
        prepare_page=prepare,
        consume_batch=lambda batch: consumed.extend(value for _page, value in batch),
        batch_limit=2,
        control=lambda: None,
        on_prepare_error=lambda page, error: failures.append(
            (int(page["selected_index"]), str(error))
        ),
        workers=2,
    )

    assert failures == [(3, "page-local render failure")]
    assert consumed == [1, 2, 4, 5, 6, 7]
    assert stats["failed_pages"] == 1
    assert stats["prepared_pages"] == 6
    assert stats["consumed_pages"] == 6
    assert stats["max_outstanding"] <= 4


def test_render_prepare_pool_honours_immediate_control_stop():
    class StopRequested(RuntimeError):
        pass

    calls = 0

    def prepare(_page):
        nonlocal calls
        calls += 1

    with pytest.raises(StopRequested, match="cancelled"):
        srv._run_bounded_page_prepare_pool(
            _pages(2),
            selected_index=lambda page: page["selected_index"],
            page_id=lambda page: page["page_id"],
            prepare_page=prepare,
            consume_batch=lambda _batch: None,
            batch_limit=1,
            control=lambda: (_ for _ in ()).throw(StopRequested("cancelled")),
            workers=2,
        )

    assert calls == 0


@pytest.mark.parametrize(
    "field",
    ["selected_index", "page_id"],
)
def test_render_prepare_pool_rejects_duplicate_frozen_identity(field):
    pages = [dict(item) for item in _pages(2)]
    pages[1][field] = pages[0][field]

    with pytest.raises(ValueError, match=f"duplicate {field}"):
        srv._run_bounded_page_prepare_pool(
            pages,
            selected_index=lambda page: page["selected_index"],
            page_id=lambda page: page["page_id"],
            prepare_page=lambda page: page,
            consume_batch=lambda _batch: None,
            batch_limit=1,
            control=lambda: None,
            workers=2,
        )

"""Bounded overlap coordinator for visual verification and full-page OCR."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
import queue
import threading


def run_overlapping_ocr_lanes(
    initial_full_ocr_page_ids: Sequence[str],
    *,
    run_visual_lane: Callable[[Callable[[str], None]], None],
    process_full_ocr_batch: Callable[[tuple[str, ...]], Mapping[str, object]],
    selected_index: Callable[[str], int],
    batch_limit: Callable[[], int],
    recoverable_full_ocr_page_ids: Callable[[], Iterable[str]],
    idle_poll_seconds: float = 0.05,
) -> dict[str, object]:
    """Run both lanes concurrently while granting each page one full-OCR claim.

    The visual lane publishes a page only after its caller has persisted the
    route decision.  Once the visual lane is complete, ``recoverable_*`` closes
    the crash window where that durable write happened before the callback.
    Duplicate live publication is a scheduler invariant violation and fails
    closed; repeated recovery discovery is idempotent.
    """

    if not 0.001 <= float(idle_poll_seconds) <= 1.0:
        raise ValueError("lane idle poll must remain within 1 ms..1 s")
    work: queue.Queue[str] = queue.Queue()
    lock = threading.Lock()
    enqueued: set[str] = set()
    claimed: set[str] = set()
    visual_done = threading.Event()
    visual_errors: list[BaseException] = []

    def validate_page_id(page_id: str) -> str:
        value = str(page_id or "")
        index = selected_index(value)
        if not value or not isinstance(index, int) or isinstance(index, bool) or index < 1:
            raise ValueError("OCR lane page requires frozen identity")
        return value

    def enqueue(page_id: str, *, recovery: bool = False) -> bool:
        value = validate_page_id(page_id)
        with lock:
            if value in enqueued or value in claimed:
                if recovery:
                    return False
                raise ValueError(f"duplicate full OCR lane publication: {value}")
            enqueued.add(value)
            work.put(value)
            return True

    initial = [validate_page_id(page_id) for page_id in initial_full_ocr_page_ids]
    if len(initial) != len(set(initial)):
        raise ValueError("initial full OCR lane contains duplicate page_id")
    for page_id in sorted(initial, key=selected_index):
        enqueue(page_id)

    def visual_owner() -> None:
        try:
            run_visual_lane(lambda page_id: enqueue(page_id))
        except BaseException as exc:  # noqa: BLE001 - re-raised by coordinator
            visual_errors.append(exc)
        finally:
            visual_done.set()

    thread = threading.Thread(
        target=visual_owner,
        name="ocr-visual-lane",
        daemon=False,
    )
    thread.start()
    batches: list[dict[str, object]] = []
    processed_order: list[str] = []
    coordinator_error: BaseException | None = None
    try:
        while True:
            try:
                first = work.get(timeout=float(idle_poll_seconds))
            except queue.Empty:
                if not visual_done.is_set():
                    continue
                for page_id in sorted(
                    tuple(recoverable_full_ocr_page_ids()), key=selected_index
                ):
                    enqueue(page_id, recovery=True)
                if work.empty():
                    break
                continue

            limit = batch_limit()
            if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
                raise ValueError("full OCR lane batch limit must be positive")
            page_ids = [first]
            while len(page_ids) < limit:
                try:
                    page_ids.append(work.get_nowait())
                except queue.Empty:
                    break
            page_ids.sort(key=selected_index)
            with lock:
                for page_id in page_ids:
                    enqueued.remove(page_id)
                    if page_id in claimed:
                        raise ValueError(
                            f"duplicate full OCR lane claim: {page_id}"
                        )
                    claimed.add(page_id)
            result = dict(process_full_ocr_batch(tuple(page_ids)) or {})
            batches.append(result)
            processed_order.extend(page_ids)
            for _page_id in page_ids:
                work.task_done()
    except BaseException as exc:  # noqa: BLE001 - join the paid visual lane first
        coordinator_error = exc
    finally:
        thread.join()

    if coordinator_error is not None:
        raise coordinator_error
    if visual_errors:
        raise visual_errors[0]
    return {
        "processed_page_ids": processed_order,
        "claimed_pages": len(claimed),
        "batches": batches,
        "visual_lane_completed": True,
    }

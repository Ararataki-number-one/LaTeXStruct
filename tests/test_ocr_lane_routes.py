import hashlib
import json

import pytest

from latexstruct.core.ocr_lane_routes import (
    OcrLaneOwner,
    OcrLaneRoute,
    OcrLaneRouteStore,
    build_lane_routes_artifact,
    parse_lane_routes_artifact,
)


def _route(owner=OcrLaneOwner.VISUAL):
    return OcrLaneRoute(
        run_id="immutable-run",
        page_id="ocr-page-000001",
        source_page=7,
        selected_index=1,
        candidate_sha256=hashlib.sha256(b"candidate").hexdigest(),
        owner=owner,
    )


def test_visual_escalation_is_durable_and_recovers_without_visual_reassignment(tmp_path):
    store = OcrLaneRouteStore(tmp_path / "run")
    visual = store.create(_route())
    queued = store.transition(
        visual.page_id,
        OcrLaneOwner.FULL_OCR_QUEUED,
        verifier_response_sha256=hashlib.sha256(b"verifier").hexdigest(),
        reason="page-wide missing region",
    )
    in_flight = store.transition(queued.page_id, OcrLaneOwner.FULL_OCR_IN_FLIGHT)

    recovered = store.recover(in_flight.page_id)

    assert recovered is not None
    assert recovered.owner is OcrLaneOwner.FULL_OCR_QUEUED
    assert recovered.verifier_response_sha256 == queued.verifier_response_sha256
    assert recovered.candidate_sha256 == visual.candidate_sha256
    assert recovered.previous_route_sha256 == in_flight.route_sha256
    assert [event.owner for event in recovered.history] == [
        OcrLaneOwner.VISUAL,
        OcrLaneOwner.FULL_OCR_QUEUED,
        OcrLaneOwner.FULL_OCR_IN_FLIGHT,
        OcrLaneOwner.FULL_OCR_QUEUED,
    ]
    assert all(
        current.previous_event_sha256 == previous.event_sha256
        for previous, current in zip(recovered.history, recovered.history[1:])
    )
    with pytest.raises(ValueError, match="already exists"):
        store.create(_route())


def test_direct_full_ocr_has_one_owner_and_terminal_is_final(tmp_path):
    store = OcrLaneRouteStore(tmp_path / "run")
    direct = _route(OcrLaneOwner.FULL_OCR_QUEUED)
    store.create(direct)
    store.transition(direct.page_id, OcrLaneOwner.FULL_OCR_IN_FLIGHT)
    terminal = store.transition(direct.page_id, OcrLaneOwner.TERMINAL_FULL_OCR)

    assert store.list() == (terminal,)
    with pytest.raises(ValueError, match="illegal OCR lane transition"):
        store.transition(direct.page_id, OcrLaneOwner.FULL_OCR_QUEUED)


def test_terminal_local_review_never_recovers_into_full_ocr_queue(tmp_path):
    store = OcrLaneRouteStore(tmp_path / "run")
    visual = store.create(_route())
    terminal = store.transition(
        visual.page_id,
        OcrLaneOwner.TERMINAL_UNRESOLVED,
        verifier_response_sha256=hashlib.sha256(b"local-verifier").hexdigest(),
        reason="known block requires local review",
    )

    assert store.recover(terminal.page_id) == terminal
    with pytest.raises(ValueError, match="illegal OCR lane transition"):
        store.transition(terminal.page_id, OcrLaneOwner.FULL_OCR_QUEUED)


def test_verified_terminal_reconciliation_closes_recovered_full_ocr_queue(tmp_path):
    store = OcrLaneRouteStore(tmp_path / "run")
    direct = store.create(_route(OcrLaneOwner.FULL_OCR_QUEUED))
    in_flight = store.transition(
        direct.page_id, OcrLaneOwner.FULL_OCR_IN_FLIGHT
    )
    recovered = store.recover(in_flight.page_id)

    with pytest.raises(ValueError, match="illegal OCR lane transition"):
        store.transition(recovered.page_id, OcrLaneOwner.TERMINAL_FULL_OCR)

    terminal = store.reconcile_terminal(
        recovered.page_id,
        OcrLaneOwner.TERMINAL_FULL_OCR,
        reason="validated persisted SUCCESS response after restart",
    )

    assert terminal.owner is OcrLaneOwner.TERMINAL_FULL_OCR
    assert terminal.previous_route_sha256 == recovered.route_sha256
    assert [event.owner for event in terminal.history][-3:] == [
        OcrLaneOwner.FULL_OCR_IN_FLIGHT,
        OcrLaneOwner.FULL_OCR_QUEUED,
        OcrLaneOwner.TERMINAL_FULL_OCR,
    ]
    assert store.reconcile_terminal(
        terminal.page_id,
        OcrLaneOwner.TERMINAL_FULL_OCR,
    ) == terminal


@pytest.mark.parametrize(
    "retry_owner",
    [OcrLaneOwner.VISUAL, OcrLaneOwner.FULL_OCR_QUEUED],
)
def test_manual_retry_reopens_only_unresolved_and_preserves_hash_chain(
    tmp_path, retry_owner
):
    store = OcrLaneRouteStore(tmp_path / f"run-{retry_owner.value}")
    store.create(_route())
    terminal = store.transition(
        "ocr-page-000001",
        OcrLaneOwner.TERMINAL_UNRESOLVED,
        verifier_response_sha256=hashlib.sha256(b"verifier").hexdigest(),
        reason="bounded review required",
    )

    reopened = store.retry(
        terminal.page_id,
        retry_owner,
        reason="explicit manual retry with host-selected lane",
    )

    assert reopened.owner is retry_owner
    assert reopened.previous_route_sha256 == terminal.route_sha256
    assert reopened.history[-1].previous_event_sha256 == terminal.history[-1].event_sha256
    assert reopened.verifier_response_sha256 == terminal.verifier_response_sha256
    assert store.load(reopened.page_id) == reopened


def test_retry_and_reconciliation_special_paths_fail_closed(tmp_path):
    store = OcrLaneRouteStore(tmp_path / "run")
    visual = store.create(_route())
    with pytest.raises(ValueError, match="retry transition"):
        store.retry(
            visual.page_id,
            OcrLaneOwner.FULL_OCR_QUEUED,
            reason="not terminal",
        )
    with pytest.raises(ValueError, match="terminal reconciliation"):
        store.reconcile_terminal(
            visual.page_id,
            OcrLaneOwner.TERMINAL_FULL_OCR,
        )


def test_route_tampering_and_identity_mismatch_fail_closed(tmp_path):
    store = OcrLaneRouteStore(tmp_path / "run")
    route = store.create(_route())
    path = store.routes_dir / f"{route.page_id}.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["candidate_sha256"] = hashlib.sha256(b"tampered").hexdigest()
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        store.load(route.page_id)


def test_route_rejects_foreign_or_noncanonical_page_identity(tmp_path):
    with pytest.raises(ValueError, match="match page_id"):
        OcrLaneRoute(
            run_id="immutable-run",
            page_id="ocr-page-000002",
            source_page=1,
            selected_index=1,
            candidate_sha256=hashlib.sha256(b"candidate").hexdigest(),
            owner=OcrLaneOwner.VISUAL,
        )

    store = OcrLaneRouteStore(tmp_path / "run")
    with pytest.raises(ValueError, match="invalid OCR route page_id"):
        store.load("../escape")


def test_terminal_route_artifact_binds_every_selected_page_in_order():
    verifier_sha = hashlib.sha256(b"verifier").hexdigest()
    first = _route().transition(
        OcrLaneOwner.TERMINAL_VISUAL,
        verifier_response_sha256=verifier_sha,
    )
    second = OcrLaneRoute(
        run_id="immutable-run",
        page_id="ocr-page-000002",
        source_page=11,
        selected_index=2,
        candidate_sha256=hashlib.sha256(b"candidate-2").hexdigest(),
        owner=OcrLaneOwner.FULL_OCR_QUEUED,
    ).transition(OcrLaneOwner.FULL_OCR_IN_FLIGHT).transition(
        OcrLaneOwner.TERMINAL_FULL_OCR
    )

    data = build_lane_routes_artifact(
        run_id="immutable-run",
        selected_pages=(7, 11),
        routes=(second, first),
    )

    assert parse_lane_routes_artifact(
        data,
        expected_run_id="immutable-run",
        expected_selected_pages=(7, 11),
    ) == (first, second)
    assert json.loads(data)["terminal_counts"] == {
        "TERMINAL_FULL_OCR": 1,
        "TERMINAL_UNRESOLVED": 0,
        "TERMINAL_VISUAL": 1,
    }
    assert json.loads(data)["event_count"] == 5


def test_route_event_history_tampering_fails_closed(tmp_path):
    store = OcrLaneRouteStore(tmp_path / "run")
    visual = store.create(_route())
    terminal = store.transition(
        visual.page_id,
        OcrLaneOwner.TERMINAL_VISUAL,
        verifier_response_sha256=hashlib.sha256(b"verifier").hexdigest(),
    )
    path = store.routes_dir / f"{terminal.page_id}.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["history"][1]["reason"] = "tampered"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="event SHA-256 mismatch"):
        store.load(terminal.page_id)


def test_terminal_route_artifact_rejects_nonterminal_or_stale_coverage():
    with pytest.raises(ValueError, match="terminal ownership"):
        build_lane_routes_artifact(
            run_id="immutable-run",
            selected_pages=(7,),
            routes=(_route(),),
        )

    terminal = _route().transition(
        OcrLaneOwner.TERMINAL_VISUAL,
        verifier_response_sha256=hashlib.sha256(b"verifier").hexdigest(),
    )
    data = build_lane_routes_artifact(
        run_id="immutable-run",
        selected_pages=(7,),
        routes=(terminal,),
    )
    with pytest.raises(ValueError, match="identity|expected run or pages"):
        parse_lane_routes_artifact(
            data,
            expected_run_id="immutable-run",
            expected_selected_pages=(8,),
        )

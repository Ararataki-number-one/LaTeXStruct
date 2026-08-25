# -*- coding: utf-8 -*-
"""Production transport-budget wiring and persistence contracts."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pymupdf
import pytest

from latexstruct.pricing import estimate_call_cost
from latexstruct.core import analysis_production
from latexstruct.core.analysis_budget import (
    BudgetExhaustedError,
    LowPriorityBudgetStop,
)
from latexstruct.core.analysis_orchestrator import (
    CallBinding,
    FinalPageReviewRequest,
    FindingRequest,
    PageMaterials,
)
from latexstruct.core.analysis_schema import (
    ANALYSIS_RESPONSE_SCHEMA_VERSIONS,
    AnalysisRunSnapshot,
    CompileState,
    ModelBinding,
    PageMapEntry,
    sha256_bytes,
    sha256_text,
)


BASELINE_TEX = (
    "\\documentclass{article}\n"
    "\\begin{document}\n"
    "% Page 1\n"
    "Budget test page.\n"
    "\\end{document}\n"
)
PAGE_ID = "source-budget-page-000001"
PAGE_PNG = b"\x89PNG\r\n\x1a\nbudget-page-evidence"


def _pdf() -> bytes:
    document = pymupdf.open()
    try:
        page = document.new_page(width=240, height=320)
        page.insert_text((24, 48), "budget candidate")
        return document.tobytes(garbage=4, deflate=True)
    finally:
        document.close()


def _snapshot(**limits) -> AnalysisRunSnapshot:
    pdf = _pdf()
    values = {
        "max_input_tokens": 0,
        "max_output_tokens": 0,
        "max_cost": 0.0,
        "max_requests": 0,
        "max_strong_model_calls": 0,
        "max_wall_time_minutes": 120.0,
    }
    values.update(limits)
    return AnalysisRunSnapshot(
        run_id="production-budget-run",
        project_id="production-budget-project",
        workflow_version="analysis-loop-v2",
        prompt_version="analysis-prompts-v2",
        application_version="2.0.0",
        source_pdf_hash=sha256_bytes(pdf),
        raw_ocr_tex_hash=sha256_text(BASELINE_TEX),
        baseline_tex_hash=sha256_text(BASELINE_TEX),
        baseline_pdf_hash=sha256_bytes(pdf),
        page_count=1,
        page_range=(1,),
        latex_engine="xelatex",
        models=(
            ModelBinding("AI-1", "fake-budget-text", ("json",)),
            ModelBinding("AI-5", "fake-budget-vision", ("vision", "json")),
            ModelBinding("AI-6", "qwen3.7-flash", ("json", "adjudication")),
        ),
        concurrency_limit=1,
        started_at="2026-08-24T12:00:00+00:00",
        page_map=(
            PageMapEntry(PAGE_ID, 1, "% Page 1", ("candidate-page-000001",)),
        ),
        initial_compile_state=CompileState.COMPILED,
        config_hash=sha256_text("production-budget-config"),
        **values,
    )


class BudgetTextClient:
    model = "fake-budget-text"
    max_tokens = 32

    def __init__(self, *, usage=None) -> None:
        self.calls = 0
        self.usage = dict(
            usage
            or {"input_tokens": 10, "output_tokens": 2, "total_tokens": 12}
        )

    def chat_json(self, _system, user):
        self.calls += 1
        binding = json.loads(user)["binding"]
        return {"binding": binding, "findings": []}, dict(self.usage)


class FailingTextClient(BudgetTextClient):
    last_usage: dict[str, object] = {}

    def chat_json(self, _system, _user):
        self.calls += 1
        raise RuntimeError("transport failed after start")


class RetryingTextClient(BudgetTextClient):
    model = "qwen3.7-flash"

    def __init__(self) -> None:
        super().__init__(
            usage={"input_tokens": 7, "output_tokens": 3, "total_tokens": 10}
        )
        self.cfg = SimpleNamespace(max_tokens=32, max_retries=1)
        self.last_transport_attempts = []

    def chat_json(self, system, user):
        payload, usage = super().chat_json(system, user)
        self.last_transport_attempts = [
            {
                "attempt_number": 1,
                "succeeded": False,
                "usage_complete": True,
                "failure_stage": "http_error",
                "usage": {
                    "input_tokens": 5,
                    "output_tokens": 1,
                    "total_tokens": 6,
                },
            },
            {
                "attempt_number": 2,
                "succeeded": True,
                "usage_complete": True,
                "failure_stage": "",
                "usage": usage,
            },
        ]
        return payload, usage


class InvalidAttemptLedgerTextClient(BudgetTextClient):
    def __init__(self, *, over_bound: bool) -> None:
        super().__init__()
        self.cfg = SimpleNamespace(max_tokens=32, max_retries=0)
        self.over_bound = over_bound
        self.last_transport_attempts = []

    def chat_json(self, system, user):
        payload, usage = super().chat_json(system, user)
        if self.over_bound:
            self.last_transport_attempts = [
                {
                    "attempt_number": 1,
                    "succeeded": False,
                    "usage_complete": True,
                    "failure_stage": "http_error",
                    "usage": {
                        "input_tokens": 5,
                        "output_tokens": 1,
                        "total_tokens": 6,
                    },
                },
                {
                    "attempt_number": 2,
                    "succeeded": True,
                    "usage_complete": True,
                    "failure_stage": "",
                    "usage": usage,
                },
            ]
        else:
            self.last_transport_attempts = [
                {
                    "attempt_number": 1,
                    "succeeded": True,
                    "usage_complete": True,
                    "failure_stage": "timeout",
                    "usage": usage,
                }
            ]
        return payload, usage


class BudgetVisionClient:
    model = "fake-budget-vision"
    max_tokens = 32

    def __init__(self) -> None:
        self.calls = 0

    def chat_vision_json_images_bytes(self, _system, user, _images, *, schema=None):
        assert isinstance(schema, dict)
        self.calls += 1
        binding = json.loads(user)["binding"]
        return {
            "binding": binding,
            "content_conservation_ok": True,
            "math_conservation_ok": True,
            "visual_review_ok": True,
            "formal_inventory_ok": True,
            "new_high_risk_issues": 0,
            "prior_pass_conclusion_visible": False,
        }, {"input_tokens": 8, "output_tokens": 2, "total_tokens": 10}


def _bridge(tmp_path, snapshot, *, text_client=None, vision_client=None):
    pdf = _pdf()
    text = text_client or BudgetTextClient()
    vision = vision_client or BudgetVisionClient()
    bridge = analysis_production._ProductionCallbacks(
        snapshot=snapshot,
        source_pages={PAGE_ID: PAGE_PNG},
        source_page_numbers={PAGE_ID: 1},
        candidate_page_map={1: (1,)},
        candidate_page_mapper=None,
        host_inventory_expectations_by_page={},
        host_inventory_bundle_digest=sha256_text("empty-host-inventory"),
        baseline_pdf=pdf,
        text_clients={"AI-1": text, "AI-6": text},
        vision_clients={"AI-5": vision},
        compiler=lambda *_args, **_kwargs: {},
        compile_extra_files={},
        cache_root=tmp_path / ".model-response-cache",
        machine_verifier=lambda _request: {},
    )
    bridge._page_map_for_candidate(snapshot.baseline_tex_hash, pdf=pdf)
    return bridge


def _materials(snapshot, *, current_tex=BASELINE_TEX) -> PageMaterials:
    return PageMaterials(
        source_page_id=PAGE_ID,
        candidate_hash=snapshot.baseline_tex_hash,
        source_pdf_page=PAGE_PNG,
        baseline_tex_region=BASELINE_TEX,
        current_tex_region=current_tex,
        current_pdf_page=PAGE_PNG,
    )


def _binding(snapshot, materials, *, role, operation, issue_id) -> CallBinding:
    return CallBinding(
        run_id=snapshot.run_id,
        role=role,
        candidate_hash=materials.candidate_hash,
        source_page_id=materials.source_page_id,
        issue_id=issue_id,
        material_hashes=materials.hashes,
        snapshot_hash=snapshot.snapshot_hash,
        prompt_version=snapshot.prompt_version,
        response_schema_version=ANALYSIS_RESPONSE_SCHEMA_VERSIONS[operation],
    )


def _finding_request(snapshot, *, current_tex=BASELINE_TEX) -> FindingRequest:
    materials = _materials(snapshot, current_tex=current_tex)
    return FindingRequest(
        _binding(
            snapshot,
            materials,
            role="AI-1",
            operation="structure-findings",
            issue_id="DISCOVERY-AI-1-budget",
        ),
        materials,
    )


def _final_review_request(snapshot) -> FinalPageReviewRequest:
    materials = _materials(snapshot)
    return FinalPageReviewRequest(
        binding=_binding(
            snapshot,
            materials,
            role="AI-5",
            operation="final-review-1",
            issue_id="FINAL-REVIEW-budget-1",
        ),
        materials=materials,
        pass_number=1,
        context_id="budget-review-context",
    )


def test_request_hard_limit_rejects_second_high_priority_transport(tmp_path):
    snapshot = _snapshot(max_requests=1)
    vision = BudgetVisionClient()
    bridge = _bridge(tmp_path, snapshot, vision_client=vision)
    request = _final_review_request(snapshot)

    bridge.ai5_final_review(request)
    with pytest.raises(BudgetExhaustedError, match="limit_reached:requests"):
        bridge.ai5_final_review(request)

    assert vision.calls == 1
    assert bridge.budget.usage.requests == 1
    assert bridge.budget.stop_reason == "LIMIT_REACHED"
    assert bridge.budget.active_reservations == ()


def test_budget_state_replace_fsyncs_its_parent_directory(tmp_path, monkeypatch):
    fsynced = []
    monkeypatch.setattr(
        analysis_production,
        "_fsync_directory",
        lambda path: fsynced.append(path),
    )
    _bridge(tmp_path, _snapshot())

    assert fsynced == [tmp_path]


def test_reservation_save_failure_is_fatal_poisoned_and_never_starts_transport(
    tmp_path,
    monkeypatch,
):
    snapshot = _snapshot(max_requests=5)
    client = BudgetTextClient()
    bridge = _bridge(tmp_path, snapshot, text_client=client)
    durable_before = (tmp_path / "analysis_budget.json").read_bytes()

    def fail_save(_budget):
        raise OSError("injected reservation save failure")

    monkeypatch.setattr(bridge._budget_store, "save", fail_save)
    with pytest.raises(analysis_production.BudgetPersistenceError) as caught:
        bridge.ai1_structure(_finding_request(snapshot))

    assert caught.value.retryable is False
    assert caught.value.fatal_analysis is True
    assert client.calls == 0
    assert bridge.budget.active_reservations == ()
    assert bridge.budget.usage.requests == 0
    assert (tmp_path / "analysis_budget.json").read_bytes() == durable_before

    with pytest.raises(analysis_production.BudgetPersistenceError, match="poisoned"):
        bridge.ai1_structure(_finding_request(snapshot))
    assert client.calls == 0


def test_commit_save_failure_is_fatal_and_cannot_retransport(
    tmp_path,
    monkeypatch,
):
    snapshot = _snapshot(max_requests=5)
    client = BudgetTextClient()
    bridge = _bridge(tmp_path, snapshot, text_client=client)
    original_save = bridge._budget_store.save
    save_calls = 0

    def fail_second_save(budget):
        nonlocal save_calls
        save_calls += 1
        if save_calls == 2:
            raise OSError("injected commit save failure")
        return original_save(budget)

    monkeypatch.setattr(bridge._budget_store, "save", fail_second_save)
    with pytest.raises(analysis_production.BudgetPersistenceError) as caught:
        bridge.ai1_structure(_finding_request(snapshot))

    assert caught.value.retryable is False
    assert caught.value.fatal_analysis is True
    assert client.calls == 1
    # The published in-memory authority remains the last durable reservation
    # state; it never pretends that the failed commit reached disk.
    assert len(bridge.budget.active_reservations) == 1
    assert bridge.budget.usage.requests == 0
    persisted = json.loads((tmp_path / "analysis_budget.json").read_text("utf-8"))
    assert len(persisted["budget"]["reservations"]) == 1

    with pytest.raises(analysis_production.BudgetPersistenceError, match="poisoned"):
        bridge.ai1_structure(_finding_request(snapshot))
    assert client.calls == 1


def test_post_replace_fsync_failure_poison_handles_new_durable_winner(
    tmp_path,
    monkeypatch,
):
    snapshot = _snapshot(max_requests=5)
    client = BudgetTextClient()
    bridge = _bridge(tmp_path, snapshot, text_client=client)
    original_fsync_directory = analysis_production._fsync_directory
    fsync_calls = 0

    def fail_commit_directory_fsync(path):
        nonlocal fsync_calls
        fsync_calls += 1
        if fsync_calls == 2:
            raise OSError("injected post-replace directory fsync failure")
        return original_fsync_directory(path)

    monkeypatch.setattr(
        analysis_production,
        "_fsync_directory",
        fail_commit_directory_fsync,
    )
    with pytest.raises(analysis_production.BudgetPersistenceError, match="poisoned"):
        bridge.ai1_structure(_finding_request(snapshot))

    assert client.calls == 1
    assert len(bridge.budget.active_reservations) == 1
    assert bridge.budget.usage.requests == 0
    # os.replace happened before the injected directory-fsync failure, so this
    # fault demonstrates why the live bridge cannot guess a rollback winner.
    persisted = json.loads((tmp_path / "analysis_budget.json").read_text("utf-8"))
    assert persisted["budget"]["reservations"] == []
    assert persisted["budget"]["usage"]["requests"] == 1

    reopened = _bridge(tmp_path, snapshot, text_client=BudgetTextClient())
    assert reopened.budget.active_reservations == ()
    assert reopened.budget.usage.requests == 1


def test_durable_gate_rejects_active_reservations_and_poison_stops_new_work(
    tmp_path,
):
    snapshot = _snapshot(max_requests=5)
    client = BudgetTextClient()
    bridge = _bridge(tmp_path, snapshot, text_client=client)
    bridge._reserve_transport_budget(
        role="AI-1",
        client=client,
        system="system",
        user="user",
        schema={"type": "object"},
    )

    with pytest.raises(analysis_production.BudgetClosureError) as caught:
        bridge.budget_state()
    assert caught.value.retryable is False
    assert caught.value.fatal_analysis is True

    with pytest.raises(analysis_production.BudgetPersistenceError, match="poisoned"):
        bridge._reserve_transport_budget(
            role="AI-1",
            client=client,
            system="system-2",
            user="user-2",
            schema={"type": "object"},
        )
    assert client.calls == 0


def test_near_limit_stops_low_priority_before_transport(tmp_path):
    snapshot = _snapshot(max_requests=2)
    client = BudgetTextClient()
    bridge = _bridge(tmp_path, snapshot, text_client=client)

    assert bridge.ai1_structure(_finding_request(snapshot)) == ()
    with pytest.raises(LowPriorityBudgetStop, match="near_limit:requests"):
        bridge.ai1_structure(
            _finding_request(snapshot, current_tex=BASELINE_TEX + "% changed material\n")
        )

    assert client.calls == 1
    assert bridge.budget.usage.requests == 1
    assert bridge.budget.stop_reason == "STOP_LOW_PRIORITY"
    persisted = json.loads((tmp_path / "analysis_budget.json").read_text("utf-8"))
    assert persisted["budget"]["stop_reason"] == "STOP_LOW_PRIORITY"


def test_transport_exception_commits_request_and_unknown_usage(tmp_path):
    snapshot = _snapshot(max_requests=5)
    client = FailingTextClient()
    bridge = _bridge(tmp_path, snapshot, text_client=client)

    with pytest.raises(RuntimeError, match="transport failed after start"):
        bridge.ai1_structure(_finding_request(snapshot))

    usage = bridge.budget.usage
    assert client.calls == 1
    assert usage.requests == 1
    assert usage.unknown_input_token_requests == 1
    assert usage.unknown_output_token_requests == 1
    assert usage.unknown_cost_requests == 1
    assert usage.input_tokens is None
    assert usage.output_tokens is None
    assert usage.cost is None
    assert bridge.budget.active_reservations == ()
    assert len(bridge.transport_evidence) == 1


def test_cache_hit_does_not_charge_request_and_reopens_budget(tmp_path):
    snapshot = _snapshot(max_requests=5)
    first_client = BudgetTextClient()
    first = _bridge(tmp_path, snapshot, text_client=first_client)
    request = _finding_request(snapshot)

    assert first.ai1_structure(request) == ()
    assert first.budget.usage.requests == 1

    resumed_client = BudgetTextClient()
    resumed = _bridge(tmp_path, snapshot, text_client=resumed_client)
    assert resumed.ai1_structure(request) == ()

    assert resumed_client.calls == 0
    assert resumed.budget.usage.requests == 1
    assert len(resumed.cache_hit_evidence) == 1
    assert not list(tmp_path.glob(".analysis_budget.json.*.tmp"))


def test_orphaned_reservation_is_committed_unknown_on_atomic_reopen(tmp_path):
    snapshot = _snapshot(max_requests=5)
    client = BudgetTextClient()
    first = _bridge(tmp_path, snapshot, text_client=client)
    reservation = first._reserve_transport_budget(
        role="AI-1",
        client=client,
        system="system",
        user="user",
        schema={"type": "object"},
    )
    assert reservation in first.budget.active_reservations

    persisted = json.loads((tmp_path / "analysis_budget.json").read_text("utf-8"))
    assert len(persisted["budget"]["reservations"]) == 1

    resumed = _bridge(tmp_path, snapshot, text_client=BudgetTextClient())
    usage = resumed.budget.usage
    assert usage.requests == 1
    assert usage.unknown_input_token_requests == 1
    assert usage.unknown_output_token_requests == 1
    assert usage.unknown_cost_requests == 1
    assert resumed.budget.active_reservations == ()
    reloaded = json.loads((tmp_path / "analysis_budget.json").read_text("utf-8"))
    assert reloaded["budget"]["reservations"] == []
    reopened_again = _bridge(tmp_path, snapshot, text_client=BudgetTextClient())
    assert reopened_again.budget.usage.requests == 1


def test_ai6_is_the_only_strong_call_and_strict_cost_is_recorded(tmp_path):
    snapshot = _snapshot(
        max_cost=1.0,
        max_requests=5,
        max_strong_model_calls=1,
    )
    usage = {"input_tokens": 1_000, "output_tokens": 100, "total_tokens": 1_100}
    client = BudgetTextClient(usage=usage)
    client.model = "qwen3.7-flash"
    bridge = _bridge(tmp_path, snapshot, text_client=client)
    materials = _materials(snapshot)
    request = FindingRequest(
        _binding(
            snapshot,
            materials,
            role="AI-6",
            operation="adjudication",
            issue_id="ISS-budget-adjudication",
        ),
        materials,
    )

    bridge._text(
        "AI-6",
        "adjudication",
        request,
        "system",
        {"type": "object"},
    )
    expected = estimate_call_cost("qwen3.7-flash", usage)
    assert expected is not None
    assert bridge.budget.usage.strong_model_calls == 1
    assert bridge.budget.usage.cost == pytest.approx(expected["cny"])

    with pytest.raises(BudgetExhaustedError, match="strong_model_calls"):
        bridge._text(
            "AI-6",
            "adjudication",
            request,
            "system",
            {"type": "object"},
        )
    assert client.calls == 1


def test_retry_bound_and_complete_attempt_ledger_are_accounted(tmp_path):
    snapshot = _snapshot(
        max_cost=1.0,
        max_requests=2,
        max_strong_model_calls=2,
    )
    client = RetryingTextClient()
    bridge = _bridge(tmp_path, snapshot, text_client=client)
    materials = _materials(snapshot)
    request = FindingRequest(
        _binding(
            snapshot,
            materials,
            role="AI-6",
            operation="adjudication",
            issue_id="ISS-budget-retry",
        ),
        materials,
    )

    bridge._text(
        "AI-6",
        "adjudication",
        request,
        "system",
        {"type": "object"},
    )

    usage = bridge.budget.usage
    assert usage.requests == 2
    assert usage.strong_model_calls == 2
    assert usage.observed_input_tokens == 12
    assert usage.observed_output_tokens == 4
    expected_first = estimate_call_cost(
        "qwen3.7-flash",
        {"input_tokens": 5, "output_tokens": 1, "total_tokens": 6},
    )
    expected_second = estimate_call_cost(
        "qwen3.7-flash",
        {"input_tokens": 7, "output_tokens": 3, "total_tokens": 10},
    )
    assert expected_first is not None and expected_second is not None
    assert usage.cost == pytest.approx(
        expected_first["cny"] + expected_second["cny"]
    )


@pytest.mark.parametrize("over_bound", [False, True])
def test_live_attempt_ledger_must_obey_stage_and_retry_bound(
    tmp_path,
    over_bound,
):
    snapshot = _snapshot(max_requests=2)
    client = InvalidAttemptLedgerTextClient(over_bound=over_bound)
    bridge = _bridge(tmp_path, snapshot, text_client=client)
    materials = _materials(snapshot)
    request = FindingRequest(
        _binding(
            snapshot,
            materials,
            role="AI-1",
            operation="structure-findings",
            issue_id="DISCOVERY-AI-1-attempt-closure",
        ),
        materials,
    )

    with pytest.raises(
        analysis_production.ProductionAnalysisError,
        match="attempt evidence",
    ):
        bridge._text(
            "AI-1",
            "structure-findings",
            request,
            "system",
            {"type": "object"},
        )

    assert bridge.budget.usage.requests == 1
    assert bridge.budget.usage.committed_reservations == 1
    assert len(bridge.transport_evidence) == 1
    assert bridge.transport_evidence[0].attempts == ()
    assert bridge.transport_evidence[0].attempt_evidence_complete is False
    assert bridge.cache_miss_count == 1

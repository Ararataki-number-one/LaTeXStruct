# -*- coding: utf-8 -*-
"""Persistence and fail-closed contracts for the production task ledger."""

from __future__ import annotations

import hashlib
import json

import pytest

from latexstruct.core import analysis_tasks
from latexstruct.core.analysis_tasks import (
    AnalysisTaskStore,
    TaskAttemptsExhaustedError,
    TaskLedgerPersistenceError,
    make_task_identity,
)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _identity(label: str = "base", **changes):
    values = {
        "snapshot_hash": _digest("snapshot"),
        "candidate_hash": _digest("candidate"),
        "operation": "discover-structure",
        "role": "AI-1",
        "source_page_id": "source-page-000001",
        "scope_id": f"scope-{label}",
        "binding_payload": {
            "prompt_hash": _digest("prompt"),
            "schema_hash": _digest("schema"),
            "model": "structure-model",
            "tool_version": "2.0.0",
        },
    }
    values.update(changes)
    return make_task_identity(**values)


def _complete(store: AnalysisTaskStore, identity, response=None):
    store.register(identity)
    store.start(identity.task_id)
    return store.commit_success(
        identity.task_id,
        response if response is not None else {"issues": [], "page": 1},
    )


def test_task_identity_changes_when_any_host_binding_changes():
    baseline = _identity()
    variants = (
        _identity(snapshot_hash=_digest("snapshot-2")),
        _identity(candidate_hash=_digest("candidate-2")),
        _identity(operation="discover-content"),
        _identity(role="AI-2"),
        _identity(source_page_id="source-page-000002"),
        _identity(scope_id="scope-different"),
        _identity(
            binding_payload={
                "prompt_hash": _digest("prompt-2"),
                "schema_hash": _digest("schema"),
                "model": "structure-model",
                "tool_version": "2.0.0",
            }
        ),
    )
    assert all(item.task_id != baseline.task_id for item in variants)
    assert all(item.identity_hash != baseline.identity_hash for item in variants)
    assert len({baseline.task_id, *(item.task_id for item in variants)}) == 8

    reordered_binding = {
        "tool_version": "2.0.0",
        "model": "structure-model",
        "schema_hash": _digest("schema"),
        "prompt_hash": _digest("prompt"),
    }
    assert _identity(binding_payload=reordered_binding) == baseline


def test_response_is_durable_before_completed_ledger_is_saved(tmp_path, monkeypatch):
    store = AnalysisTaskStore(tmp_path / "tasks")
    identity = _identity()
    store.register(identity)
    store.start(identity.task_id)
    original_save = store._save
    completed_save_observations = []

    def inspect_then_save(records=None):
        source = store._records if records is None else records
        record = source[identity.task_id]
        if record.state == "COMPLETED":
            response_path = store.root / record.response_path
            payload = response_path.read_bytes()
            assert response_path.is_file()
            assert hashlib.sha256(payload).hexdigest() == record.response_sha256
            completed_save_observations.append(response_path)
        original_save(records)

    monkeypatch.setattr(store, "_save", inspect_then_save)
    expected = {"issues": [{"type": "FORMAL_BOUNDARY"}], "page": 1}
    record = store.commit_success(identity.task_id, expected)

    assert record.state == "COMPLETED"
    assert completed_save_observations == [store.root / record.response_path]
    assert store.response(identity.task_id) == expected


def test_task_and_response_replaces_fsync_their_parent_directories(
    tmp_path,
    monkeypatch,
):
    fsynced = []
    monkeypatch.setattr(
        analysis_tasks,
        "_fsync_directory",
        lambda path: fsynced.append(path),
    )
    root = tmp_path / "tasks"
    store = AnalysisTaskStore(root)
    _complete(store, _identity())

    assert fsynced == [root, root, store.responses, root]


def test_running_task_recovers_to_pending_without_losing_attempt_count(tmp_path):
    root = tmp_path / "tasks"
    store = AnalysisTaskStore(root)
    identity = _identity()
    store.register(identity)
    running = store.start(identity.task_id)
    assert running.state == "RUNNING"
    assert running.attempts == 1

    recovered_store = AnalysisTaskStore(root)
    recovered = recovered_store.get(identity.task_id)
    assert recovered.state == "PENDING"
    assert recovered.attempts == 1
    assert recovered.error == "process interrupted before task commit"

    reopened = AnalysisTaskStore(root).get(identity.task_id)
    assert reopened.state == "PENDING"
    assert reopened.attempts == 1


def test_recovered_task_at_retry_limit_is_durably_blocked_before_restart(tmp_path):
    root = tmp_path / "tasks"
    store = AnalysisTaskStore(root)
    identity = _identity()
    store.register(identity)
    store.start(identity.task_id)
    recovered = AnalysisTaskStore(root)

    with pytest.raises(TaskAttemptsExhaustedError, match="allowance exhausted"):
        recovered.start(identity.task_id, max_attempts=1)

    blocked = recovered.get(identity.task_id)
    assert blocked.state == "BLOCKED"
    assert blocked.attempts == 1
    reopened = AnalysisTaskStore(root).get(identity.task_id)
    assert reopened.state == "BLOCKED"
    assert reopened.attempts == 1


def test_start_save_failure_keeps_prior_state_and_permanently_poisons_store(
    tmp_path,
    monkeypatch,
):
    root = tmp_path / "tasks"
    store = AnalysisTaskStore(root)
    identity = _identity()
    store.register(identity)

    def fail_save(_records=None):
        raise OSError("injected task-ledger save failure")

    monkeypatch.setattr(store, "_save", fail_save)
    with pytest.raises(TaskLedgerPersistenceError, match="cannot persist"):
        store.start(identity.task_id)

    assert store.get(identity.task_id).state == "PENDING"
    assert store.get(identity.task_id).attempts == 0
    with pytest.raises(TaskLedgerPersistenceError, match="poisoned"):
        store.start(identity.task_id)

    durable = AnalysisTaskStore(root).get(identity.task_id)
    assert durable.state == "PENDING"
    assert durable.attempts == 0


def test_completed_index_save_failure_never_publishes_completed_in_memory(
    tmp_path,
    monkeypatch,
):
    root = tmp_path / "tasks"
    store = AnalysisTaskStore(root)
    identity = _identity()
    store.register(identity)
    store.start(identity.task_id)

    def fail_save(_records=None):
        raise OSError("injected completed-ledger save failure")

    monkeypatch.setattr(store, "_save", fail_save)
    with pytest.raises(TaskLedgerPersistenceError, match="cannot persist"):
        store.commit_success(identity.task_id, {"issues": [], "page": 1})

    assert store.get(identity.task_id).state == "RUNNING"
    assert len(tuple(store.responses.glob(f"{identity.task_id}-*.json"))) == 1
    recovered = AnalysisTaskStore(root).get(identity.task_id)
    assert recovered.state == "PENDING"
    assert recovered.attempts == 1


@pytest.mark.parametrize(
    "mutate",
    (
        lambda record: record.update(attempts=True),
        lambda record: record.update(attempts="0"),
        lambda record: record.update(extra_field="not allowed"),
        lambda record: record["identity"].update(operation=7),
        lambda record: record.update(state="COMPLETED", attempts=0),
    ),
)
def test_task_ledger_load_rejects_noncanonical_types_keys_and_states(
    tmp_path,
    mutate,
):
    root = tmp_path / "tasks"
    store = AnalysisTaskStore(root)
    identity = _identity()
    store.register(identity)
    ledger = json.loads(store.index_path.read_text(encoding="utf-8"))
    mutate(ledger["records"][identity.task_id])
    store.index_path.write_text(
        json.dumps(ledger, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        AnalysisTaskStore(root)


def test_task_ledger_load_rejects_duplicate_json_members(tmp_path):
    root = tmp_path / "tasks"
    store = AnalysisTaskStore(root)
    store.register(_identity())
    payload = store.index_path.read_text(encoding="utf-8")
    duplicate = payload.replace(
        '"records": {',
        '"records": {},\n  "records": {',
        1,
    )
    store.index_path.write_text(duplicate, encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate JSON object member"):
        AnalysisTaskStore(root)


@pytest.mark.parametrize(
    ("field", "tampered", "message"),
    (
        ("response_sha256", "f" * 64, "response hash mismatch"),
        ("response_path", "../escaped-response.json", "escapes its run root"),
    ),
)
def test_completed_response_hash_or_path_tampering_fails_closed(
    tmp_path,
    field,
    tampered,
    message,
):
    root = tmp_path / field
    store = AnalysisTaskStore(root)
    identity = _identity(field)
    _complete(store, identity)

    ledger = json.loads(store.index_path.read_text(encoding="utf-8"))
    ledger["records"][identity.task_id][field] = tampered
    store.index_path.write_text(
        json.dumps(ledger, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match=message):
        AnalysisTaskStore(root)


def test_completed_response_byte_tampering_is_rejected_by_live_and_reloaded_store(tmp_path):
    root = tmp_path / "tasks"
    store = AnalysisTaskStore(root)
    identity = _identity()
    record = _complete(store, identity)
    response_path = store.root / record.response_path
    response_path.write_text('{"tampered":true}\n', encoding="utf-8")

    with pytest.raises(ValueError, match="response hash mismatch"):
        store.response(identity.task_id)
    with pytest.raises(ValueError, match="response hash mismatch"):
        AnalysisTaskStore(root)


def test_retryable_failure_returns_to_pending_then_final_attempt_blocks(tmp_path):
    store = AnalysisTaskStore(tmp_path / "tasks")
    identity = _identity()
    store.register(identity)

    store.start(identity.task_id)
    retry = store.fail(
        identity.task_id,
        "temporary provider failure",
        retryable=True,
        max_attempts=2,
    )
    assert retry.state == "PENDING"
    assert retry.attempts == 1
    assert retry.error == "temporary provider failure"

    second_attempt = store.start(identity.task_id)
    assert second_attempt.attempts == 2
    blocked = store.fail(
        identity.task_id,
        "provider still unavailable",
        retryable=True,
        max_attempts=2,
    )
    assert blocked.state == "BLOCKED"
    assert blocked.attempts == 2
    with pytest.raises(ValueError, match="only a pending task"):
        store.start(identity.task_id)


def test_non_retryable_failure_blocks_on_first_attempt_and_truncates_error(tmp_path):
    store = AnalysisTaskStore(tmp_path / "tasks")
    identity = _identity()
    store.register(identity)
    store.start(identity.task_id)
    blocked = store.fail(
        identity.task_id,
        "x" * 2_100,
        retryable=False,
        max_attempts=5,
    )
    assert blocked.state == "BLOCKED"
    assert blocked.attempts == 1
    assert len(blocked.error) == 2_000


def test_summary_reports_every_state_and_records_are_stably_sorted(tmp_path):
    store = AnalysisTaskStore(tmp_path / "tasks")

    pending = _identity("pending")
    store.register(pending)

    running = _identity("running")
    store.register(running)
    store.start(running.task_id)

    completed = _identity("completed")
    _complete(store, completed)

    blocked = _identity("blocked")
    store.register(blocked)
    store.start(blocked.task_id)
    store.fail(blocked.task_id, "invalid response", retryable=False, max_attempts=3)

    assert store.summary() == {
        "BLOCKED": 1,
        "COMPLETED": 1,
        "PENDING": 1,
        "RUNNING": 1,
    }
    task_ids = [record.identity.task_id for record in store.records]
    assert task_ids == sorted(task_ids)

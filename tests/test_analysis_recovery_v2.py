# -*- coding: utf-8 -*-
from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from latexstruct.core import analysis_recovery
from latexstruct.core.analysis_recovery import (
    ActiveRunLockError,
    AnalysisRunStore,
    ImmutableEvidenceError,
    RecoveryValidationError,
)
from latexstruct.core.analysis_runtime import (
    CandidateRepository,
    CandidateStoreError,
    make_candidate_id,
)
from latexstruct.core.analysis_schema import CandidateDisposition, QualityVector
from latexstruct.core.compilecheck import build_compile_input_manifest


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _symlink_or_skip(
    link: Path,
    target: Path,
    *,
    target_is_directory: bool = False,
) -> None:
    try:
        link.symlink_to(target, target_is_directory=target_is_directory)
    except OSError as exc:
        if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
            pytest.skip("Windows symlink privilege is unavailable")
        raise


def _junction_or_skip(link: Path, target: Path) -> None:
    if os.name != "nt":
        pytest.skip("Windows junction test")
    completed = subprocess.run(
        ["cmd.exe", "/d", "/c", "mklink", "/J", os.fspath(link), os.fspath(target)],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        pytest.skip("Windows junction creation is unavailable")


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _pretty_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def _compile_manifest(tex: bytes, extras: dict[str, bytes]) -> dict[str, object]:
    payloads = {"main.tex": tex, **extras}
    body: dict[str, object] = {
        "schema": "latexstruct-compile-input-set-v1",
        "file_count": len(payloads),
        "files": [
            {
                "path": name,
                "bytes": len(payloads[name]),
                "sha256": _sha(payloads[name]),
            }
            for name in sorted(payloads)
        ],
    }
    compact = json.dumps(
        body, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return {**body, "manifest_sha256": _sha(compact)}


def _snapshot(
    *,
    source_pdf: bytes,
    raw_ocr_tex: bytes,
    baseline_tex: bytes,
    baseline_pdf: bytes,
    compile_input_hash: str,
) -> dict[str, object]:
    body: dict[str, object] = {
        "run_id": "run-recovery-01",
        "project_id": "project-recovery-01",
        "workflow_version": "analysis-v2",
        "source_pdf_hash": _sha(source_pdf),
        "raw_ocr_tex_hash": _sha(raw_ocr_tex),
        "baseline_tex_hash": _sha(baseline_tex),
        "baseline_pdf_hash": _sha(baseline_pdf),
        "evidence_hashes": {
            "baseline_compile_inputs_hash": compile_input_hash,
        },
    }
    return {**body, "snapshot_hash": _sha(_canonical_json(body))}


def _frozen_values() -> dict[str, object]:
    baseline = b"\\documentclass{article}\n\\begin{document}x\\end{document}\n"
    extras = {"figures/plot.png": b"PNG\x00frozen"}
    manifest = _compile_manifest(baseline, extras)
    source_pdf = b"%PDF-1.7\nsource"
    raw_ocr = b"raw OCR source\n"
    baseline_pdf = b"%PDF-1.7\nbaseline"
    return {
        "source_pdf": source_pdf,
        "raw_ocr_tex": raw_ocr,
        "baseline_tex": baseline,
        "baseline_pdf": baseline_pdf,
        "baseline_compile_log": b"two passes; ok\n",
        "compile_extras": extras,
        "compile_input_manifest": manifest,
        "page_map": [{"source_page_id": "page-0001", "candidate_page_id": "page-0001"}],
        "snapshot": _snapshot(
            source_pdf=source_pdf,
            raw_ocr_tex=raw_ocr,
            baseline_tex=baseline,
            baseline_pdf=baseline_pdf,
            compile_input_hash=str(manifest["manifest_sha256"]),
        ),
    }


def _freeze(
    store: AnalysisRunStore,
    *,
    acquire_lock: bool = True,
) -> tuple[dict[str, object], object]:
    values = _frozen_values()
    if acquire_lock:
        with store.exclusive_lock():
            frozen = store.freeze_inputs(**values)
    else:
        frozen = store.freeze_inputs(**values)
    return values, frozen


def _candidate(
    store: AnalysisRunStore,
    *,
    tex: bytes,
    round_index: int,
    disposition: CandidateDisposition,
    parent_candidate_id: str = "",
):
    repository = CandidateRepository(store.candidates_directory)
    tex_hash = _sha(tex)
    return repository.persist(
        candidate_id=make_candidate_id(round_index, tex_hash),
        parent_candidate_id=parent_candidate_id,
        round_index=round_index,
        tex=tex.decode("utf-8"),
        pdf=b"%PDF-1.7\ncandidate",
        compile_log="two passes; ok\n",
        patch={},
        diff="",
        issue_ledger={"issues": []},
        quality=QualityVector(fully_compiled=True),
        review={},
        disposition=disposition,
        reason="test candidate",
    )


def _commit(
    store: AnalysisRunStore,
    candidate,
    *,
    sequence: int,
    round_index: int,
    run_state: object | None = None,
    issue_ledger: object | None = None,
    acquire_lock: bool = True,
):
    def commit():
        frozen = store.verify_frozen_inputs()
        return store.commit_checkpoint(
            sequence=sequence,
            run_id=frozen.run_id,
            project_id=frozen.project_id,
            snapshot_hash=frozen.snapshot_hash,
            compile_input_hash=store.candidate_compile_input_hash(candidate.candidate_id),
            round_index=round_index,
            current_candidate_id=candidate.candidate_id,
            current_candidate_hash=candidate.tex_sha256,
            best_candidate_id=candidate.candidate_id,
            best_candidate_hash=candidate.tex_sha256,
            run_state={"phase": "macro-round"} if run_state is None else run_state,
            issue_ledger={"issues": []} if issue_ledger is None else issue_ledger,
            task_ledger={"tasks": []},
            budget_ledger={"used_requests": sequence},
            invocation_ledger={"invocations": []},
            compile_history=[{"round": round_index}],
            candidate_page_map={"pages": []},
            rollback_history=[],
        )

    if acquire_lock:
        with store.exclusive_lock():
            return commit()
    return commit()


def _rewrite_checkpoint_metadata(
    checkpoint: Path,
    *,
    updates: dict[str, object],
) -> Path:
    metadata_path = checkpoint / "checkpoint.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata.update(updates)
    identity = dict(metadata)
    identity.pop("checkpoint_id")
    new_id = AnalysisRunStore._checkpoint_id(identity)
    metadata["checkpoint_id"] = new_id
    metadata_path.write_bytes(_pretty_json(metadata))

    payloads = {
        path.name: path.read_bytes()
        for path in checkpoint.iterdir()
        if path.name != "SHA256SUMS"
    }
    sums = "".join(
        f"{_sha(payloads[name])}  {name}\n" for name in sorted(payloads)
    ).encode("utf-8")
    (checkpoint / "SHA256SUMS").write_bytes(sums)
    destination = checkpoint.with_name(new_id)
    checkpoint.rename(destination)
    (destination.parent / "LATEST").write_text(f"{new_id}\n", encoding="ascii")
    return destination


def _rewrite_candidate_disposition(candidate_directory: Path, disposition: str) -> None:
    metadata_path = candidate_directory / "candidate.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["disposition"] = disposition
    metadata_path.write_bytes(_pretty_json(metadata))
    payloads = {
        path.name: path.read_bytes()
        for path in candidate_directory.iterdir()
        if path.name != "SHA256SUMS"
    }
    (candidate_directory / "SHA256SUMS").write_bytes(
        "".join(
            f"{_sha(payloads[name])}  {name}\n" for name in sorted(payloads)
        ).encode("utf-8")
    )


def _rehash_directory(directory: Path) -> None:
    payloads = {
        path.name: path.read_bytes()
        for path in directory.iterdir()
        if path.name != "SHA256SUMS"
    }
    (directory / "SHA256SUMS").write_bytes(
        "".join(
            f"{_sha(payloads[name])}  {name}\n" for name in sorted(payloads)
        ).encode("utf-8")
    )


def test_freeze_inputs_is_atomic_write_once_and_path_safe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = AnalysisRunStore(tmp_path / "active")
    values, first = _freeze(store)
    with store.exclusive_lock():
        second = store.freeze_inputs(**values)
    assert second == first
    assert (store.inputs_directory / "compile-inputs/figures/plot.png").read_bytes() == (
        b"PNG\x00frozen"
    )

    changed = dict(values)
    changed["baseline_compile_log"] = b"different log\n"
    with store.exclusive_lock():
        with pytest.raises(ImmutableEvidenceError, match="immutable bytes differ"):
            store.freeze_inputs(**changed)

    unsafe = _frozen_values()
    unsafe["compile_extras"] = {"../escape.sty": b"bad"}
    unsafe_store = AnalysisRunStore(tmp_path / "unsafe")
    with unsafe_store.exclusive_lock():
        with pytest.raises(RecoveryValidationError, match="canonical relative path"):
            unsafe_store.freeze_inputs(**unsafe)

    actual_root = tmp_path / "actual-root"
    actual_root.mkdir()
    linked_root = tmp_path / "linked-root"
    _symlink_or_skip(linked_root, actual_root, target_is_directory=True)
    with pytest.raises(
        RecoveryValidationError,
        match=r"(?:symlink|link or reparse point)",
    ):
        AnalysisRunStore(linked_root)

    crash_store = AnalysisRunStore(tmp_path / "crash")
    real_replace = analysis_recovery.os.replace

    def fail_input_commit(source: object, destination: object) -> None:
        if Path(destination).name == "inputs":
            raise OSError("simulated power loss before input rename")
        real_replace(source, destination)

    monkeypatch.setattr(analysis_recovery.os, "replace", fail_input_commit)
    with crash_store.exclusive_lock():
        with pytest.raises(OSError, match="simulated power loss"):
            crash_store.freeze_inputs(**_frozen_values())
    assert not crash_store.inputs_directory.exists()
    assert not list(crash_store.root.glob(".inputs-*"))


def test_checkpoint_copies_every_ledger_and_is_idempotently_immutable(tmp_path: Path) -> None:
    store = AnalysisRunStore(tmp_path / "active")
    values, frozen = _freeze(store)
    candidate = _candidate(
        store,
        tex=values["baseline_tex"],
        round_index=0,
        disposition=CandidateDisposition.BASELINE,
    )
    run_state = {"phase": "discovery", "nested": {"attempt": 1}}
    issue_ledger = {"issues": [{"issue_id": "ISS-000000000001"}]}
    committed = _commit(
        store,
        candidate,
        sequence=1,
        round_index=0,
        run_state=run_state,
        issue_ledger=issue_ledger,
    )
    run_state["nested"]["attempt"] = 99
    issue_ledger["issues"].append({"issue_id": "ISS-mutated"})

    expected_files = {
        "checkpoint.json",
        "run_state.json",
        "issue_ledger.json",
        "task_ledger.json",
        "budget_ledger.json",
        "invocation_ledger.json",
        "compile_history.json",
        "candidate_page_map.json",
        "rollback_history.json",
        "SHA256SUMS",
    }
    assert {path.name for path in committed.directory.iterdir()} == expected_files
    manifest_names = {
        line.partition("  ")[2]
        for line in (committed.directory / "SHA256SUMS").read_text().splitlines()
    }
    assert manifest_names == expected_files - {"SHA256SUMS"}

    recovered = AnalysisRunStore(store.root).recover_latest(
        expected_run_id=frozen.run_id,
        expected_project_id=frozen.project_id,
        expected_snapshot_hash=frozen.snapshot_hash,
        expected_frozen_compile_input_manifest_hash=frozen.compile_input_manifest_hash,
    )
    assert recovered.latest_pointer_valid is True
    assert recovered.checkpoint is not None
    assert recovered.checkpoint.checkpoint_id == committed.checkpoint_id
    assert recovered.checkpoint.run_state["nested"]["attempt"] == 1
    assert len(recovered.checkpoint.issue_ledger["issues"]) == 1
    assert recovered.checkpoint.current_candidate.candidate_hash == candidate.tex_sha256

    same = _commit(
        store,
        candidate,
        sequence=1,
        round_index=0,
        run_state={"phase": "discovery", "nested": {"attempt": 1}},
        issue_ledger={"issues": [{"issue_id": "ISS-000000000001"}]},
    )
    assert same.checkpoint_id == committed.checkpoint_id
    with pytest.raises(ImmutableEvidenceError, match="sequence already"):
        _commit(
            store,
            candidate,
            sequence=1,
            round_index=0,
            run_state={"phase": "different"},
        )


def test_candidate_orphan_before_checkpoint_is_idempotently_adopted(
    tmp_path: Path,
) -> None:
    store = AnalysisRunStore(tmp_path / "active")
    values, frozen = _freeze(store)

    # The first process durably publishes the complete candidate, then dies
    # before it can create checkpoint 1.
    first = _candidate(
        store,
        tex=values["baseline_tex"],
        round_index=0,
        disposition=CandidateDisposition.BASELINE,
    )
    assert not store.checkpoints_directory.exists()

    # A resumed process replays the same deterministic candidate.  The
    # write-once repository adopts the byte-identical orphan without rewriting
    # it, allowing the previously missing checkpoint to be committed normally.
    replayed = _candidate(
        AnalysisRunStore(store.root),
        tex=values["baseline_tex"],
        round_index=0,
        disposition=CandidateDisposition.BASELINE,
    )
    assert replayed == first
    committed = _commit(store, replayed, sequence=1, round_index=0)

    recovered = AnalysisRunStore(store.root).recover_latest(
        expected_run_id=frozen.run_id,
        expected_project_id=frozen.project_id,
        expected_snapshot_hash=frozen.snapshot_hash,
        expected_frozen_compile_input_manifest_hash=frozen.compile_input_manifest_hash,
    )
    assert recovered.latest_pointer_valid is True
    assert recovered.checkpoint is not None
    assert recovered.checkpoint.checkpoint_id == committed.checkpoint_id
    assert recovered.checkpoint.current_candidate.candidate_id == first.candidate_id


def test_analysis_run_mutations_require_the_exclusive_lock(tmp_path: Path) -> None:
    store = AnalysisRunStore(tmp_path / "active")
    with pytest.raises(ActiveRunLockError, match="exclusive lock"):
        store.freeze_inputs(**_frozen_values())

    values, _ = _freeze(store)
    candidate = _candidate(
        store,
        tex=values["baseline_tex"],
        round_index=0,
        disposition=CandidateDisposition.BASELINE,
    )
    with pytest.raises(ActiveRunLockError, match="exclusive lock"):
        _commit(
            store,
            candidate,
            sequence=1,
            round_index=0,
            acquire_lock=False,
        )
    assert not store.checkpoints_directory.exists()


def test_idempotent_historical_checkpoint_replay_never_rewinds_latest(
    tmp_path: Path,
) -> None:
    store = AnalysisRunStore(tmp_path / "active")
    values, _ = _freeze(store)
    candidate = _candidate(
        store,
        tex=values["baseline_tex"],
        round_index=0,
        disposition=CandidateDisposition.BASELINE,
    )
    older = _commit(store, candidate, sequence=1, round_index=0)
    newest = _commit(store, candidate, sequence=2, round_index=0)
    assert (store.checkpoints_directory / "LATEST").read_text(encoding="ascii") == (
        f"{newest.checkpoint_id}\n"
    )

    replay = _commit(store, candidate, sequence=1, round_index=0)
    assert replay.checkpoint_id == older.checkpoint_id
    assert (store.checkpoints_directory / "LATEST").read_text(encoding="ascii") == (
        f"{newest.checkpoint_id}\n"
    )
    recovered = store.recover_latest()
    assert recovered.checkpoint is not None
    assert recovered.checkpoint.checkpoint_id == newest.checkpoint_id
    assert recovered.latest_pointer_valid is True


def test_freeze_captures_implicit_production_compile_inputs(tmp_path: Path) -> None:
    baseline = b"\\documentclass{elegantbook}\n\\begin{document}x\\end{document}\n"
    compile_manifest = build_compile_input_manifest(baseline.decode("utf-8"), {})
    source_pdf = b"%PDF-1.7\nsource"
    raw_ocr = b"raw OCR source\n"
    baseline_pdf = b"%PDF-1.7\nbaseline"
    snapshot = _snapshot(
        source_pdf=source_pdf,
        raw_ocr_tex=raw_ocr,
        baseline_tex=baseline,
        baseline_pdf=baseline_pdf,
        compile_input_hash=str(compile_manifest["manifest_sha256"]),
    )
    store = AnalysisRunStore(tmp_path / "implicit-input")
    with store.exclusive_lock():
        frozen = store.freeze_inputs(
            snapshot=snapshot,
            source_pdf=source_pdf,
            raw_ocr_tex=raw_ocr,
            baseline_tex=baseline,
            baseline_pdf=baseline_pdf,
            baseline_compile_log="two passes; ok\n",
            compile_extras={},
            compile_input_manifest=compile_manifest,
            page_map=[],
        )
    assert [item.logical_path for item in frozen.compile_extras] == ["elegantbook.cls"]
    assert (store.inputs_directory / "compile-inputs/elegantbook.cls").is_file()


def test_recovery_falls_back_from_half_written_newest_and_broken_latest(
    tmp_path: Path,
) -> None:
    store = AnalysisRunStore(tmp_path / "active")
    values, _ = _freeze(store)
    baseline = _candidate(
        store,
        tex=values["baseline_tex"],
        round_index=0,
        disposition=CandidateDisposition.BASELINE,
    )
    older = _commit(store, baseline, sequence=1, round_index=0)
    accepted_tex = values["baseline_tex"] + b"% accepted round\n"
    accepted = _candidate(
        store,
        tex=accepted_tex,
        round_index=1,
        disposition=CandidateDisposition.ACCEPTED,
        parent_candidate_id=baseline.candidate_id,
    )
    newest = _commit(store, accepted, sequence=2, round_index=1)
    (newest.directory / "run_state.json").write_text("{\"torn\":true}\n", encoding="utf-8")
    half_written = store.checkpoints_directory / "checkpoint-00000003-0000000000000000"
    half_written.mkdir()
    (half_written / "run_state.json").write_text("{}\n", encoding="utf-8")
    (store.checkpoints_directory / "LATEST").write_text("torn", encoding="ascii")

    result = store.recover_latest()
    assert result.checkpoint is not None
    assert result.checkpoint.checkpoint_id == older.checkpoint_id
    assert result.latest_pointer_valid is False
    codes = {rejection.code for rejection in result.rejected}
    assert "latest_pointer" in codes
    assert "missing_manifest" in codes
    assert "hash_mismatch" in codes


def test_store_rejects_orphan_rejected_and_explicit_binding_mismatches(
    tmp_path: Path,
) -> None:
    store = AnalysisRunStore(tmp_path / "active")
    values, frozen = _freeze(store)
    baseline = _candidate(
        store,
        tex=values["baseline_tex"],
        round_index=0,
        disposition=CandidateDisposition.BASELINE,
    )
    orphan_scan = store.recover_latest()
    assert orphan_scan.checkpoint is None

    with store.exclusive_lock():
        with pytest.raises(RecoveryValidationError, match="identity differs"):
            store.commit_checkpoint(
                sequence=1,
                run_id=frozen.run_id,
                project_id=frozen.project_id,
                snapshot_hash="f" * 64,
                compile_input_hash=store.candidate_compile_input_hash(baseline.candidate_id),
                round_index=0,
                current_candidate_id=baseline.candidate_id,
                current_candidate_hash=baseline.tex_sha256,
                best_candidate_id=baseline.candidate_id,
                best_candidate_hash=baseline.tex_sha256,
                run_state={},
                issue_ledger={},
                task_ledger={},
                budget_ledger={},
                invocation_ledger={},
                compile_history=[],
                candidate_page_map={},
                rollback_history=[],
            )
        with pytest.raises(RecoveryValidationError, match="compile input hash differs"):
            store.commit_checkpoint(
                sequence=1,
                run_id=frozen.run_id,
                project_id=frozen.project_id,
                snapshot_hash=frozen.snapshot_hash,
                compile_input_hash="e" * 64,
                round_index=0,
                current_candidate_id=baseline.candidate_id,
                current_candidate_hash=baseline.tex_sha256,
                best_candidate_id=baseline.candidate_id,
                best_candidate_hash=baseline.tex_sha256,
                run_state={},
                issue_ledger={},
                task_ledger={},
                budget_ledger={},
                invocation_ledger={},
                compile_history=[],
                candidate_page_map={},
                rollback_history=[],
            )

    rejected = _candidate(
        store,
        tex=values["baseline_tex"] + b"% rejected\n",
        round_index=1,
        disposition=CandidateDisposition.REJECTED_ROLLED_BACK,
        parent_candidate_id=baseline.candidate_id,
    )
    with pytest.raises(RecoveryValidationError, match="rejected candidate"):
        _commit(store, rejected, sequence=1, round_index=1)


@pytest.mark.parametrize(
    ("update_name", "update_value", "expected_code"),
    [
        ("snapshot_hash", "a" * 64, "snapshot_mismatch"),
        ("compile_input_hash", "b" * 64, "compile_mismatch"),
    ],
)
def test_recovery_rejects_self_hashed_snapshot_and_compile_mismatch(
    tmp_path: Path,
    update_name: str,
    update_value: str,
    expected_code: str,
) -> None:
    store = AnalysisRunStore(tmp_path / update_name)
    values, _ = _freeze(store)
    baseline = _candidate(
        store,
        tex=values["baseline_tex"],
        round_index=0,
        disposition=CandidateDisposition.BASELINE,
    )
    committed = _commit(store, baseline, sequence=1, round_index=0)
    _rewrite_checkpoint_metadata(
        committed.directory,
        updates={update_name: update_value},
    )

    result = store.recover_latest()
    assert result.checkpoint is None
    assert expected_code in {rejection.code for rejection in result.rejected}


def test_recovery_rejects_rejected_or_orphaned_candidate_and_symlink(
    tmp_path: Path,
) -> None:
    rejected_store = AnalysisRunStore(tmp_path / "rejected")
    values, _ = _freeze(rejected_store)
    candidate = _candidate(
        rejected_store,
        tex=values["baseline_tex"],
        round_index=0,
        disposition=CandidateDisposition.BASELINE,
    )
    _commit(rejected_store, candidate, sequence=1, round_index=0)
    _rewrite_candidate_disposition(
        rejected_store.candidates_directory / candidate.candidate_id,
        "REJECTED_ROLLED_BACK",
    )
    rejected_result = rejected_store.recover_latest()
    assert rejected_result.checkpoint is None
    assert "candidate_rejected" in {
        rejection.code for rejection in rejected_result.rejected
    }

    orphan_store = AnalysisRunStore(tmp_path / "orphan")
    orphan_values, _ = _freeze(orphan_store)
    orphan_candidate = _candidate(
        orphan_store,
        tex=orphan_values["baseline_tex"],
        round_index=0,
        disposition=CandidateDisposition.BASELINE,
    )
    _commit(orphan_store, orphan_candidate, sequence=1, round_index=0)
    candidate_directory = orphan_store.candidates_directory / orphan_candidate.candidate_id
    moved_directory = orphan_store.root / "detached-candidate"
    candidate_directory.rename(moved_directory)
    orphan_result = orphan_store.recover_latest()
    assert orphan_result.checkpoint is None
    assert "missing_directory" in {rejection.code for rejection in orphan_result.rejected}

    _symlink_or_skip(candidate_directory, moved_directory, target_is_directory=True)
    symlink_result = orphan_store.recover_latest()
    assert symlink_result.checkpoint is None
    assert "symlink" in {rejection.code for rejection in symlink_result.rejected}


def test_candidate_quality_vector_must_match_candidate_metadata(tmp_path: Path) -> None:
    store = AnalysisRunStore(tmp_path / "active")
    values, _ = _freeze(store)
    candidate = _candidate(
        store,
        tex=values["baseline_tex"],
        round_index=0,
        disposition=CandidateDisposition.BASELINE,
    )
    _commit(store, candidate, sequence=1, round_index=0)
    directory = store.candidates_directory / candidate.candidate_id
    quality_path = directory / "quality_vector.json"
    quality = json.loads(quality_path.read_text(encoding="utf-8"))
    quality["open_high"] = 1
    quality_path.write_bytes(_pretty_json(quality))
    _rehash_directory(directory)

    with pytest.raises(RecoveryValidationError, match="quality metadata differs"):
        store.verify_candidate(candidate.candidate_id)
    recovered = store.recover_latest()
    assert recovered.checkpoint is None
    assert "candidate_quality" in {
        rejection.code for rejection in recovered.rejected
    }


@pytest.mark.parametrize(
    "payload",
    [
        b'{"nested":{"value":1,"value":2}}\n',
        b'{"value":NaN}\n',
        b'{"value":1e999}\n',
    ],
    ids=["duplicate-key", "nan", "overflowing-number"],
)
def test_candidate_recovery_json_rejects_duplicates_and_non_finite_numbers(
    tmp_path: Path,
    payload: bytes,
) -> None:
    store = AnalysisRunStore(tmp_path / "active")
    values, _ = _freeze(store)
    candidate = _candidate(
        store,
        tex=values["baseline_tex"],
        round_index=0,
        disposition=CandidateDisposition.BASELINE,
    )
    directory = store.candidates_directory / candidate.candidate_id
    (directory / "review.json").write_bytes(payload)
    _rehash_directory(directory)

    with pytest.raises(RecoveryValidationError, match="not valid JSON"):
        store.verify_candidate(candidate.candidate_id)


def test_frozen_inputs_reject_any_symlink_or_extra_file(tmp_path: Path) -> None:
    store = AnalysisRunStore(tmp_path / "active")
    _freeze(store)
    extra = store.inputs_directory / "extra.json"
    extra.write_text("{}\n", encoding="utf-8")
    with pytest.raises(RecoveryValidationError, match="exact file set"):
        store.verify_frozen_inputs()
    extra.unlink()

    source = store.inputs_directory / "source.pdf"
    saved = store.root / "saved-source.pdf"
    source.rename(saved)
    _symlink_or_skip(source, saved)
    with pytest.raises(
        RecoveryValidationError,
        match=r"(?:symlink|link or reparse point)",
    ):
        store.verify_frozen_inputs()


def test_active_run_lock_is_cross_process_nonblocking_and_reusable(
    tmp_path: Path,
) -> None:
    active_root = tmp_path / "active"
    child_script = "\n".join(
        (
            "import sys",
            "from latexstruct.core.analysis_recovery import AnalysisRunStore",
            "store = AnalysisRunStore(sys.argv[1])",
            "with store.exclusive_lock():",
            "    print('LOCKED', flush=True)",
            "    sys.stdin.readline()",
        )
    )
    process = subprocess.Popen(
        [sys.executable, "-c", child_script, os.fspath(active_root)],
        cwd=Path(__file__).resolve().parents[1],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert process.stdout is not None
        assert process.stdout.readline() == "LOCKED\n"
        contender = AnalysisRunStore(active_root)
        with pytest.raises(ActiveRunLockError, match="already locked"):
            with contender.exclusive_lock():
                pytest.fail("a second holder entered the active run")
    finally:
        if process.stdin is not None:
            process.stdin.write("\n")
            process.stdin.flush()
        process.wait(timeout=5)
    assert process.returncode == 0
    with AnalysisRunStore(active_root).exclusive_lock():
        pass


def test_provisional_identity_reuses_host_time_and_binds_one_snapshot(
    tmp_path: Path,
) -> None:
    store = AnalysisRunStore(tmp_path / "active")
    started_at = "2026-08-24T12:34:56+00:00"
    with pytest.raises(ActiveRunLockError, match="exclusive lock"):
        store.stage_provisional_identity(
            run_id="run-recovery-01",
            project_id="project-recovery-01",
            started_at=started_at,
        )

    with store.exclusive_lock():
        staged = store.stage_provisional_identity(
            run_id="run-recovery-01",
            project_id="project-recovery-01",
            started_at=started_at,
        )
        assert staged.started_at == started_at
        assert staged.snapshot_hash is None
        assert store.provisional_identity_path.parent == store.root
        assert store.provisional_identity_path.parent != store.inputs_directory
        assert store.stage_provisional_identity(
            run_id="run-recovery-01",
            project_id="project-recovery-01",
            started_at=None,
        ) == staged

        with pytest.raises(RecoveryValidationError, match="run/project"):
            store.stage_provisional_identity(
                run_id="different-run",
                project_id="project-recovery-01",
                started_at=None,
            )
        with pytest.raises(RecoveryValidationError, match="started_at differs"):
            store.stage_provisional_identity(
                run_id="run-recovery-01",
                project_id="project-recovery-01",
                started_at="2026-08-24T12:34:57+00:00",
            )

        values = _frozen_values()
        snapshot = dict(values["snapshot"])
        snapshot.pop("snapshot_hash")
        snapshot["started_at"] = staged.started_at
        snapshot_hash = _sha(_canonical_json(snapshot))
        snapshot["snapshot_hash"] = snapshot_hash
        values["snapshot"] = snapshot
        with pytest.raises(RecoveryValidationError, match="not bound"):
            store.freeze_inputs(**values)
        assert not store.inputs_directory.exists()
        bound = store.bind_provisional_snapshot(
            staged,
            snapshot_hash=snapshot_hash,
        )
        assert bound.snapshot_hash == snapshot_hash
        assert store.bind_provisional_snapshot(
            bound,
            snapshot_hash=snapshot_hash,
        ) == bound
        with pytest.raises(RecoveryValidationError, match="configuration"):
            store.bind_provisional_snapshot(
                bound,
                snapshot_hash="f" * 64,
            )

        frozen = store.freeze_inputs(**values)
        assert frozen.snapshot_hash == snapshot_hash
        assert store.provisional_identity_path.is_file()


def test_provisional_identity_requires_creation_time_and_durable_replace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = AnalysisRunStore(tmp_path / "active")
    fsync_modes: list[int] = []
    replace_destinations: list[Path] = []
    real_fsync = analysis_recovery.os.fsync
    real_replace = analysis_recovery.os.replace

    def record_fsync(descriptor: int) -> None:
        fsync_modes.append(stat.S_IFMT(os.fstat(descriptor).st_mode))
        real_fsync(descriptor)

    def record_replace(source: object, destination: object) -> None:
        replace_destinations.append(Path(destination))
        real_replace(source, destination)

    monkeypatch.setattr(analysis_recovery.os, "fsync", record_fsync)
    monkeypatch.setattr(analysis_recovery.os, "replace", record_replace)
    with store.exclusive_lock():
        with pytest.raises(RecoveryValidationError, match="started_at is required"):
            store.stage_provisional_identity(
                run_id="run-recovery-01",
                project_id="project-recovery-01",
                started_at=None,
            )
        store.stage_provisional_identity(
            run_id="run-recovery-01",
            project_id="project-recovery-01",
            started_at="2026-08-24T12:34:56Z",
        )

    assert replace_destinations == [store.provisional_identity_path]
    assert stat.S_IFREG in fsync_modes
    if os.name != "nt":
        assert stat.S_IFDIR in fsync_modes


@pytest.mark.skipif(os.name != "nt", reason="Windows binary-mode regression")
def test_low_level_artifact_io_preserves_binary_bytes_on_windows(tmp_path: Path) -> None:
    target = tmp_path / "binary-artifact.bin"
    payload = b"prefix\nembedded\x1a\ntrailer\r\n"
    analysis_recovery._write_new_file(target, payload)
    assert target.read_bytes() == payload
    assert analysis_recovery._read_regular_file(target) == payload


def test_provisional_snapshot_replace_failure_preserves_staged_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = AnalysisRunStore(tmp_path / "active")
    real_replace = analysis_recovery.os.replace

    def fail_binding(source: object, destination: object) -> None:
        if Path(destination) == store.provisional_identity_path:
            raise OSError("simulated power loss before staging rename")
        real_replace(source, destination)

    monkeypatch.setattr(analysis_recovery.os, "replace", fail_binding)
    with store.exclusive_lock():
        with pytest.raises(OSError, match="simulated power loss"):
            store.stage_provisional_identity(
                run_id="run-recovery-01",
                project_id="project-recovery-01",
                started_at="2026-08-24T12:34:56Z",
            )
    assert not store.provisional_identity_path.exists()
    assert not list(store.root.glob(".provisional_run_identity.json-*"))

    monkeypatch.setattr(analysis_recovery.os, "replace", real_replace)
    with store.exclusive_lock():
        staged = store.stage_provisional_identity(
            run_id="run-recovery-01",
            project_id="project-recovery-01",
            started_at="2026-08-24T12:34:56Z",
        )
    original = store.provisional_identity_path.read_bytes()
    monkeypatch.setattr(analysis_recovery.os, "replace", fail_binding)
    with store.exclusive_lock():
        with pytest.raises(OSError, match="simulated power loss"):
            store.bind_provisional_snapshot(staged, snapshot_hash="a" * 64)
    assert store.provisional_identity_path.read_bytes() == original
    assert not list(store.root.glob(".provisional_run_identity.json-*"))


@pytest.mark.parametrize(
    "damage",
    ["invalid-json", "duplicate-key", "extra-field", "self-hash"],
)
def test_provisional_identity_invalid_json_or_tamper_fails_closed(
    tmp_path: Path,
    damage: str,
) -> None:
    store = AnalysisRunStore(tmp_path / damage)
    with store.exclusive_lock():
        store.stage_provisional_identity(
            run_id="run-recovery-01",
            project_id="project-recovery-01",
            started_at="2026-08-24T12:34:56Z",
        )
    if damage == "invalid-json":
        store.provisional_identity_path.write_bytes(b"{not-json\n")
    elif damage == "duplicate-key":
        payload = store.provisional_identity_path.read_bytes()
        store.provisional_identity_path.write_bytes(
            payload.replace(b'"run_id":', b'"run_id":"shadow","run_id":', 1)
        )
    else:
        value = json.loads(store.provisional_identity_path.read_text(encoding="utf-8"))
        if damage == "extra-field":
            value["unexpected"] = True
        else:
            value["started_at"] = "2026-08-24T12:34:57Z"
        store.provisional_identity_path.write_bytes(_pretty_json(value))

    with store.exclusive_lock():
        with pytest.raises(RecoveryValidationError):
            store.stage_provisional_identity(
                run_id="run-recovery-01",
                project_id="project-recovery-01",
                started_at=None,
            )


@pytest.mark.parametrize("damage", ["symlink", "directory"])
def test_provisional_identity_symlink_or_nonregular_file_fails_closed(
    tmp_path: Path,
    damage: str,
) -> None:
    store = AnalysisRunStore(tmp_path / damage)
    with store.exclusive_lock():
        store.stage_provisional_identity(
            run_id="run-recovery-01",
            project_id="project-recovery-01",
            started_at="2026-08-24T12:34:56Z",
        )
    saved = store.root / "saved-provisional.json"
    store.provisional_identity_path.rename(saved)
    if damage == "symlink":
        _symlink_or_skip(store.provisional_identity_path, saved)
    else:
        store.provisional_identity_path.mkdir()

    with store.exclusive_lock():
        with pytest.raises(RecoveryValidationError):
            store.stage_provisional_identity(
                run_id="run-recovery-01",
                project_id="project-recovery-01",
                started_at=None,
            )


@pytest.mark.parametrize(
    "name",
    [
        "INPUTS",
        "inputs.",
        "CheckPoints",
        "checkpoints ",
        "CON",
        "con.txt",
        "Lpt9.log",
        "provisional_run_identity.json",
    ],
)
def test_custom_candidate_storage_rejects_portable_aliases_and_reserved_names(
    tmp_path: Path,
    name: str,
) -> None:
    active_root = tmp_path / "active"
    with pytest.raises(RecoveryValidationError):
        AnalysisRunStore(
            active_root,
            candidates_directory=active_root / name,
        )


def test_custom_candidate_storage_rejects_file_symlink_nested_and_outside(
    tmp_path: Path,
) -> None:
    active_root = tmp_path / "active"
    active_root.mkdir()
    ordinary_file = active_root / "ordinary"
    ordinary_file.write_text("not a directory", encoding="utf-8")
    with pytest.raises(RecoveryValidationError, match="not a directory"):
        AnalysisRunStore(active_root, candidates_directory=ordinary_file)

    real_directory = active_root / "real-candidates"
    real_directory.mkdir()
    linked_directory = active_root / "linked-candidates"
    _symlink_or_skip(linked_directory, real_directory, target_is_directory=True)
    with pytest.raises(
        RecoveryValidationError,
        match=r"(?:symlink|link or reparse point)",
    ):
        AnalysisRunStore(active_root, candidates_directory=linked_directory)

    with pytest.raises(RecoveryValidationError, match="one direct child"):
        AnalysisRunStore(
            active_root,
            candidates_directory=active_root / "nested" / "candidates",
        )
    with pytest.raises(RecoveryValidationError, match="one direct child"):
        AnalysisRunStore(
            active_root,
            candidates_directory=tmp_path / "outside-candidates",
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows reparse-point regression")
@pytest.mark.parametrize("location", ["run-root", "candidate-storage"])
def test_windows_junctions_are_rejected_as_storage_paths(
    tmp_path: Path,
    location: str,
) -> None:
    external = tmp_path / f"external-{location}"
    external.mkdir()
    if location == "run-root":
        junction = tmp_path / "active-junction"
        _junction_or_skip(junction, external)
        try:
            with pytest.raises(RecoveryValidationError, match="reparse point"):
                AnalysisRunStore(junction)
        finally:
            if junction.exists():
                junction.rmdir()
        return

    active = tmp_path / "active"
    active.mkdir()
    junction = active / "candidates"
    _junction_or_skip(junction, external)
    try:
        with pytest.raises(RecoveryValidationError, match="reparse point"):
            AnalysisRunStore(active)
    finally:
        if junction.exists():
            junction.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows reparse-point regression")
def test_candidate_repository_rejects_windows_junction_root(tmp_path: Path) -> None:
    external = tmp_path / "external-candidate-repository"
    external.mkdir()
    junction = tmp_path / "candidate-repository-junction"
    _junction_or_skip(junction, external)
    try:
        with pytest.raises(CandidateStoreError, match="unsafe|plain directory"):
            CandidateRepository(junction)
    finally:
        if junction.exists():
            junction.rmdir()


def test_candidate_storage_name_is_frozen_and_legacy_default_remains_readable(
    tmp_path: Path,
) -> None:
    custom_root = tmp_path / "custom"
    custom = AnalysisRunStore(
        custom_root,
        candidates_directory=custom_root / "review-candidates",
    )
    _, frozen = _freeze(custom)
    assert frozen.candidate_storage_name == "review-candidates"
    assert custom.verify_frozen_inputs().candidate_storage_name == "review-candidates"
    other = AnalysisRunStore(
        custom_root,
        candidates_directory=custom_root / "other-candidates",
    )
    with pytest.raises(RecoveryValidationError, match="candidate storage differs"):
        other.verify_frozen_inputs()

    legacy = AnalysisRunStore(tmp_path / "legacy")
    _freeze(legacy)
    metadata_path = legacy.inputs_directory / "frozen_inputs.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["schema"] = "latexstruct-analysis-frozen-inputs-v1"
    metadata.pop("candidate_storage_name")
    metadata_path.write_bytes(_pretty_json(metadata))
    payloads = {
        path.relative_to(legacy.inputs_directory).as_posix(): path.read_bytes()
        for path in legacy.inputs_directory.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    }
    (legacy.inputs_directory / "SHA256SUMS").write_bytes(
        b"".join(
            f"{_sha(payloads[name])}  {name}\n".encode("utf-8")
            for name in sorted(payloads)
        )
    )
    assert AnalysisRunStore(legacy.root).verify_frozen_inputs().candidate_storage_name == (
        "candidates"
    )


def test_hash_verified_bytes_are_the_bytes_parsed_and_returned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    frozen_store = AnalysisRunStore(tmp_path / "frozen")
    _freeze(frozen_store)
    snapshot_path = frozen_store.inputs_directory / "snapshot.json"
    expected_snapshot = snapshot_path.read_bytes()
    original_read = analysis_recovery._read_regular_file
    snapshot_reads = 0

    def replace_snapshot_after_read(path: Path) -> bytes:
        nonlocal snapshot_reads
        payload = original_read(path)
        if path == snapshot_path:
            snapshot_reads += 1
            if snapshot_reads == 1:
                snapshot_path.write_bytes(b'{"replaced":true}\n')
        return payload

    monkeypatch.setattr(
        analysis_recovery,
        "_read_regular_file",
        replace_snapshot_after_read,
    )
    frozen = frozen_store.verify_frozen_inputs()
    assert frozen.snapshot_bytes == expected_snapshot
    assert snapshot_reads == 1


def test_candidate_and_checkpoint_consumers_use_the_hash_verified_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = AnalysisRunStore(tmp_path / "active")
    values, _ = _freeze(store)
    candidate = _candidate(
        store,
        tex=values["baseline_tex"],
        round_index=0,
        disposition=CandidateDisposition.BASELINE,
    )
    committed = _commit(store, candidate, sequence=1, round_index=0)
    compile_log_path = store.candidates_directory / candidate.candidate_id / "compile.log"
    run_state_path = committed.directory / "run_state.json"
    expected_log = compile_log_path.read_bytes()
    expected_state = json.loads(run_state_path.read_text(encoding="utf-8"))
    original_read = analysis_recovery._read_regular_file
    reads = {compile_log_path: 0, run_state_path: 0}

    def replace_after_read(path: Path) -> bytes:
        payload = original_read(path)
        if path in reads:
            reads[path] += 1
            if reads[path] == 1:
                path.write_bytes(b'{"unverified":"replacement"}\n')
        return payload

    monkeypatch.setattr(analysis_recovery, "_read_regular_file", replace_after_read)
    recovered = store.recover_latest()
    assert recovered.checkpoint is not None
    assert recovered.checkpoint.current_candidate.compile_log_bytes == expected_log
    assert recovered.checkpoint.run_state == expected_state
    assert reads == {compile_log_path: 1, run_state_path: 1}


@pytest.mark.parametrize("mode", ["false", "exception"])
def test_semantic_validator_rejects_newest_and_recovers_older_without_leakage(
    tmp_path: Path,
    mode: str,
) -> None:
    store = AnalysisRunStore(tmp_path / mode)
    values, _ = _freeze(store)
    baseline = _candidate(
        store,
        tex=values["baseline_tex"],
        round_index=0,
        disposition=CandidateDisposition.BASELINE,
    )
    older = _commit(store, baseline, sequence=1, round_index=0)
    accepted = _candidate(
        store,
        tex=values["baseline_tex"] + b"% accepted\n",
        round_index=1,
        disposition=CandidateDisposition.ACCEPTED,
        parent_candidate_id=baseline.candidate_id,
    )
    _commit(store, accepted, sequence=2, round_index=1)
    seen: list[int] = []

    def validate(checkpoint: object) -> bool:
        sequence = checkpoint.sequence  # type: ignore[attr-defined]
        seen.append(sequence)
        if sequence == 2 and mode == "exception":
            raise RuntimeError("private-validator-detail")
        return sequence != 2

    recovered = store.recover_latest(semantic_validator=validate)
    assert recovered.checkpoint is not None
    assert recovered.checkpoint.checkpoint_id == older.checkpoint_id
    assert seen == [2, 1]
    semantic_rejections = [
        rejection
        for rejection in recovered.rejected
        if rejection.code == "semantic_validation"
    ]
    assert len(semantic_rejections) == 1
    assert semantic_rejections[0].sequence == 2
    assert "private-validator-detail" not in semantic_rejections[0].message

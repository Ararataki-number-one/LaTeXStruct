from __future__ import annotations

import json
import threading

import pytest

import latexstruct.server.audit_store as audit_store_module
from latexstruct.core.audit_schema import (
    ArtifactRole,
    AuditSubmissionRequest,
    AuditWorkflow,
    RunSnapshot,
    TerminalStatus,
)
from latexstruct.core.audit_submission import (
    FULL_PROMPT_PATH,
    MANIFEST_PATH,
    README_PATH,
    SHORT_PROMPT_PATH,
    make_audit_artifact,
)
from latexstruct.server.audit_store import AuditSubmissionStore


def _snapshot(
    *,
    suffix: bytes = b"",
    path_in_metadata: bool = False,
    extra_metadata: dict | None = None,
) -> RunSnapshot:
    source = make_audit_artifact(ArtifactRole.SOURCE_TEX, b"source" + suffix)
    current = make_audit_artifact(
        ArtifactRole.CURRENT_TEX,
        b"current" + suffix,
        parent_artifact_ids=(source.artifact_id,),
        metadata={"local_path": r"C:\Users\ZQY\input.tex"} if path_in_metadata else {},
    )
    duplicate = make_audit_artifact(ArtifactRole.STAGE_SOURCE_TEX, b"source" + suffix)
    metadata = {
        "source_path": "/home/zqy/input.tex",
        "workspace": "/workspace/zqy/project",
        "id_token": "identity-secret",
        "ANTHROPIC_API_KEY": "anthropic-secret",
        "email": "codex-user@example.test",
        "application": "/Applications/Codex/auth.json",
    } if path_in_metadata else {}
    metadata.update(extra_metadata or {})
    return RunSnapshot(
        project_id="中文项目",
        run_id="run-store",
        workflow=AuditWorkflow.ANALYSIS_REVIEW_ONLY,
        terminal_status=TerminalStatus.PARTIAL,
        captured_at="2026-08-22T01:00:00Z",
        artifacts=(source, duplicate, current),
        machine_verification={
            "safe_to_export": False,
            "compile": {
                "log_path": r"C:\Users\ZQY\AppData\Local\Temp\compile.log"
                if path_in_metadata
                else "compile.log"
            },
        },
        blockers=(r"检查 C:\Users\ZQY\input.tex",) if path_in_metadata else ("compile",),
        model="codex",
        app_version="1.2.6",
        template="elegantbook",
        page_range="1-2",
        metadata=metadata,
    )


@pytest.fixture
def store(tmp_path):
    project = tmp_path / "中文项目"
    project.mkdir()
    return AuditSubmissionStore(project)


def test_snapshot_persists_deeply_with_content_addressed_blob_reuse(store):
    snapshot = _snapshot()
    snapshot_id = store.save_snapshot(snapshot)
    descriptor = json.loads(
        (store.root / "snapshots" / f"{snapshot_id}.json").read_text(encoding="utf-8")
    )
    assert descriptor["snapshot_id"] == snapshot.snapshot_id
    assert all(not row["blob"].startswith(("/", "C:")) for row in descriptor["artifacts"])
    assert descriptor["artifacts"][0]["blob"] == descriptor["artifacts"][1]["blob"]
    assert descriptor["artifacts"][0]["artifact_id"] == snapshot.artifacts[0].artifact_id
    assert len(list((store.root / "blobs").rglob("*.blob"))) == 2

    loaded = store.load_snapshot(snapshot_id)
    assert loaded.snapshot_id == snapshot.snapshot_id
    assert loaded.current_fingerprint == snapshot.current_fingerprint
    assert [item.data for item in loaded.artifacts] == [item.data for item in snapshot.artifacts]
    assert loaded.artifacts[2].parent_artifact_ids == (snapshot.artifacts[0].artifact_id,)


def test_snapshot_descriptor_redacts_absolute_paths_and_sensitive_location_fields(store):
    snapshot_id = store.save_snapshot(_snapshot(path_in_metadata=True))
    descriptor_path = store.root / "snapshots" / f"{snapshot_id}.json"
    text = descriptor_path.read_text(encoding="utf-8")
    assert r"C:\Users\ZQY" not in text
    assert "/home/zqy" not in text
    assert "/workspace/zqy" not in text
    assert "identity-secret" not in text
    assert "anthropic-secret" not in text
    assert "codex-user@example.test" not in text
    assert "/Applications/Codex" not in text
    assert "<LOCAL_PATH>" in text or "<REDACTED>" in text
    loaded = store.load_snapshot(snapshot_id)
    assert loaded.machine_verification["safe_to_export"] is False


def test_snapshot_descriptor_redacts_composite_codex_login_fields(store):
    snapshot_id = store.save_snapshot(_snapshot(extra_metadata={
        "codex_login_token": "login-token-secret",
        "codex_login_email": "user@example.test",
        "chatgpt_account_email": "chatgpt@example.test",
        "codex_account_id": "account-secret",
    }))
    descriptor = json.loads(
        (store.root / "snapshots" / f"{snapshot_id}.json").read_text(encoding="utf-8")
    )
    for key in (
        "codex_login_token",
        "codex_login_email",
        "chatgpt_account_email",
        "codex_account_id",
    ):
        assert descriptor["metadata"][key] == "<REDACTED>"


def test_snapshot_descriptor_keeps_only_bounded_machine_verification_summary(store):
    source = make_audit_artifact(ArtifactRole.SOURCE_TEX, b"source")
    snapshot = RunSnapshot(
        project_id="project",
        run_id="bounded",
        workflow=AuditWorkflow.ANALYSIS_REVIEW_ONLY,
        terminal_status=TerminalStatus.UNVERIFIED,
        captured_at="2026-08-22T00:00:00Z",
        artifacts=(source,),
        machine_verification={
            "safe_to_export": False,
            "checks": [{"id": str(index), "message": "x" * 10000} for index in range(250)],
            "huge_private_record": "y" * 100000,
        },
    )
    snapshot_id = store.save_snapshot(snapshot)
    descriptor = json.loads(
        (store.root / "snapshots" / f"{snapshot_id}.json").read_text(encoding="utf-8")
    )
    verification = descriptor["machine_verification"]
    assert "huge_private_record" not in verification
    assert len(verification["checks"]) == 100
    assert max(len(item["message"]) for item in verification["checks"]) == 2000


def test_snapshot_is_idempotent_but_cannot_be_overwritten(store):
    snapshot = _snapshot()
    snapshot_id = store.save_snapshot(snapshot)
    store.save_snapshot(snapshot)
    descriptor = store.root / "snapshots" / f"{snapshot_id}.json"
    descriptor.write_text("{}", encoding="utf-8")
    with pytest.raises(FileExistsError, match="immutable"):
        store.save_snapshot(snapshot)


def test_snapshot_descriptor_tampering_cannot_promote_verified_or_change_lineage(store):
    snapshot_id = store.save_snapshot(_snapshot())
    path = store.root / "snapshots" / f"{snapshot_id}.json"
    descriptor = json.loads(path.read_text(encoding="utf-8"))
    descriptor["machine_verification"]["safe_to_export"] = True
    descriptor["artifacts"][-1]["parent_artifact_ids"] = []
    path.write_text(json.dumps(descriptor, ensure_ascii=False), encoding="utf-8")
    with pytest.raises(ValueError, match="integrity check"):
        store.load_snapshot(snapshot_id)


def test_snapshot_descriptor_filename_and_embedded_id_are_bound(store):
    snapshot_id = store.save_snapshot(_snapshot())
    path = store.root / "snapshots" / f"{snapshot_id}.json"
    descriptor = json.loads(path.read_text(encoding="utf-8"))
    descriptor["snapshot_id"] = "snapshot-other"
    path.write_text(json.dumps(descriptor, ensure_ascii=False), encoding="utf-8")
    with pytest.raises(ValueError, match="ID does not match"):
        store.load_snapshot(snapshot_id)


def test_corrupt_or_missing_blob_is_rejected(store):
    snapshot_id = store.save_snapshot(_snapshot())
    descriptor = json.loads(
        (store.root / "snapshots" / f"{snapshot_id}.json").read_text(encoding="utf-8")
    )
    blob = store.root / descriptor["artifacts"][0]["blob"]
    blob.write_bytes(b"corrupt")
    with pytest.raises(ValueError, match="hash/size"):
        store.load_snapshot(snapshot_id)


def test_terminal_snapshot_commits_exactly_four_lightweight_controls_and_latest(store):
    submission = store.create_lightweight(_snapshot(), audit_focus="检查定理边界")
    directory = store.root / submission.relative_directory
    assert submission.state == "LIGHTWEIGHT"
    assert submission.zip_relative_path is None
    assert {path.name for path in directory.iterdir()} == {
        README_PATH,
        SHORT_PROMPT_PATH,
        FULL_PROMPT_PATH,
        MANIFEST_PATH,
        "submission.json",
    }
    assert store.latest() == submission
    assert "检查定理边界" in (directory / FULL_PROMPT_PATH).read_text(encoding="utf-8")


def test_tampered_or_missing_lightweight_control_fails_closed(store):
    submission = store.create_lightweight(_snapshot())
    directory = store.root / submission.relative_directory
    (directory / SHORT_PROMPT_PATH).write_text("tampered", encoding="utf-8")
    with pytest.raises(ValueError, match="control file failed verification"):
        store.get_submission(submission.submission_id)
    with pytest.raises(ValueError, match="control file failed verification"):
        store.latest()


def test_same_requested_zip_name_never_overwrites_older_submission(store):
    snapshot = _snapshot()
    store.save_snapshot(snapshot)
    first = store.generate_zip(snapshot.snapshot_id, filename="AI 审计提交包.zip")
    first_path = store.download_path(first.submission_id)
    first_bytes = first_path.read_bytes()
    second = store.generate_zip(snapshot.snapshot_id, filename="AI 审计提交包.zip")
    second_path = store.download_path(second.submission_id)
    assert first.submission_id != second.submission_id
    assert first_path != second_path
    assert first_path.name == second_path.name == "AI 审计提交包.zip"
    assert first_path.read_bytes() == first_bytes
    assert store.latest().submission_id == second.submission_id


def test_generating_older_snapshot_cannot_replace_newer_terminal_latest(store):
    older = _snapshot(suffix=b"-older")
    newer = _snapshot(suffix=b"-newer")
    older_light = store.create_lightweight(older)
    newer_light = store.create_lightweight(newer)
    assert store.latest().submission_id == newer_light.submission_id

    older_zip = store.generate_zip(older_light.snapshot_id)
    assert older_zip.snapshot_id == older.snapshot_id
    assert store.latest().submission_id == newer_light.submission_id


def test_force_latest_racing_old_zip_returns_old_zip_stale(store, monkeypatch):
    """A terminal commit wins even if an old ZIP reaches commit concurrently."""
    older = _snapshot(suffix=b"-race-older")
    newer = _snapshot(suffix=b"-race-newer")
    older_light = store.create_lightweight(older)
    zip_store = AuditSubmissionStore(store.root.parent)

    terminal_holds_lock = threading.Event()
    release_terminal = threading.Event()
    zip_reached_commit = threading.Event()
    original_lightweight_builder = audit_store_module.build_lightweight_audit_files

    def pause_new_terminal(snapshot, *args, **kwargs):
        if snapshot.snapshot_id == newer.snapshot_id:
            terminal_holds_lock.set()
            assert release_terminal.wait(timeout=10)
        return original_lightweight_builder(snapshot, *args, **kwargs)

    original_zip_commit = zip_store._commit_submission

    def observe_zip_commit(result, *, zip_filename, force_latest=False):
        zip_reached_commit.set()
        return original_zip_commit(
            result,
            zip_filename=zip_filename,
            force_latest=force_latest,
        )

    monkeypatch.setattr(
        audit_store_module,
        "build_lightweight_audit_files",
        pause_new_terminal,
    )
    monkeypatch.setattr(zip_store, "_commit_submission", observe_zip_commit)

    results = {}
    errors = []

    def publish_terminal():
        try:
            results["terminal"] = store.persist_terminal_snapshot(newer)
        except BaseException as exc:  # pragma: no cover - surfaced below
            errors.append(exc)

    def publish_old_zip():
        try:
            results["zip"] = zip_store.generate_zip(older.snapshot_id)
        except BaseException as exc:  # pragma: no cover - surfaced below
            errors.append(exc)

    terminal_thread = threading.Thread(target=publish_terminal)
    terminal_thread.start()
    assert terminal_holds_lock.wait(timeout=10)

    zip_thread = threading.Thread(target=publish_old_zip)
    zip_thread.start()
    assert zip_reached_commit.wait(timeout=10)
    release_terminal.set()

    terminal_thread.join(timeout=10)
    zip_thread.join(timeout=10)
    assert not terminal_thread.is_alive()
    assert not zip_thread.is_alive()
    assert errors == []

    terminal = results["terminal"]
    old_zip = results["zip"]
    assert store.latest().submission_id == terminal.submission_id
    assert old_zip.stale is True
    assert "新的终态运行快照" in old_zip.stale_reason
    assert store.get_submission(old_zip.submission_id).stale is True
    assert store.get_submission(older_light.submission_id).stale is True


def test_force_latest_repairs_corrupt_latest_pointer(store):
    older = store.create_lightweight(_snapshot(suffix=b"-pointer-older"))
    (store.root / "latest.json").write_text("{broken", encoding="utf-8")
    with pytest.raises(json.JSONDecodeError):
        store.latest()

    newer = store.persist_terminal_snapshot(_snapshot(suffix=b"-pointer-newer"))

    assert store.latest().submission_id == newer.submission_id
    assert store.get_submission(older.submission_id).stale is True
    pointer = json.loads((store.root / "latest.json").read_text(encoding="utf-8"))
    assert pointer["submission_id"] == newer.submission_id


def test_force_latest_bypasses_corrupt_historic_controls_but_reads_fail_closed(store):
    older = store.create_lightweight(_snapshot(suffix=b"-control-older"))
    old_directory = store.root / older.relative_directory
    (old_directory / SHORT_PROMPT_PATH).write_text("tampered", encoding="utf-8")
    with pytest.raises(ValueError, match="control file failed verification"):
        store.latest()

    newer = store.persist_terminal_snapshot(_snapshot(suffix=b"-control-newer"))

    assert store.latest().submission_id == newer.submission_id
    with pytest.raises(ValueError, match="control file failed verification"):
        store.get_submission(older.submission_id)
    stale = json.loads(
        (store.root / "stale" / f"{older.submission_id}.json").read_text(
            encoding="utf-8"
        )
    )
    assert stale["submission_id"] == older.submission_id
    assert stale["current_fingerprint"] == newer.snapshot_fingerprint


def test_zip_filename_rejects_paths_and_windows_device_aliases(store):
    snapshot = _snapshot()
    store.save_snapshot(snapshot)
    with pytest.raises(ValueError, match="must not contain a directory"):
        store.generate_zip(snapshot.snapshot_id, filename="outside/audit.zip")
    with pytest.raises(ValueError, match="reserved Windows device"):
        store.generate_zip(snapshot.snapshot_id, filename="CON.zip")


def test_download_rechecks_zip_hash_and_size(store):
    snapshot = _snapshot()
    store.save_snapshot(snapshot)
    submission = store.generate_zip(snapshot.snapshot_id)
    path = store.download_path(submission.submission_id)
    path.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="hash/size"):
        store.download_path(submission.submission_id)


def test_stale_reason_is_explicit_and_latest_summary_reflects_sidecar(store):
    submission = store.create_lightweight(_snapshot())
    stale = store.mark_stale(
        submission.submission_id,
        "用户接受了新的审阅项",
        current_fingerprint="f" * 64,
        marked_at="2026-08-22T02:00:00Z",
    )
    assert stale.stale is True
    assert stale.stale_reason == "用户接受了新的审阅项"
    assert stale.current_fingerprint == "f" * 64
    assert store.latest().stale is True
    with pytest.raises(ValueError, match="explicit reason"):
        store.mark_stale(submission.submission_id, "")


def test_mark_outdated_submissions_compares_immutable_fingerprint(store):
    current = store.create_lightweight(_snapshot())
    marked = store.mark_outdated_submissions("0" * 64, "current TeX changed")
    assert current.submission_id in marked
    assert store.get_submission(current.submission_id).stale_reason == "current TeX changed"


def test_mark_outdated_skips_corrupt_history_without_weakening_direct_reads(store):
    first = store.create_lightweight(_snapshot(suffix=b"-old"))
    first_control = (
        store.root / first.relative_directory / "01_PROMPT_SHORT.txt"
    )
    first_control.write_text("tampered", encoding="utf-8")

    current = store.create_lightweight(_snapshot(suffix=b"-current"))

    with pytest.raises(ValueError, match="control file failed verification"):
        store.get_submission(first.submission_id)
    assert store.mark_outdated_submissions(
        current.snapshot_fingerprint,
        "current changed",
    ) == ()
    assert store.latest().submission_id == current.submission_id
    assert store.latest().stale is False


def test_generate_zip_can_mark_new_package_stale_against_current_state(store):
    snapshot = _snapshot()
    store.save_snapshot(snapshot)
    submission = store.generate_zip(
        snapshot.snapshot_id,
        AuditSubmissionRequest(),
        current_fingerprint="1" * 64,
        stale_reason="current PDF changed",
    )
    assert submission.state == "READY"
    assert submission.stale is True
    assert submission.stale_reason == "current PDF changed"


def test_failed_generation_does_not_advance_latest_or_leave_stage_directory(store, monkeypatch):
    snapshot = _snapshot()
    previous = store.create_lightweight(snapshot)

    def fail(*_args, **_kwargs):
        raise RuntimeError("build failed")

    monkeypatch.setattr("latexstruct.server.audit_store.build_audit_submission", fail)
    with pytest.raises(RuntimeError, match="build failed"):
        store.generate_zip(snapshot.snapshot_id)
    assert store.latest().submission_id == previous.submission_id
    assert not any(path.name.startswith(".submission-") for path in store.root.iterdir())


def test_public_summaries_and_descriptors_do_not_contain_project_absolute_root(store):
    submission = store.create_lightweight(_snapshot())
    serialized = json.dumps(submission.to_dict(), ensure_ascii=False)
    assert str(store.root.parent) not in serialized
    descriptors = b"\n".join(
        path.read_bytes()
        for path in store.root.rglob("*.json")
        if "submission_manifest.json" not in path.as_posix()
    ).decode("utf-8")
    assert str(store.root.parent) not in descriptors

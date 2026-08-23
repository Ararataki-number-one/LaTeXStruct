from __future__ import annotations

import hashlib
import io
import json
import re
import zipfile

import pytest

import latexstruct.core.audit_submission as audit_submission_module
from latexstruct.core.audit_evidence import (
    build_metrics,
    build_report_json,
    compile_input_manifest_sha256,
    issues_csv_bytes,
    template_manifest,
    template_manifest_sha256,
)
from latexstruct.core.audit_schema import (
    ArtifactRole,
    AuditArtifact,
    AuditDepth,
    AuditPackageStatus,
    AuditSubmissionRequest,
    AuditWorkflow,
    PackagingStatus,
    RunSnapshot,
    StageExecutionStatus,
    TerminalStatus,
)
from latexstruct.core.audit_submission import (
    FULL_PROMPT_PATH,
    MANIFEST_PATH,
    MAX_AUDIT_ZIP_BYTES,
    README_PATH,
    SHA256SUMS_PATH,
    SHORT_PROMPT_PATH,
    build_audit_submission,
    build_lightweight_audit_files,
    canonical_artifact_path,
    make_audit_artifact,
    snapshot_fingerprint_from_hashes,
    write_audit_submission_atomic,
)
from latexstruct.core.preview import COMPILED, PARTIAL_COMPILED, SOURCE_PREVIEW


def _artifact(
    role: str,
    data: bytes,
    *,
    path: str | None = None,
    preview_status: str | None = None,
    parents=(),
    media_type: str | None = None,
) -> AuditArtifact:
    return make_audit_artifact(
        role,
        data,
        path=path,
        preview_status=preview_status,
        parent_artifact_ids=parents,
        media_type=media_type or (
            "application/pdf" if role.endswith("PREVIEW") else "text/plain"
        ),
    )


def _snapshot(
    *,
    workflow: AuditWorkflow = AuditWorkflow.ANALYSIS_REVIEW_ONLY,
    terminal: TerminalStatus = TerminalStatus.SUCCESS,
    verified: bool = False,
    artifacts: tuple[AuditArtifact, ...] | None = None,
    machine_verification: dict[str, object] | None = None,
    stages: dict[str, object] | None = None,
    source_pdf: dict[str, object] | None = None,
) -> RunSnapshot:
    source = _artifact(ArtifactRole.SOURCE_TEX, b"source\n")
    current = _artifact(
        ArtifactRole.CURRENT_TEX,
        b"current\n",
        parents=(source.artifact_id,),
    )
    return RunSnapshot(
        project_id="中文项目",
        run_id="run-1",
        workflow=workflow,
        terminal_status=terminal,
        captured_at="2026-08-22T00:00:00Z",
        artifacts=artifacts or (source, current),
        machine_verification=(
            {"safe_to_export": verified}
            if machine_verification is None
            else machine_verification
        ),
        blockers=() if verified else ("机器验证尚未通过",),
        model="gpt-test",
        app_version="1.2.6",
        template="elegantbook",
        page_range="1-17",
        stages=stages or {},
        source_pdf=source_pdf,
    )


@pytest.mark.parametrize("workflow", list(AuditWorkflow))
@pytest.mark.parametrize("terminal", list(TerminalStatus))
def test_all_workflows_and_terminal_states_can_build(workflow, terminal):
    result = build_audit_submission(
        _snapshot(workflow=workflow, terminal=terminal),
        submission_id=f"test-{workflow.value}-{terminal.value}",
        generated_at="2026-08-22T00:00:01Z",
    )
    with zipfile.ZipFile(io.BytesIO(result.zip_bytes)) as archive:
        manifest = json.loads(archive.read(MANIFEST_PATH))
        assert manifest["workflow"] == workflow.value
        assert manifest["terminal_status"] == terminal.value
        assert manifest["verification_status"] == "UNVERIFIED"
        assert {README_PATH, SHORT_PROMPT_PATH, FULL_PROMPT_PATH, MANIFEST_PATH}.issubset(
            archive.namelist()
        )


def test_snapshot_is_byte_immutable_and_success_does_not_promote_verification():
    source = bytearray(b"before")
    artifact = AuditArtifact(ArtifactRole.SOURCE_TEX, "inputs/source.tex", source)
    snapshot = _snapshot(artifacts=(artifact,), verified=False)
    source[:] = b"after!"
    assert snapshot.artifacts[0].data == b"before"
    assert snapshot.verification_status == "UNVERIFIED"
    result = build_audit_submission(snapshot)
    assert result.manifest.verification_status == "UNVERIFIED"


def test_verified_is_copied_only_from_existing_machine_result():
    snapshot = _snapshot(terminal=TerminalStatus.FAILED, verified=True)
    assert snapshot.verification_status == "VERIFIED"
    assert build_audit_submission(snapshot).manifest.verification_status == "VERIFIED"


def test_missing_files_are_reported_and_prompt_does_not_claim_paths_for_them():
    result = build_audit_submission(_snapshot())
    missing = set(result.manifest.missing_expected_roles)
    assert ArtifactRole.REPORT in missing
    prompt = result.files[FULL_PROMPT_PATH].decode("utf-8")
    assert "audit/report.md" not in prompt
    assert "`REPORT`" in prompt
    actual_paths = {item.path for item in result.manifest.artifacts}
    table_paths = {
        match.group(1)
        for match in re.finditer(r"\| [A-Z][A-Z0-9_]+ \| ([^|]+?) \|", prompt)
    }
    assert {path.strip() for path in table_paths}.issubset(actual_paths)


def test_byte_sha256_deduplication_records_role_and_path_aliases():
    source = _artifact(ArtifactRole.SOURCE_TEX, b"same bytes")
    stage = _artifact(
        ArtifactRole.STAGE_SOURCE_TEX,
        b"same bytes",
        parents=(source.artifact_id,),
    )
    assert source.artifact_id != stage.artifact_id
    result = build_audit_submission(_snapshot(artifacts=(source, stage)))
    data_records = [
        item for item in result.manifest.artifacts if item.artifact_role == ArtifactRole.SOURCE_TEX
    ]
    assert len(data_records) == 1
    assert data_records[0].path == "inputs/source.tex"
    alias = data_records[0].aliases[0]
    assert "path" not in alias
    assert alias["logical_path"] == "stages/00_source.tex"
    assert alias["canonical_path"] == "inputs/source.tex"
    assert alias["canonical_artifact_id"] == source.artifact_id
    assert alias["deduplicated"] is True
    assert data_records[0].aliases[0]["artifact_role"] == ArtifactRole.STAGE_SOURCE_TEX
    assert data_records[0].aliases[0]["artifact_id"] == stage.artifact_id
    assert data_records[0].aliases[0]["parent_artifact_ids"] == (source.artifact_id,)
    assert data_records[0].artifact_id == source.artifact_id
    assert "stages/00_source.tex" not in result.files
    authority = json.loads(result.files[MANIFEST_PATH])["authority"]
    assert "submission_manifest.json.artifacts[].aliases[].artifact_role" in authority[
        "artifact_roles"
    ]
    prompt = result.files[FULL_PROMPT_PATH].decode("utf-8")
    assert ArtifactRole.STAGE_SOURCE_TEX in prompt
    assert "logical_path=stages/00_source.tex" in prompt
    assert "canonical_path=inputs/source.tex" in prompt


def test_same_name_different_bytes_never_overwrites():
    one = _artifact(ArtifactRole.EVIDENCE, b"one", path="evidence/证据.txt")
    two = _artifact(ArtifactRole.EVIDENCE, b"two", path="evidence/证据.txt")
    result = build_audit_submission(_snapshot(artifacts=(one, two)))
    assert result.files["evidence/证据.txt"] == b"one"
    assert result.files["evidence/证据-2.txt"] == b"two"


def test_raw_to_current_diff_uses_tex_aware_sanitizer_and_integrity_gate():
    diff = (
        "--- raw.tex\n"
        "+++ current.tex\n"
        "@@ -1 +1 @@\n"
        "-u\\in V:\\lvert N(u)\\rvert\\n"
        "+u\\in V:\\lvert N(u)\\rvert\\n"
    ).encode("utf-8")
    artifact = make_audit_artifact(
        ArtifactRole.RAW_TO_CURRENT_DIFF,
        diff,
        path="audit/raw_to_current.diff",
        media_type="text/x-diff",
    )

    result = build_audit_submission(_snapshot(artifacts=(artifact,)))

    packaged = result.files["audit/raw_to_current.diff"].decode("utf-8")
    assert packaged == diff.decode("utf-8")
    assert r"V:\lvert" in packaged
    assert r"<LOCAL_PATH>(u)" not in packaged
    integrity = json.loads(result.files["audit/packaging-integrity.json"])
    checked = [
        item
        for item in integrity["artifacts"]
        if item["artifact_role"] == ArtifactRole.RAW_TO_CURRENT_DIFF
    ]
    assert len(checked) == 1
    assert checked[0]["valid"] is True


def test_deduplicated_alias_cannot_collide_with_file_or_control_namespace():
    first = _artifact(ArtifactRole.EVIDENCE, b"same", path="evidence/a.txt")
    second = _artifact(ArtifactRole.EVIDENCE, b"different", path="evidence/a.txt")
    alias = _artifact(ArtifactRole.PROJECT_FILE, b"same", path="evidence/a-2.txt")
    control_alias = _artifact(
        ArtifactRole.STAGE_SOURCE_TEX,
        b"same",
        path=MANIFEST_PATH,
    )
    result = build_audit_submission(_snapshot(artifacts=(first, second, alias, control_alias)))
    record = next(item for item in result.manifest.artifacts if item.path == "evidence/a.txt")
    alias_paths = [item["logical_path"] for item in record.aliases]
    assert "evidence/a-2.txt" not in alias_paths
    assert MANIFEST_PATH not in alias_paths
    assert len(alias_paths) == len(set(alias_paths))
    assert not set(alias_paths).intersection(result.files)
    assert any(
        item.get("requested_logical_path") == "evidence/a-2.txt"
        for item in record.aliases
    )
    assert any(
        item.get("requested_logical_path") == MANIFEST_PATH
        for item in record.aliases
    )


def test_chinese_paths_are_portable_and_absolute_paths_are_rejected():
    item = _artifact(ArtifactRole.EVIDENCE, "中文".encode(), path="evidence/中文/证据.txt")
    result = build_audit_submission(_snapshot(artifacts=(item,)))
    assert "evidence/中文/证据.txt" in result.files
    bad = _artifact(ArtifactRole.EVIDENCE, b"bad", path=r"C:\Users\FixtureUser\secret.txt")
    with pytest.raises(ValueError, match="non-portable"):
        build_audit_submission(_snapshot(artifacts=(bad,)))


def test_default_privacy_cleanup_removes_credentials_and_local_paths():
    secret = (
        "Authorization: Bearer abcdefghijklmnopqrstuvwxyz\n"
        "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz\n"
        "ANTHROPIC_API_KEY=anthropic-secret-value\n"
        "GOOGLE_API_KEY=google-secret-value\n"
        '{"codex_login":"login-secret-value","Authorization":"Bearer json-secret-value"}\n'
        '{"id_token":"identity-secret-value","account_id":"account-secret-value",'
        '"email":"codex-user@example.test"}\n'
        r"log=C:\Users\FixtureUser\private\main.tex" + "\n"
        "cache=/home/fixture/.codex/auth.json\n"
        "workspace=/workspace/private/project/main.tex\n"
        "mac=/Applications/Codex/auth.json\n"
        "volume=/Volumes/Private/auth.json\n"
        "media=/media/user/auth.json\n"
    ).encode()
    item = _artifact(ArtifactRole.ERROR_LOG, secret)
    result = build_audit_submission(
        _snapshot(terminal=TerminalStatus.FAILED, artifacts=(item,))
    )
    payload = result.files["audit/error.log"].decode()
    whole_bundle = b"\n".join(result.files.values())
    assert "<REDACTED>" in payload
    assert "<LOCAL_PATH>" in payload
    assert b"sk-abcdefghijklmnopqrstuvwxyz" not in whole_bundle
    assert b"login-secret-value" not in whole_bundle
    assert b"json-secret-value" not in whole_bundle
    assert b"identity-secret-value" not in whole_bundle
    assert b"account-secret-value" not in whole_bundle
    assert b"anthropic-secret-value" not in whole_bundle
    assert b"google-secret-value" not in whole_bundle
    assert b"codex-user@example.test" not in whole_bundle
    assert b"C:\\Users\\FixtureUser" not in whole_bundle
    assert b"/home/fixture" not in whole_bundle
    assert b"/workspace/private" not in whole_bundle
    assert b"/Applications/Codex" not in whole_bundle
    assert b"/Volumes/Private" not in whole_bundle
    assert b"/media/user" not in whole_bundle


def test_json_privacy_cleanup_decodes_values_without_destroying_latex():
    latex = r"\documentclass{article}\begin{document}Text\end{document}"
    record = {
        "tex": latex,
        "codex_login_token": "login-token-secret",
        "codex_login_email": "user@example.test",
        "chatgpt_account_email": "chatgpt@example.test",
        "codex_account_id": "account-secret",
        "nested": {"path": r"C:\Users\FixtureUser\private\main.tex"},
    }
    artifact = make_audit_artifact(
        ArtifactRole.VERIFICATION,
        json.dumps(record).encode("utf-8"),
        media_type="application/json",
    )
    result = build_audit_submission(_snapshot(artifacts=(artifact,)))
    cleaned = json.loads(result.files["audit/verification.json"])
    assert cleaned["tex"] == latex
    assert cleaned["codex_login_token"] == "<REDACTED>"
    assert cleaned["codex_login_email"] == "<REDACTED>"
    assert cleaned["chatgpt_account_email"] == "<REDACTED>"
    assert cleaned["codex_account_id"] == "<REDACTED>"
    assert cleaned["nested"]["path"] == "<LOCAL_PATH>"


def test_composite_codex_login_fields_are_redacted_in_plain_logs():
    artifact = _artifact(
        ArtifactRole.ERROR_LOG,
        (
            "codex_login_token=login-token-secret\n"
            "codex_login_email=user@example.test\n"
            "chatgpt_account_email=chatgpt@example.test\n"
            "codex_account_id=account-secret\n"
        ).encode(),
    )
    result = build_audit_submission(
        _snapshot(terminal=TerminalStatus.FAILED, artifacts=(artifact,))
    )
    payload = result.files["audit/error.log"].decode()
    assert "login-token-secret" not in payload
    assert "user@example.test" not in payload
    assert "chatgpt@example.test" not in payload
    assert "account-secret" not in payload


def test_privacy_cleanup_preserves_tex_delimiters_around_paths_and_secrets():
    tex = "\n".join([
        r"\documentclass{article}",
        r"\usepackage{graphicx}",
        r"\newcommand{\auth}{Authorization: Bearer abcdefghijklmnopqrstuvwxyz}",
        r"\newcommand{\apikey}{OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz}",
        r"\newcommand{\login}{codex_login_token=codex-secret-value}",
        r"\begin{document}",
        r"\includegraphics[width=.4\textwidth]{C:\Users\FixtureUser\secret\figure.png}",
        r"\includegraphics{/home/fixture/private/second-figure.png}",
        r"\end{document}",
    ])
    artifact = make_audit_artifact(
        ArtifactRole.SOURCE_TEX,
        tex.encode("utf-8"),
        media_type="application/x-tex; charset=utf-8",
    )
    result = build_audit_submission(_snapshot(artifacts=(artifact,)))
    cleaned = result.files["inputs/source.tex"].decode("utf-8")

    assert r"\includegraphics[width=.4\textwidth]{<LOCAL_PATH>}" in cleaned
    assert r"\includegraphics{<LOCAL_PATH>}" in cleaned
    assert r"\newcommand{\auth}{Authorization: Bearer <REDACTED>}" in cleaned
    assert r"\newcommand{\apikey}{OPENAI_API_KEY=<REDACTED>}" in cleaned
    assert r"\newcommand{\login}{codex_login_token=<REDACTED>}" in cleaned
    assert cleaned.count("{") == tex.count("{")
    assert cleaned.count("}") == tex.count("}")
    assert cleaned.count("[") == tex.count("[")
    assert cleaned.count("]") == tex.count("]")
    assert r"C:\Users\FixtureUser" not in cleaned
    assert "/home/fixture" not in cleaned
    assert "abcdefghijklmnopqrstuvwxyz" not in cleaned
    assert "codex-secret-value" not in cleaned


def test_privacy_cleanup_preserves_json_and_log_assignment_delimiters():
    record = {
        "source_path": r"C:\Users\FixtureUser\private\main.tex",
        "nested": {
            "preview": "/workspace/private/current.pdf",
            "Authorization": "Bearer json-secret-value",
            "codex_login_email": "user@example.test",
        },
        "tex": r"\includegraphics{/home/fixture/private/figure.png}",
    }
    json_artifact = make_audit_artifact(
        ArtifactRole.VERIFICATION,
        json.dumps(record).encode("utf-8"),
        media_type="application/json",
    )
    log_artifact = make_audit_artifact(
        ArtifactRole.ERROR_LOG,
        (
            r"path=C:\Users\FixtureUser\private\main.tex, status=failed; "
            "Authorization: Bearer log-secret-value; "
            "OPENAI_API_KEY=api-secret-value, "
            "codex_login_email=user@example.test (account)"
        ).encode("utf-8"),
        media_type="text/plain; charset=utf-8",
    )
    result = build_audit_submission(
        _snapshot(artifacts=(json_artifact, log_artifact)),
    )

    cleaned_json = json.loads(result.files["audit/verification.json"])
    assert cleaned_json["source_path"] == "<LOCAL_PATH>"
    assert cleaned_json["nested"]["preview"] == "<LOCAL_PATH>"
    assert cleaned_json["nested"]["Authorization"] == "<REDACTED>"
    assert cleaned_json["nested"]["codex_login_email"] == "<REDACTED>"
    assert cleaned_json["tex"] == r"\includegraphics{<LOCAL_PATH>}"

    cleaned_log = result.files["audit/error.log"].decode("utf-8")
    assert "path=<LOCAL_PATH>, status=failed;" in cleaned_log
    assert "Authorization: Bearer <REDACTED>;" in cleaned_log
    assert "OPENAI_API_KEY=<REDACTED>," in cleaned_log
    assert "codex_login_email=<REDACTED> (account)" in cleaned_log
    whole_bundle = b"\n".join(result.files.values()).decode(
        "utf-8", errors="ignore"
    )
    for leaked in (
        r"C:\Users\FixtureUser",
        "/workspace/private",
        "/home/fixture",
        "json-secret-value",
        "log-secret-value",
        "api-secret-value",
        "user@example.test",
    ):
        assert leaked not in whole_bundle


def test_disabling_payload_secret_cleanup_still_never_leaks_paths_in_manifest():
    item = make_audit_artifact(
        ArtifactRole.EVIDENCE,
        b"OPENAI_API_KEY=kept-by-explicit-opt-out",
        filename="evidence.txt",
        metadata={"workspace": "/root/private/project"},
    )
    snapshot = RunSnapshot(
        project_id=r"C:\Users\FixtureUser\project",
        run_id="run-opt-out",
        workflow=AuditWorkflow.ANALYSIS_REVIEW_ONLY,
        terminal_status=TerminalStatus.UNVERIFIED,
        captured_at="2026-08-22T00:00:00Z",
        artifacts=(item,),
        machine_verification={"safe_to_export": False},
        blockers=("inspect /mnt/private/log",),
        model="model /opt/local/model",
    )
    result = build_audit_submission(
        snapshot,
        AuditSubmissionRequest(
            sanitize_sensitive=False,
            audit_focus="check /workspace/private/source.tex",
        ),
    )
    manifest_text = result.files[MANIFEST_PATH].decode("utf-8")
    assert "kept-by-explicit-opt-out" in result.files["evidence/evidence.txt"].decode()
    for leaked in (r"C:\Users\FixtureUser", "/root/private", "/mnt/private", "/opt/local", "/workspace/private"):
        assert leaked not in manifest_text
    assert result.manifest.privacy["payload_sensitive_data_sanitized"] is False


def test_default_privacy_excludes_credential_like_multifile_project_files():
    safe = make_audit_artifact(
        ArtifactRole.PROJECT_FILE,
        b"safe project content",
        filename="chapters/main.tex",
    )
    filenames = (
        ".env",
        ".ENV.production",
        "keys/server.PEM",
        "keys/client.Key",
        "keys/signing.P12",
        "keys/windows.PfX",
    )
    sensitive = tuple(
        make_audit_artifact(
            ArtifactRole.PROJECT_FILE,
            f"secret-{index}".encode(),
            filename=filename,
        )
        for index, filename in enumerate(filenames, start=1)
    )
    result = build_audit_submission(
        _snapshot(
            workflow=AuditWorkflow.MULTIFILE_PROJECT,
            artifacts=(safe, *sensitive),
        )
    )

    assert result.files["project/chapters/main.tex"] == b"safe project content"
    for index, item in enumerate(sensitive, start=1):
        assert item.path not in result.files
        assert f"secret-{index}".encode() not in result.zip_bytes
    payload_ids = {
        item.artifact_id
        for item in result.manifest.artifacts
    }
    assert payload_ids.isdisjoint(item.artifact_id for item in sensitive)
    privacy = json.loads(result.files[MANIFEST_PATH])["privacy"]
    assert privacy["sensitive_project_file_policy"] == (
        "exclude_credential_like_filenames"
    )
    assert privacy["skipped_sensitive_project_file_count"] == len(sensitive)
    skipped = privacy["skipped_sensitive_project_files"]
    assert {item["artifact_id"] for item in skipped} == {
        item.artifact_id for item in sensitive
    }
    assert {item["path"] for item in skipped} == {item.path for item in sensitive}
    assert all(item["artifact_role"] == ArtifactRole.PROJECT_FILE for item in skipped)
    assert all("credential-like" in item["reason"] for item in skipped)


def test_explicit_privacy_opt_out_includes_credential_like_project_file_bytes():
    credential = make_audit_artifact(
        ArtifactRole.PROJECT_FILE,
        b"private-key-bytes",
        filename="credentials/CLIENT.PeM",
    )
    result = build_audit_submission(
        _snapshot(
            workflow=AuditWorkflow.MULTIFILE_PROJECT,
            artifacts=(credential,),
        ),
        AuditSubmissionRequest(sanitize_sensitive=False),
    )

    assert result.files[credential.path] == b"private-key-bytes"
    privacy = json.loads(result.files[MANIFEST_PATH])["privacy"]
    assert privacy["sensitive_project_file_policy"] == (
        "disabled_by_explicit_opt_out"
    )
    assert privacy["skipped_sensitive_project_file_count"] == 0
    assert privacy["skipped_sensitive_project_files"] == []


def test_sensitive_project_file_cannot_survive_as_a_deduplicated_alias():
    safe = make_audit_artifact(
        ArtifactRole.PROJECT_FILE,
        b"same bytes",
        filename="main.tex",
    )
    credential = make_audit_artifact(
        ArtifactRole.PROJECT_FILE,
        b"same bytes",
        filename=".env",
    )
    result = build_audit_submission(
        _snapshot(
            workflow=AuditWorkflow.MULTIFILE_PROJECT,
            artifacts=(safe, credential),
        )
    )

    record = next(item for item in result.manifest.artifacts if item.path == safe.path)
    assert record.aliases == ()
    assert credential.path not in result.files
    assert result.manifest.privacy["skipped_sensitive_project_file_count"] == 1


def test_partial_compiled_pdf_keeps_truthful_status_and_filename():
    partial = _artifact(
        ArtifactRole.CURRENT_PREVIEW,
        b"%PDF-1.7\npartial",
        preview_status=PARTIAL_COMPILED,
    )
    result = build_audit_submission(_snapshot(artifacts=(partial,)))
    record = next(item for item in result.manifest.artifacts if item.preview_status)
    assert record.preview_status == PARTIAL_COMPILED
    assert record.path == "previews/current-partial-compiled.pdf"


def test_source_preview_gets_first_page_notice_and_noncompiled_filename():
    preview = _artifact(
        ArtifactRole.RAW_OCR_PREVIEW,
        b"plain degraded source preview",
        path="previews/misleading-compiled.pdf",
        preview_status=SOURCE_PREVIEW,
    )
    result = build_audit_submission(_snapshot(artifacts=(preview,)))
    record = next(item for item in result.manifest.artifacts if item.preview_status)
    assert record.path == "previews/raw-ocr-source-preview.txt"
    assert "compiled" not in record.path.casefold()
    assert record.media_type == "text/plain; charset=utf-8"
    assert result.files[record.path].startswith(
        b"SOURCE_PREVIEW: NOT A LATEX COMPILED RESULT."
    )


def test_source_preview_notice_later_in_text_does_not_satisfy_first_page_rule():
    preview = _artifact(
        ArtifactRole.CURRENT_PREVIEW,
        b"source body\nNOT A LATEX COMPILED RESULT\n",
        path="previews/current-source-preview.txt",
        preview_status=SOURCE_PREVIEW,
    )
    result = build_audit_submission(_snapshot(artifacts=(preview,)))
    assert result.files["previews/current-source-preview.txt"].startswith(
        b"SOURCE_PREVIEW: NOT A LATEX COMPILED RESULT."
    )


def test_pdf_notice_on_later_page_does_not_satisfy_first_page_rule():
    fitz = pytest.importorskip("fitz")
    document = fitz.open()
    document.new_page()
    second = document.new_page()
    second.insert_text((72, 72), "NOT A LATEX COMPILED RESULT")
    payload = document.tobytes()
    document.close()
    preview = _artifact(
        ArtifactRole.CURRENT_PREVIEW,
        payload,
        path="previews/current-source-preview.pdf",
        preview_status=SOURCE_PREVIEW,
    )
    result = build_audit_submission(_snapshot(artifacts=(preview,)))
    rendered = fitz.open(stream=result.files["previews/current-source-preview.pdf"], filetype="pdf")
    try:
        assert rendered.page_count == 3
        assert "NOT A LATEX COMPILED RESULT" in rendered[0].get_text().upper()
    finally:
        rendered.close()


def test_compiled_preview_preserves_compiled_status():
    preview = _artifact(
        ArtifactRole.CURRENT_PREVIEW,
        b"%PDF-1.7\ncompiled",
        preview_status=COMPILED,
    )
    record = next(
        item
        for item in build_audit_submission(_snapshot(artifacts=(preview,))).manifest.artifacts
        if item.preview_status
    )
    assert record.preview_status == COMPILED
    assert record.path == "previews/current.pdf"


def test_compiled_preview_status_rejects_non_pdf_payload():
    preview = _artifact(
        ArtifactRole.CURRENT_PREVIEW,
        b"source text only",
        preview_status=COMPILED,
    )
    with pytest.raises(ValueError, match="real PDF"):
        build_audit_submission(_snapshot(artifacts=(preview,)))


def test_depth_and_explicit_heavy_evidence_controls():
    page = make_audit_artifact(
        ArtifactRole.PAGE_IMAGE, b"png", index=2, filename="page.png"
    )
    snapshot = _snapshot(artifacts=(page,))
    standard = build_audit_submission(snapshot)
    full = build_audit_submission(snapshot, AuditSubmissionRequest(depth=AuditDepth.FULL))
    explicit = build_audit_submission(
        snapshot,
        AuditSubmissionRequest(depth=AuditDepth.STANDARD, include_page_images=True),
    )
    assert not any(path.startswith("evidence/page-images/") for path in standard.files)
    assert "evidence/page-images/page-0002.png" in full.files
    assert "evidence/page-images/page-0002.png" in explicit.files


def test_filtered_parent_is_explicitly_reported_instead_of_left_silently_dangling():
    source = _artifact(ArtifactRole.SOURCE_TEX, b"source")
    current = _artifact(
        ArtifactRole.CURRENT_TEX,
        b"current",
        parents=(source.artifact_id,),
    )
    result = build_audit_submission(
        _snapshot(artifacts=(source, current)),
        AuditSubmissionRequest(include_source_files=False),
    )
    assert result.manifest.unavailable_parent_artifact_ids == (source.artifact_id,)
    assert not any(
        item.get("status") == "INCONSISTENT"
        and source.artifact_id in str(item.get("reason") or "")
        for item in result.manifest.missing_expected_role_details
    )
    prompt = result.files[FULL_PROMPT_PATH].decode("utf-8")
    assert source.artifact_id in prompt
    assert "不得猜测" in prompt


def test_stale_fingerprint_covers_current_tex_pdf_decisions_and_verification():
    current = _artifact(ArtifactRole.CURRENT_TEX, b"tex")
    pdf = _artifact(ArtifactRole.CURRENT_PREVIEW, b"%PDF-1.7\npdf", preview_status=COMPILED)
    decisions = _artifact(ArtifactRole.DECISIONS, b"decisions")
    verification = _artifact(ArtifactRole.VERIFICATION, b"verification")
    snapshot = _snapshot(artifacts=(current, pdf, decisions, verification))
    result = build_audit_submission(snapshot)
    same = snapshot_fingerprint_from_hashes(
        current_tex_sha256=current.bytes_sha256,
        current_pdf_sha256=pdf.bytes_sha256,
        decisions_sha256=decisions.bytes_sha256,
        verification_sha256=verification.bytes_sha256,
    )
    assert same == snapshot.current_fingerprint
    assert not result.is_stale(same)
    changed = snapshot_fingerprint_from_hashes(current_tex_sha256="f" * 64)
    assert result.is_stale(changed)


def test_short_prompt_is_exactly_one_sentence_and_points_to_real_control_files():
    result = build_audit_submission(_snapshot())
    short = result.files[SHORT_PROMPT_PATH].decode().strip()
    assert short.count("。") == 1
    assert "\n" not in short
    for path in (README_PATH, MANIFEST_PATH, FULL_PROMPT_PATH):
        assert path in short
        assert path in result.files


def test_lightweight_controls_never_claim_omitted_payload_or_hash_manifest_exists():
    result = build_lightweight_audit_files(_snapshot())
    assert set(result.files) == {
        README_PATH,
        SHORT_PROMPT_PATH,
        FULL_PROMPT_PATH,
        MANIFEST_PATH,
    }
    assert {item.path for item in result.manifest.artifacts} == set(result.files)
    readme = result.files[README_PATH].decode("utf-8")
    prompt = result.files[FULL_PROMPT_PATH].decode("utf-8")
    assert SHA256SUMS_PATH not in readme
    assert SHA256SUMS_PATH not in prompt
    assert "inputs/source.tex" not in prompt
    assert "轻量控制" in readme
    assert "不得作内容审计结论" in prompt
    assert result.manifest.packaging_status is PackagingStatus.PARTIAL
    assert result.manifest.audit_package_status is AuditPackageStatus.INCOMPLETE
    assert "请优先审计" in result.files[SHORT_PROMPT_PATH].decode("utf-8")


def test_sha256sums_is_recomputable_and_excludes_itself():
    result = build_audit_submission(_snapshot())
    sums = {}
    for line in result.files[SHA256SUMS_PATH].decode("utf-8").splitlines():
        digest, path = line.split("  ", 1)
        sums[path] = digest
    assert SHA256SUMS_PATH not in sums
    assert set(sums) == set(result.files) - {SHA256SUMS_PATH}
    for path, digest in sums.items():
        assert hashlib.sha256(result.files[path]).hexdigest() == digest


def test_zip_write_is_atomic_and_has_no_temporary_residue(tmp_path):
    target = tmp_path / "中文审计包.zip"
    target.write_bytes(b"old")
    result = write_audit_submission_atomic(
        _snapshot(),
        target,
        submission_id="atomic-test",
        generated_at="2026-08-22T00:00:01Z",
    )
    assert target.read_bytes() == result.zip_bytes
    with zipfile.ZipFile(target) as archive:
        assert archive.testzip() is None
        assert MANIFEST_PATH in archive.namelist()
    assert list(tmp_path.glob("*.tmp")) == []
    assert list(tmp_path.glob(".*.tmp")) == []


def test_entire_zip_limit_is_500_mib_and_overflow_leaves_no_partial_file(
    tmp_path,
    monkeypatch,
):
    assert MAX_AUDIT_ZIP_BYTES == 500 * 1024 * 1024
    snapshot = _snapshot()
    baseline = build_audit_submission(
        snapshot,
        submission_id="zip-size-limit",
        generated_at="2026-08-22T00:00:01Z",
    )
    exact_size = len(baseline.zip_bytes)
    monkeypatch.setattr(
        audit_submission_module,
        "MAX_AUDIT_ZIP_BYTES",
        exact_size,
    )
    assert len(build_audit_submission(
        snapshot,
        submission_id="zip-size-limit",
        generated_at="2026-08-22T00:00:01Z",
    ).zip_bytes) == exact_size

    monkeypatch.setattr(
        audit_submission_module,
        "MAX_AUDIT_ZIP_BYTES",
        exact_size - 1,
    )
    target = tmp_path / "bounded-audit.zip"
    target.write_bytes(b"existing complete archive")
    with pytest.raises(ValueError, match="audit ZIP exceeds configured maximum"):
        write_audit_submission_atomic(
            snapshot,
            target,
            submission_id="zip-size-limit",
            generated_at="2026-08-22T00:00:01Z",
        )
    assert target.read_bytes() == b"existing complete archive"
    assert list(tmp_path.glob("*.tmp")) == []
    assert list(tmp_path.glob(".*.tmp")) == []


def test_canonical_paths_cover_ocr_analysis_review_tree():
    assert canonical_artifact_path(ArtifactRole.SOURCE_PDF) == "inputs/source.pdf"
    assert canonical_artifact_path(
        ArtifactRole.SOURCE_IMAGE, filename="ocr-source.jpeg"
    ) == "inputs/source-image.jpg"
    assert canonical_artifact_path(ArtifactRole.RAW_OCR_TEX) == "stages/00_raw_ocr.tex"
    assert canonical_artifact_path(ArtifactRole.AI_ANALYZED_TEX) == "stages/10_ai_analyzed.tex"
    assert canonical_artifact_path(
        ArtifactRole.RULE_ANALYZED_TEX
    ) == "stages/10_rule_analyzed.tex"
    assert canonical_artifact_path(ArtifactRole.AI_REVIEWED_TEX) == "stages/20_ai_reviewed.tex"
    assert canonical_artifact_path(ArtifactRole.CURRENT_TEX) == "stages/30_current.tex"


def test_ocr_source_image_is_authoritative_and_does_not_claim_missing_pdf():
    source = make_audit_artifact(
        ArtifactRole.SOURCE_IMAGE,
        b"\x89PNG\r\n\x1a\nimage",
        filename="ocr-source.png",
        media_type="image/png",
    )
    raw = make_audit_artifact(
        ArtifactRole.RAW_OCR_TEX,
        b"raw OCR",
        parent_artifact_ids=(source.artifact_id,),
    )
    result = build_audit_submission(
        _snapshot(
            workflow=AuditWorkflow.OCR_ONLY,
            artifacts=(source, raw),
        )
    )
    assert result.files["inputs/source-image.png"].startswith(b"\x89PNG")
    roles = {item.artifact_role for item in result.manifest.artifacts}
    assert ArtifactRole.SOURCE_IMAGE in roles
    assert ArtifactRole.SOURCE_PDF not in result.manifest.missing_expected_roles


def test_builder_preserves_unchanged_tex_bytes_and_records_valid_integrity():
    tex = (
        r"\documentclass{article}"
        "\n"
        r"\begin{document}$u\in V:\lvert N(u)\cap B\rvert$\end{document}"
        "\n"
    ).encode("utf-8")
    source = make_audit_artifact(
        ArtifactRole.SOURCE_TEX,
        tex,
        media_type="application/x-tex; charset=utf-8",
    )
    current = make_audit_artifact(
        ArtifactRole.CURRENT_TEX,
        tex,
        parent_artifact_ids=(source.artifact_id,),
        media_type="application/x-tex; charset=utf-8",
    )
    result = build_audit_submission(
        _snapshot(artifacts=(source, current)),
        AuditSubmissionRequest(depth=AuditDepth.QUICK),
    )

    # Byte de-duplication stores one physical payload, while both logical TeX
    # nodes still pass the post-sanitization conservation gate independently.
    assert result.files["inputs/source.tex"] == tex
    assert "stages/30_current.tex" not in result.files
    integrity = json.loads(result.files["audit/packaging-integrity.json"])
    assert integrity["packaging_status"] == "SUCCESS"
    assert integrity["audit_package_status"] == "VALID"
    assert integrity["tex_content_gate_valid"] is True
    assert integrity["checked_tex_artifact_count"] == 2
    assert all(item["valid"] is True for item in integrity["artifacts"])
    assert all(item["bytes_equal"] is True for item in integrity["artifacts"])
    assert all(item["sanitization_applied"] is False for item in integrity["artifacts"])


def test_integrity_failure_emits_only_minimal_fail_closed_bundle(monkeypatch):
    original_sanitizer = audit_submission_module._sanitize_bytes

    def corrupt_tex_after_sanitization(data, path, media_type, *, known_paths=()):
        cleaned = original_sanitizer(
            data,
            path,
            media_type,
            known_paths=known_paths,
        )
        if not cleaned.is_tex:
            return cleaned
        return type(cleaned)(
            data=b"unauthorized body replacement\n",
            changes=cleaned.changes,
            tex_spans=cleaned.tex_spans,
            is_tex=True,
        )

    monkeypatch.setattr(
        audit_submission_module,
        "_sanitize_bytes",
        corrupt_tex_after_sanitization,
    )
    result = build_audit_submission(
        _snapshot(),
        submission_id="fail-closed-integrity",
        generated_at="2026-08-22T00:00:01Z",
    )

    assert result.manifest.packaging_status is PackagingStatus.FAILED
    assert result.manifest.audit_package_status is AuditPackageStatus.INVALID
    assert SHORT_PROMPT_PATH not in result.files
    assert FULL_PROMPT_PATH not in result.files
    assert SHA256SUMS_PATH not in result.files
    assert "inputs/source.tex" not in result.files
    assert "stages/30_current.tex" not in result.files
    assert {
        README_PATH,
        MANIFEST_PATH,
        "audit/packaging-integrity.json",
        "audit/packaging-error.json",
        "audit/error.log",
    }.issubset(result.files)

    packaging_error = json.loads(result.files["audit/packaging-error.json"])
    assert packaging_error["normal_audit_package_suppressed"] is True
    assert packaging_error["packaging_status"] == "FAILED"
    assert packaging_error["audit_package_status"] == "INVALID"
    assert packaging_error["damaged_or_unverifiable_artifact_ids"]
    with zipfile.ZipFile(io.BytesIO(result.zip_bytes)) as archive:
        assert set(archive.namelist()) == set(result.files)
        assert archive.testzip() is None


def test_declared_partial_preview_without_pdf_bytes_is_partial_and_incomplete():
    source = make_audit_artifact(
        ArtifactRole.SOURCE_PDF,
        b"%PDF-1.7\nsource",
        media_type="application/pdf",
    )
    raw = make_audit_artifact(
        ArtifactRole.RAW_OCR_TEX,
        b"\\documentclass{article}\n",
        parent_artifact_ids=(source.artifact_id,),
        media_type="application/x-tex; charset=utf-8",
    )
    snapshot = _snapshot(
        workflow=AuditWorkflow.OCR_ONLY,
        artifacts=(source, raw),
        machine_verification={
            "safe_to_export": False,
            "raw_preview_state": PARTIAL_COMPILED,
        },
    )
    result = build_audit_submission(snapshot)

    assert result.manifest.packaging_status is PackagingStatus.PARTIAL
    assert result.manifest.audit_package_status is AuditPackageStatus.INCOMPLETE
    assert ArtifactRole.RAW_OCR_PREVIEW in result.manifest.missing_expected_roles
    assert any(
        detail["role"] == ArtifactRole.RAW_OCR_PREVIEW
        and detail.get("status") == PARTIAL_COMPILED
        and "PDF bytes are missing" in str(detail["reason"])
        for detail in result.manifest.missing_expected_role_details
    )
    prompt = result.files[FULL_PROMPT_PATH].decode("utf-8")
    assert "previews/raw_ocr_PARTIAL_COMPILED.pdf" not in prompt
    assert "本包没有声明为 PARTIAL_COMPILED 的物理 PDF" in prompt


def test_raw_ocr_partial_preview_keeps_real_two_page_pdf_name_and_metadata():
    fitz = pytest.importorskip("fitz")
    document = fitz.open()
    document.new_page()
    document.new_page()
    preview_bytes = document.tobytes()
    document.close()

    source = make_audit_artifact(
        ArtifactRole.SOURCE_PDF,
        b"%PDF-1.7\nsource",
        media_type="application/pdf",
    )
    raw = make_audit_artifact(
        ArtifactRole.RAW_OCR_TEX,
        b"\\documentclass{article}\n\\begin{document}OCR\\end{document}\n",
        parent_artifact_ids=(source.artifact_id,),
        media_type="application/x-tex; charset=utf-8",
    )
    preview = make_audit_artifact(
        ArtifactRole.RAW_OCR_PREVIEW,
        preview_bytes,
        preview_status=PARTIAL_COMPILED,
        parent_artifact_ids=(raw.artifact_id,),
        media_type="application/pdf",
        metadata={
            "compiled_page_count": 2,
            "compile_complete": False,
            "retained_from_failed_compile": True,
        },
    )
    supporting = (
        make_audit_artifact(ArtifactRole.REPORT, b"report\n"),
        make_audit_artifact(ArtifactRole.VERIFICATION, b"{}", media_type="application/json"),
        make_audit_artifact(ArtifactRole.DECISIONS, b"{}", media_type="application/json"),
        make_audit_artifact(ArtifactRole.COMPILE_RAW_LOG, b"partial compile\n"),
        make_audit_artifact(ArtifactRole.OUTLINE, b"{\"pages\":[1,2]}", media_type="application/json"),
        make_audit_artifact(ArtifactRole.REPORT_JSON, b"{}", media_type="application/json"),
        make_audit_artifact(ArtifactRole.ISSUES_CSV, b"severity,message\n"),
        make_audit_artifact(ArtifactRole.METRICS, b"{}", media_type="application/json"),
        make_audit_artifact(
            ArtifactRole.RAW_COMPILE_INPUT_MANIFEST,
            b"{\"complete\":false,\"reason\":\"partial output retained\"}",
            media_type="application/json",
        ),
    )
    result = build_audit_submission(
        _snapshot(
            workflow=AuditWorkflow.OCR_ONLY,
            artifacts=(source, raw, preview, *supporting),
            machine_verification={
                "safe_to_export": False,
                "raw_preview_state": PARTIAL_COMPILED,
            },
        )
    )

    record = next(
        item
        for item in result.manifest.artifacts
        if item.artifact_role == ArtifactRole.RAW_OCR_PREVIEW
    )
    expected_path = "previews/raw_ocr_PARTIAL_COMPILED.pdf"
    assert record.path == expected_path
    assert record.preview_status == PARTIAL_COMPILED
    assert record.metadata["compiled_page_count"] == 2
    assert record.metadata["compile_complete"] is False
    assert record.metadata["retained_from_failed_compile"] is True
    packaged = fitz.open(stream=result.files[expected_path], filetype="pdf")
    try:
        assert packaged.page_count == 2
    finally:
        packaged.close()
    prompt = result.files[FULL_PROMPT_PATH].decode("utf-8")
    assert expected_path in prompt
    assert "不能当作完整编译" in prompt


def test_review_skipped_is_not_inferred_from_current_tex_or_named_as_a_file():
    source = _artifact(ArtifactRole.SOURCE_TEX, b"source\n")
    current = _artifact(
        ArtifactRole.CURRENT_TEX,
        b"current\n",
        parents=(source.artifact_id,),
    )
    result = build_audit_submission(
        _snapshot(
            artifacts=(source, current),
            stages={
                "analysis": {
                    "status": StageExecutionStatus.COMPLETED,
                    "checked": True,
                },
                "review": {
                    "status": StageExecutionStatus.SKIPPED,
                    "checked": False,
                    "reason": "second-pass review disabled by host configuration",
                },
            },
        )
    )

    review = result.manifest.stages["review"]
    assert review.status is StageExecutionStatus.SKIPPED
    assert review.checked is False
    assert review.canonical_artifact_id is None
    assert review.deduplicated is False
    assert ArtifactRole.AI_REVIEWED_TEX in result.manifest.missing_expected_roles
    prompt = result.files[FULL_PROMPT_PATH].decode("utf-8")
    assert "stages/20_ai_reviewed.tex" not in prompt
    assert "本次没有可确认完成的独立 AI 审阅" in prompt
    assert "独立 AI 审阅已记录为完成" not in prompt


def test_completed_identical_review_is_a_logical_alias_not_a_skipped_stage():
    current = _artifact(ArtifactRole.CURRENT_TEX, b"identical reviewed text\n")
    reviewed = _artifact(
        ArtifactRole.AI_REVIEWED_TEX,
        b"identical reviewed text\n",
        parents=(current.artifact_id,),
    )
    result = build_audit_submission(
        _snapshot(
            artifacts=(current, reviewed),
            stages={
                "review": {
                    "status": StageExecutionStatus.COMPLETED,
                    "checked": True,
                    "reason": "review completed without textual changes",
                }
            },
        )
    )

    canonical = next(
        item
        for item in result.manifest.artifacts
        if item.artifact_role == ArtifactRole.CURRENT_TEX
    )
    alias = next(
        item
        for item in canonical.aliases
        if item["artifact_role"] == ArtifactRole.AI_REVIEWED_TEX
    )
    review = result.manifest.stages["review"]
    assert review.status is StageExecutionStatus.COMPLETED
    assert review.checked is True
    assert review.canonical_artifact_id == canonical.artifact_id
    assert review.deduplicated is True
    assert alias["logical_path"] == "stages/20_ai_reviewed.tex"
    assert alias["canonical_path"] == "stages/30_current.tex"
    assert "stages/20_ai_reviewed.tex" not in result.files
    prompt = result.files[FULL_PROMPT_PATH].decode("utf-8")
    assert "独立 AI 审阅已记录为完成" in prompt
    assert "logical_path=stages/20_ai_reviewed.tex" in prompt
    assert "canonical_path=stages/30_current.tex" in prompt


def test_sha256sums_recomputes_from_actual_zip_members():
    result = build_audit_submission(
        _snapshot(),
        submission_id="zip-member-sha-recheck",
        generated_at="2026-08-22T00:00:01Z",
    )
    with zipfile.ZipFile(io.BytesIO(result.zip_bytes)) as archive:
        assert archive.testzip() is None
        names = set(archive.namelist())
        assert names == set(result.files)
        lines = archive.read(SHA256SUMS_PATH).decode("utf-8").splitlines()
        sums = {
            path: digest
            for digest, path in (line.split("  ", 1) for line in lines)
        }
        assert set(sums) == names - {SHA256SUMS_PATH}
        for path, digest in sums.items():
            member_bytes = archive.read(path)
            assert member_bytes == result.files[path]
            assert hashlib.sha256(member_bytes).hexdigest() == digest


def test_legacy_audit_provenance_is_explicit_unknown_not_fabricated_labels():
    result = build_audit_submission(
        _snapshot(), AuditSubmissionRequest(depth=AuditDepth.QUICK)
    )
    provenance = result.manifest.to_dict()["provenance"]

    assert provenance["runtime"]["identity_status"] == "UNKNOWN"
    assert provenance["runtime"]["app_version"] is None
    assert provenance["runtime"]["git_commit"] is None
    assert provenance["runtime"]["build_id"] is None
    assert provenance["models"]["ocr"]["status"] == "UNKNOWN"
    assert provenance["models"]["decision"]["model"] is None
    assert provenance["models"]["review"]["model"] is None
    serialized = json.dumps(provenance, ensure_ascii=False)
    assert "gpt-test" not in serialized
    assert "1.2.6" not in serialized


def test_empty_outline_and_inconsistent_machine_reports_make_package_incomplete():
    source = make_audit_artifact(
        ArtifactRole.SOURCE_PDF,
        b"%PDF-1.7\nlegacy source placeholder",
        media_type="application/pdf",
    )
    raw = make_audit_artifact(
        ArtifactRole.RAW_OCR_TEX,
        b"\\documentclass{article}\n",
        parent_artifact_ids=(source.artifact_id,),
        media_type="application/x-tex; charset=utf-8",
    )
    artifacts = (
        source,
        raw,
        make_audit_artifact(
            ArtifactRole.OUTLINE,
            b'{"schema_version":"latexstruct-outline-evidence-v1","source_outline":[]}',
            media_type="application/json",
        ),
        make_audit_artifact(
            ArtifactRole.REPORT_JSON, b"{}", media_type="application/json"
        ),
        make_audit_artifact(
            ArtifactRole.METRICS, b"{}", media_type="application/json"
        ),
        make_audit_artifact(
            ArtifactRole.ISSUES_CSV, b"severity,message\n", media_type="text/csv"
        ),
    )
    result = build_audit_submission(
        _snapshot(workflow=AuditWorkflow.OCR_ONLY, artifacts=artifacts)
    )

    assert result.manifest.packaging_status is PackagingStatus.PARTIAL
    assert result.manifest.audit_package_status is AuditPackageStatus.INCOMPLETE
    assert {
        ArtifactRole.OUTLINE,
        ArtifactRole.REPORT_JSON,
        ArtifactRole.METRICS,
        ArtifactRole.ISSUES_CSV,
    }.issubset(result.manifest.missing_expected_roles)
    assert any(
        item["role"] == ArtifactRole.OUTLINE and item.get("status") == "INVALID"
        for item in result.manifest.missing_expected_role_details
    )
    prompt = result.files[FULL_PROMPT_PATH].decode("utf-8")
    assert "不能作为有效 outline 证据" in prompt


def test_report_issues_and_metrics_remain_machine_consistent_after_enrichment():
    stages = {
        "ocr": {"status": "NOT_REQUESTED"},
        "analysis": {"status": "SKIPPED", "reason": "not run in fixture"},
        "review": {"status": "SKIPPED", "reason": "not run in fixture"},
        "template": {"status": "NOT_REQUESTED"},
    }
    metrics = build_metrics(
        source_pdf=None,
        outline_evidence=None,
        verification={},
        current_tex="current\n",
    )
    report = build_report_json(
        source_run_status="SUCCESS",
        verification_status="VERIFIED",
        stages=stages,
        blockers=[],
        metrics=metrics,
    )
    source = _artifact(ArtifactRole.SOURCE_TEX, b"source\n")
    current = _artifact(
        ArtifactRole.CURRENT_TEX,
        b"current\n",
        parents=(source.artifact_id,),
    )
    artifacts = (
        source,
        current,
        make_audit_artifact(
            ArtifactRole.REPORT_JSON,
            (json.dumps(report, sort_keys=True) + "\n").encode(),
            media_type="application/json",
        ),
        make_audit_artifact(
            ArtifactRole.METRICS,
            (json.dumps(metrics, sort_keys=True) + "\n").encode(),
            media_type="application/json",
        ),
        make_audit_artifact(
            ArtifactRole.ISSUES_CSV,
            issues_csv_bytes([]),
            media_type="text/csv",
        ),
    )
    result = build_audit_submission(
        _snapshot(
            artifacts=artifacts,
            verified=True,
            stages=stages,
        )
    )
    final_metrics = json.loads(result.files["audit/metrics.json"])
    final_report = json.loads(result.files["audit/report.json"])

    assert final_report["metrics"] == final_metrics
    assert final_metrics["packaging_integrity"] == {
        "packaging_status": result.manifest.packaging_status.value,
        "audit_package_status": result.manifest.audit_package_status.value,
    }
    assert not any(
        item["role"] in {
            ArtifactRole.REPORT_JSON,
            ArtifactRole.METRICS,
            ArtifactRole.ISSUES_CSV,
        }
        and item.get("status") == "INVALID"
        for item in result.manifest.missing_expected_role_details
    )


def test_sharp_source_pdf_records_real_17_page_total_and_selected_range():
    fitz = pytest.importorskip("fitz")
    document = fitz.open()
    for page_number in range(1, 18):
        page = document.new_page()
        page.insert_text((72, 72), f"Sharp Bounds source page {page_number}")
    source_bytes = document.tobytes()
    document.close()
    source = make_audit_artifact(
        ArtifactRole.SOURCE_PDF, source_bytes, media_type="application/pdf"
    )
    raw = make_audit_artifact(
        ArtifactRole.RAW_OCR_TEX,
        b"\\documentclass{article}\n",
        parent_artifact_ids=(source.artifact_id,),
        media_type="application/x-tex",
    )
    snapshot = _snapshot(
        workflow=AuditWorkflow.OCR_ONLY,
        artifacts=(source, raw),
        source_pdf={
            "page_count": 17,
            "selected_page_range": {
                "start": 1,
                "end": 17,
                "pages": list(range(1, 18)),
            },
        },
    )
    result = build_audit_submission(snapshot)

    assert result.manifest.source_pdf.page_count == 17
    assert result.manifest.source_pdf.selected_page_range.pages == tuple(range(1, 18))
    assert not any(
        item["role"] == ArtifactRole.SOURCE_PDF
        and item.get("status") in {"INVALID", "INCONSISTENT"}
        for item in result.manifest.missing_expected_role_details
    )

    wrong_snapshot = _snapshot(
        workflow=AuditWorkflow.OCR_ONLY,
        artifacts=(source, raw),
        source_pdf={
            "page_count": 1,
            "selected_page_range": {"start": 1, "end": 1, "pages": [1]},
        },
    )
    wrong_result = build_audit_submission(wrong_snapshot)
    assert any(
        item["role"] == ArtifactRole.SOURCE_PDF
        and item.get("status") == "INCONSISTENT"
        for item in wrong_result.manifest.missing_expected_role_details
    )


def _compile_manifest_bytes(
    *,
    main: AuditArtifact,
    preview: AuditArtifact,
    main_bytes: bytes,
    packaged_path: str,
) -> bytes:
    source_row = {
        "path": "main.tex",
        "bytes": len(main_bytes),
        "sha256": hashlib.sha256(main_bytes).hexdigest(),
    }
    payload = {
        "schema": "latexstruct-compile-inputs-v1",
        "file_count": 1,
        "files": [source_row],
        "compile_scope": "current",
        "main_artifact_id": main.artifact_id,
        "main_artifact_path": packaged_path,
        "preview_artifact_sha256": preview.bytes_sha256,
        "packaged_files": [{
            "path": "main.tex",
            "packaged_path": packaged_path,
            "artifact_role": ArtifactRole.CURRENT_TEX,
            "artifact_id": main.artifact_id,
            "parent_artifact_ids": list(main.parent_artifact_ids),
            "bytes": len(main_bytes),
            "bytes_sha256": hashlib.sha256(main_bytes).hexdigest(),
            "required_for_compile": True,
        }],
        "complete": True,
        "completeness_reasons": [],
    }
    payload["manifest_sha256"] = compile_input_manifest_sha256(payload)
    payload["recorded_compile_input_sha256"] = payload["manifest_sha256"]
    return (json.dumps(payload, sort_keys=True) + "\n").encode()


def test_compile_manifest_recomputes_and_resolves_deduplicated_current_alias():
    tex = b"\\documentclass{article}\n"
    source = make_audit_artifact(
        ArtifactRole.SOURCE_TEX, tex, media_type="application/x-tex"
    )
    current = make_audit_artifact(
        ArtifactRole.CURRENT_TEX,
        tex,
        parent_artifact_ids=(source.artifact_id,),
        media_type="application/x-tex",
    )
    preview = make_audit_artifact(
        ArtifactRole.CURRENT_PREVIEW,
        b"%PDF-1.7\ncurrent preview",
        preview_status=COMPILED,
        parent_artifact_ids=(current.artifact_id,),
        media_type="application/pdf",
    )
    manifest = make_audit_artifact(
        ArtifactRole.COMPILE_INPUT_MANIFEST,
        _compile_manifest_bytes(
            main=current,
            preview=preview,
            main_bytes=tex,
            packaged_path="stages/30_current.tex",
        ),
        media_type="application/json",
    )
    result = build_audit_submission(
        _snapshot(artifacts=(source, current, preview, manifest))
    )

    assert "stages/30_current.tex" not in result.files
    assert not any(
        item["role"] == ArtifactRole.COMPILE_INPUT_MANIFEST
        and item.get("status") == "INVALID"
        for item in result.manifest.missing_expected_role_details
    )
    assert any(
        item["role"] == ArtifactRole.COMPILE_CURRENT_LOG
        and "expected physical run artifact" in item["reason"]
        for item in result.manifest.missing_expected_role_details
    )
    assert result.manifest.audit_package_status is AuditPackageStatus.INCOMPLETE


def test_compile_manifest_wrong_hash_or_pdf_binding_is_rejected():
    tex = b"\\documentclass{article}\n"
    current = make_audit_artifact(
        ArtifactRole.CURRENT_TEX, tex, media_type="application/x-tex"
    )
    preview = make_audit_artifact(
        ArtifactRole.CURRENT_PREVIEW,
        b"%PDF-1.7\ncurrent preview",
        preview_status=COMPILED,
        parent_artifact_ids=(current.artifact_id,),
        media_type="application/pdf",
    )
    payload = json.loads(
        _compile_manifest_bytes(
            main=current,
            preview=preview,
            main_bytes=tex,
            packaged_path="stages/30_current.tex",
        )
    )
    payload["manifest_sha256"] = "0" * 64
    payload["preview_artifact_sha256"] = "1" * 64
    manifest = make_audit_artifact(
        ArtifactRole.COMPILE_INPUT_MANIFEST,
        (json.dumps(payload) + "\n").encode(),
        media_type="application/json",
    )
    result = build_audit_submission(
        _snapshot(artifacts=(current, preview, manifest))
    )
    details = [
        item
        for item in result.manifest.missing_expected_role_details
        if item["role"] == ArtifactRole.COMPILE_INPUT_MANIFEST
        and item.get("status") == "INVALID"
    ]
    assert details
    assert "not recomputable" in details[0]["reason"]
    assert "does not bind the packaged PDF" in details[0]["reason"]


def test_compiled_preview_requires_persisted_compile_input_hash():
    tex = b"\\documentclass{article}\n"
    current = make_audit_artifact(
        ArtifactRole.CURRENT_TEX, tex, media_type="application/x-tex"
    )
    preview = make_audit_artifact(
        ArtifactRole.CURRENT_PREVIEW,
        b"%PDF-1.7\ncurrent preview",
        preview_status=COMPILED,
        parent_artifact_ids=(current.artifact_id,),
        media_type="application/pdf",
    )
    payload = json.loads(
        _compile_manifest_bytes(
            main=current,
            preview=preview,
            main_bytes=tex,
            packaged_path="stages/30_current.tex",
        )
    )
    payload.pop("recorded_compile_input_sha256")
    manifest = make_audit_artifact(
        ArtifactRole.COMPILE_INPUT_MANIFEST,
        (json.dumps(payload) + "\n").encode(),
        media_type="application/json",
    )

    result = build_audit_submission(
        _snapshot(artifacts=(current, preview, manifest))
    )

    assert result.manifest.audit_package_status is AuditPackageStatus.INCOMPLETE
    assert any(
        item["role"] == ArtifactRole.COMPILE_INPUT_MANIFEST
        and item.get("status") == "INVALID"
        and "recorded compile input hash is missing" in item["reason"]
        for item in result.manifest.missing_expected_role_details
    )


def test_compile_inventory_path_and_artifact_id_must_bind_same_logical_node():
    tex = b"\\documentclass{article}\n"
    source = make_audit_artifact(
        ArtifactRole.SOURCE_TEX, tex, media_type="application/x-tex"
    )
    current = make_audit_artifact(
        ArtifactRole.CURRENT_TEX,
        tex,
        parent_artifact_ids=(source.artifact_id,),
        media_type="application/x-tex",
    )
    preview = make_audit_artifact(
        ArtifactRole.CURRENT_PREVIEW,
        b"%PDF-1.7\ncurrent preview",
        preview_status=COMPILED,
        parent_artifact_ids=(current.artifact_id,),
        media_type="application/pdf",
    )
    payload = json.loads(
        _compile_manifest_bytes(
            main=current,
            preview=preview,
            main_bytes=tex,
            packaged_path="stages/30_current.tex",
        )
    )
    payload["packaged_files"][0]["artifact_id"] = source.artifact_id
    manifest = make_audit_artifact(
        ArtifactRole.COMPILE_INPUT_MANIFEST,
        (json.dumps(payload) + "\n").encode(),
        media_type="application/json",
    )

    result = build_audit_submission(
        _snapshot(artifacts=(source, current, preview, manifest))
    )

    assert any(
        item["role"] == ArtifactRole.COMPILE_INPUT_MANIFEST
        and item.get("status") == "INVALID"
        and "required compile input is missing" in item["reason"]
        for item in result.manifest.missing_expected_role_details
    )


@pytest.mark.parametrize(
    ("field", "tampered", "message"),
    [
        ("artifact_role", ArtifactRole.SOURCE_TEX, "artifact_role mismatch"),
        (
            "parent_artifact_ids",
            ["artifact:" + "e" * 64],
            "parent_artifact_ids mismatch",
        ),
    ],
)
def test_compile_inventory_rejects_tampered_role_or_parent(
    field,
    tampered,
    message,
):
    tex = b"\\documentclass{article}\n"
    current = make_audit_artifact(
        ArtifactRole.CURRENT_TEX, tex, media_type="application/x-tex"
    )
    preview = make_audit_artifact(
        ArtifactRole.CURRENT_PREVIEW,
        b"%PDF-1.7\ncurrent preview",
        preview_status=COMPILED,
        parent_artifact_ids=(current.artifact_id,),
        media_type="application/pdf",
    )
    payload = json.loads(
        _compile_manifest_bytes(
            main=current,
            preview=preview,
            main_bytes=tex,
            packaged_path="stages/30_current.tex",
        )
    )
    payload["packaged_files"][0][field] = tampered
    manifest = make_audit_artifact(
        ArtifactRole.COMPILE_INPUT_MANIFEST,
        (json.dumps(payload) + "\n").encode(),
        media_type="application/json",
    )

    result = build_audit_submission(
        _snapshot(artifacts=(current, preview, manifest))
    )

    assert any(
        item["role"] == ArtifactRole.COMPILE_INPUT_MANIFEST
        and item.get("status") == "INVALID"
        and message in item["reason"]
        for item in result.manifest.missing_expected_role_details
    )


def test_unexplained_dangling_parent_makes_package_incomplete():
    missing_parent_id = "artifact:" + "f" * 64
    current = make_audit_artifact(
        ArtifactRole.CURRENT_TEX,
        b"current\n",
        parent_artifact_ids=(missing_parent_id,),
        media_type="application/x-tex",
    )

    result = build_audit_submission(_snapshot(artifacts=(current,)))

    assert result.manifest.audit_package_status is AuditPackageStatus.INCOMPLETE
    assert any(
        item["role"] == ArtifactRole.CURRENT_TEX
        and item.get("status") == "INCONSISTENT"
        and missing_parent_id in item["reason"]
        for item in result.manifest.missing_expected_role_details
    )


def test_ocr_source_pdf_requires_structured_page_facts():
    fitz = pytest.importorskip("fitz")
    document = fitz.open()
    document.new_page()
    document.new_page()
    source_bytes = document.tobytes()
    document.close()
    source = make_audit_artifact(
        ArtifactRole.SOURCE_PDF, source_bytes, media_type="application/pdf"
    )
    raw = make_audit_artifact(
        ArtifactRole.RAW_OCR_TEX,
        b"\\documentclass{article}\n",
        parent_artifact_ids=(source.artifact_id,),
        media_type="application/x-tex",
    )

    result = build_audit_submission(
        _snapshot(
            workflow=AuditWorkflow.OCR_ONLY,
            artifacts=(source, raw),
            source_pdf=None,
        )
    )

    assert result.manifest.audit_package_status is AuditPackageStatus.INCOMPLETE
    assert any(
        item["role"] == ArtifactRole.SOURCE_PDF
        and item.get("status") == "INCONSISTENT"
        and "no structured source_pdf" in item["reason"]
        for item in result.manifest.missing_expected_role_details
    )


def test_metrics_compile_status_must_match_packaged_preview_without_top_level_hint():
    tex = b"\\documentclass{article}\n"
    current = make_audit_artifact(
        ArtifactRole.CURRENT_TEX, tex, media_type="application/x-tex"
    )
    preview = make_audit_artifact(
        ArtifactRole.CURRENT_PREVIEW,
        b"%PDF-1.7\ncurrent preview",
        preview_status=COMPILED,
        parent_artifact_ids=(current.artifact_id,),
        media_type="application/pdf",
    )
    compile_manifest = make_audit_artifact(
        ArtifactRole.COMPILE_INPUT_MANIFEST,
        _compile_manifest_bytes(
            main=current,
            preview=preview,
            main_bytes=tex,
            packaged_path="stages/30_current.tex",
        ),
        media_type="application/json",
    )
    metrics = build_metrics(
        source_pdf=None,
        outline_evidence=None,
        verification={},
        current_tex=tex.decode(),
    )
    metrics_artifact = make_audit_artifact(
        ArtifactRole.METRICS,
        (json.dumps(metrics, sort_keys=True) + "\n").encode(),
        media_type="application/json",
    )

    result = build_audit_submission(
        _snapshot(
            artifacts=(current, preview, compile_manifest, metrics_artifact),
            machine_verification={"safe_to_export": False},
        )
    )

    assert result.manifest.audit_package_status is AuditPackageStatus.INCOMPLETE
    assert any(
        item["role"] == ArtifactRole.METRICS
        and item.get("status") == "INVALID"
        and "contradicts packaged preview" in item["reason"]
        for item in result.manifest.missing_expected_role_details
    )


def test_elegantbook_template_manifest_requires_hash_bound_class_and_license():
    class_bytes = b"\\NeedsTeXFormat{LaTeX2e}\n"
    license_bytes = b"ElegantBook license\n"
    class_artifact = make_audit_artifact(
        ArtifactRole.PROJECT_FILE,
        class_bytes,
        path="project/class-style-assets/elegantbook.cls",
        media_type="application/x-tex",
    )
    license_artifact = make_audit_artifact(
        ArtifactRole.PROJECT_FILE,
        license_bytes,
        path="project/LICENSES/ELEGANTBOOK-LICENSE.txt",
        media_type="text/plain",
    )
    payload = template_manifest(
        template_id="elegantbook",
        template_version="4.5",
        assets=[{
            "path": "elegantbook.cls",
            "packaged_path": class_artifact.path,
            "artifact_id": class_artifact.artifact_id,
            "artifact_role": ArtifactRole.PROJECT_FILE,
            "bytes_sha256": class_artifact.bytes_sha256,
            "required_for_compile": True,
            "license_path": license_artifact.path,
            "source": "vendored compile closure",
        }],
    )
    manifest = make_audit_artifact(
        ArtifactRole.TEMPLATE_MANIFEST,
        (json.dumps(payload, sort_keys=True) + "\n").encode(),
        media_type="application/json",
    )
    result = build_audit_submission(
        _snapshot(
            artifacts=(class_artifact, license_artifact, manifest),
            stages={"template": {"status": "COMPLETED"}},
        )
    )
    assert not any(
        item["role"] == ArtifactRole.TEMPLATE_MANIFEST
        and item.get("status") == "INVALID"
        for item in result.manifest.missing_expected_role_details
    )

    without_license = build_audit_submission(
        _snapshot(
            artifacts=(class_artifact, manifest),
            stages={"template": {"status": "COMPLETED"}},
        )
    )
    assert any(
        item["role"] == ArtifactRole.TEMPLATE_MANIFEST
        and item.get("status") == "INVALID"
        and "no packaged license" in item["reason"]
        for item in without_license.manifest.missing_expected_role_details
    )

    tampered_cases = []
    wrong_role = json.loads(json.dumps(payload))
    wrong_role["assets"][0]["artifact_role"] = ArtifactRole.SOURCE_TEX
    wrong_role["assets"][0]["role"] = ArtifactRole.SOURCE_TEX
    tampered_cases.append((wrong_role, "template asset role mismatch"))
    wrong_parent = json.loads(json.dumps(payload))
    wrong_parent["assets"][0]["parent_artifact_ids"] = ["artifact:" + "d" * 64]
    tampered_cases.append((wrong_parent, "template asset parent_artifact_ids mismatch"))
    for tampered, expected_message in tampered_cases:
        tampered["asset_manifest_sha256"] = template_manifest_sha256(tampered)
        tampered_manifest = make_audit_artifact(
            ArtifactRole.TEMPLATE_MANIFEST,
            (json.dumps(tampered, sort_keys=True) + "\n").encode(),
            media_type="application/json",
        )
        tampered_result = build_audit_submission(
            _snapshot(
                artifacts=(class_artifact, license_artifact, tampered_manifest),
                stages={"template": {"status": "COMPLETED"}},
            )
        )
        assert any(
            item["role"] == ArtifactRole.TEMPLATE_MANIFEST
            and item.get("status") == "INVALID"
            and expected_message in item["reason"]
            for item in tampered_result.manifest.missing_expected_role_details
        )

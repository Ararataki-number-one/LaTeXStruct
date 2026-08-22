from __future__ import annotations

import hashlib
import io
import json
import re
import zipfile

import pytest

import latexstruct.core.audit_submission as audit_submission_module
from latexstruct.core.audit_schema import (
    ArtifactRole,
    AuditArtifact,
    AuditDepth,
    AuditSubmissionRequest,
    AuditWorkflow,
    RunSnapshot,
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
) -> AuditArtifact:
    return make_audit_artifact(
        role,
        data,
        path=path,
        preview_status=preview_status,
        parent_artifact_ids=parents,
        media_type="application/pdf" if role.endswith("PREVIEW") else "text/plain",
    )


def _snapshot(
    *,
    workflow: AuditWorkflow = AuditWorkflow.ANALYSIS_REVIEW_ONLY,
    terminal: TerminalStatus = TerminalStatus.SUCCESS,
    verified: bool = False,
    artifacts: tuple[AuditArtifact, ...] | None = None,
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
        machine_verification={"safe_to_export": verified},
        blockers=() if verified else ("机器验证尚未通过",),
        model="gpt-test",
        app_version="1.2.6",
        template="elegantbook",
        page_range="1-17",
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
    assert data_records[0].aliases[0]["path"] == "stages/00_source.tex"
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
    assert "stages/00_source.tex" not in prompt


def test_same_name_different_bytes_never_overwrites():
    one = _artifact(ArtifactRole.EVIDENCE, b"one", path="evidence/证据.txt")
    two = _artifact(ArtifactRole.EVIDENCE, b"two", path="evidence/证据.txt")
    result = build_audit_submission(_snapshot(artifacts=(one, two)))
    assert result.files["evidence/证据.txt"] == b"one"
    assert result.files["evidence/证据-2.txt"] == b"two"


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
    alias_paths = [item["path"] for item in record.aliases]
    assert "evidence/a-2.txt" not in alias_paths
    assert MANIFEST_PATH not in alias_paths
    assert len(alias_paths) == len(set(alias_paths))
    assert not set(alias_paths).intersection(result.files)
    assert any(item.get("requested_path") == "evidence/a-2.txt" for item in record.aliases)
    assert any(item.get("requested_path") == MANIFEST_PATH for item in record.aliases)


def test_chinese_paths_are_portable_and_absolute_paths_are_rejected():
    item = _artifact(ArtifactRole.EVIDENCE, "中文".encode(), path="evidence/中文/证据.txt")
    result = build_audit_submission(_snapshot(artifacts=(item,)))
    assert "evidence/中文/证据.txt" in result.files
    bad = _artifact(ArtifactRole.EVIDENCE, b"bad", path=r"C:\Users\ZQY\secret.txt")
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
        r"log=C:\Users\ZQY\private\main.tex" + "\n"
        "cache=/home/zqy/.codex/auth.json\n"
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
    assert b"C:\\Users\\ZQY" not in whole_bundle
    assert b"/home/zqy" not in whole_bundle
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
        "nested": {"path": r"C:\Users\ZQY\private\main.tex"},
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
        r"\includegraphics[width=.4\textwidth]{C:\Users\ZQY\secret\figure.png}",
        r"\includegraphics{/home/zqy/private/second-figure.png}",
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
    assert r"C:\Users\ZQY" not in cleaned
    assert "/home/zqy" not in cleaned
    assert "abcdefghijklmnopqrstuvwxyz" not in cleaned
    assert "codex-secret-value" not in cleaned


def test_privacy_cleanup_preserves_json_and_log_assignment_delimiters():
    record = {
        "source_path": r"C:\Users\ZQY\private\main.tex",
        "nested": {
            "preview": "/workspace/private/current.pdf",
            "Authorization": "Bearer json-secret-value",
            "codex_login_email": "user@example.test",
        },
        "tex": r"\includegraphics{/home/zqy/private/figure.png}",
    }
    json_artifact = make_audit_artifact(
        ArtifactRole.VERIFICATION,
        json.dumps(record).encode("utf-8"),
        media_type="application/json",
    )
    log_artifact = make_audit_artifact(
        ArtifactRole.ERROR_LOG,
        (
            r"path=C:\Users\ZQY\private\main.tex, status=failed; "
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
        r"C:\Users\ZQY",
        "/workspace/private",
        "/home/zqy",
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
        project_id=r"C:\Users\ZQY\project",
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
    for leaked in (r"C:\Users\ZQY", "/root/private", "/mnt/private", "/opt/local", "/workspace/private"):
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

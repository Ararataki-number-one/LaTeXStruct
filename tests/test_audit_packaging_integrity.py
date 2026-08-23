from __future__ import annotations

import hashlib
import json

import pytest

from latexstruct.core.audit_packaging_integrity import (
    AuditPackageStatus,
    AuditPackagingIntegrityGate,
    PackagingStatus,
    TexArtifactPackagingInput,
)
from latexstruct.core.audit_sanitize import (
    LOCAL_PATH_PLACEHOLDER,
    SECRET_PLACEHOLDER,
    sanitize_json_text,
    sanitize_log_text,
    sanitize_plain_text,
    sanitize_tex_text,
    sanitize_tex_text_with_spans,
)


def test_tex_sanitizer_preserves_math_colon_commands():
    samples = [
        r"u\in V:\lvert N(u)\cap B\rvert",
        r"x\in C:\mathcal{P}(X)",
        r"v\in D:\Delta(v)>0",
        r"x\in X:\exists y",
        # Preserve the double-backslash spelling from the external regression
        # requirement as well as ordinary single-backslash TeX.
        r"u\\in V:\\lvert N(u)\\cap B\\rvert",
    ]
    for sample in samples:
        assert sanitize_tex_text(sample, known_paths=[]) == sample


def test_tex_sanitizer_redacts_host_known_path_variants_without_guessing_prefixes():
    known = r"C:\Users\FixtureUser\Sharp Bounds"
    source = (
        r"Host record: c:/users/fixtureuser/sharp bounds/stages/main.tex; "
        r"math remains C:\mathcal and V:\lvert."
    )
    result = sanitize_tex_text_with_spans(source, known_paths=[known])

    assert result.text == (
        r"Host record: <LOCAL_PATH>/stages/main.tex; "
        r"math remains C:\mathcal and V:\lvert."
    )
    assert len(result.spans) == 1
    assert result.spans[0].category == "known_path"
    assert result.spans[0].reason == "host_known_path"
    assert known.casefold() not in result.text.casefold()
    assert "c:/users/fixtureuser/sharp bounds" not in json.dumps(result.spans[0].to_dict())

    # A known C:\math root does not authorize deleting the longer TeX command
    # name in C:\mathcal because the match must end at a path-token boundary.
    assert sanitize_tex_text(r"x\in C:\mathcal{P}", [r"C:\math"]) == r"x\in C:\mathcal{P}"


def test_tex_sanitizer_redacts_absolute_paths_only_in_explicit_path_arguments():
    source = "\n".join([
        r"x\in C:\mathcal{P}(X)",
        r"\includegraphics[width=.5\linewidth]{C:\private\figure one.png}",
        r"\bibliography{/Users/alice/private/a,D:/private/b}",
        r"\graphicspath{{C:/private/images/}{/home/alice/figures/}}",
    ])
    result = sanitize_tex_text_with_spans(source)

    assert r"x\in C:\mathcal{P}(X)" in result.text
    assert r"\includegraphics[width=.5\linewidth]{<LOCAL_PATH>}" in result.text
    assert r"\bibliography{<LOCAL_PATH>,<LOCAL_PATH>}" in result.text
    assert r"\graphicspath{{<LOCAL_PATH>}{<LOCAL_PATH>}}" in result.text
    assert {item.category for item in result.spans} == {"latex_path_argument"}

    remote = r"\addbibresource{https://example.org/library.bib}"
    assert sanitize_tex_text(remote) == remote


def test_tex_sanitizer_preserves_relative_paths_in_path_arguments():
    source = "\n".join([
        r"\graphicspath{{./images/}{../shared/figures/}}",
        r"\includegraphics{./images/chart.pdf}",
        r"\input{../chapters/introduction.tex}",
    ])

    result = sanitize_tex_text_with_spans(source)

    assert result.text == source
    assert result.spans == ()


@pytest.mark.parametrize(
    "source,secret",
    [
        ("API_KEY=sk-abcdefghijklmnop", "sk-abcdefghijklmnop"),
        ("Authorization: Bearer abcdefghijklmnopqrstuvwxyz", "abcdefghijklmnopqrstuvwxyz"),
        ("Authorization: Basic abcdefghijklmnopqrstuvwxyz", "abcdefghijklmnopqrstuvwxyz"),
        ("Bearer abcdefghijklmnopqrstuvwxyz", "abcdefghijklmnopqrstuvwxyz"),
        ("OPENAI_ACCESS_TOKEN=abcdefghijklmnopqrstuvwxyz", "abcdefghijklmnopqrstuvwxyz"),
        ("CODEX_SESSION=abcdefghijklmnopqrstuvwxyz", "abcdefghijklmnopqrstuvwxyz"),
    ],
)
def test_tex_sanitizer_redacts_credentials(source, secret):
    result = sanitize_tex_text_with_spans(source)
    assert secret not in result.text
    assert SECRET_PLACEHOLDER in result.text
    assert result.spans
    assert all(item.category == "credential" for item in result.spans)


def test_log_json_and_plain_sanitizers_allow_broad_path_cleanup_but_keep_valid_json():
    log = r"failed in C:\Users\alice\project\main.tex with API_KEY=sk-abcdefghijklmnop"
    assert "C:\\Users" not in sanitize_log_text(log)
    assert "sk-abcdefghijklmnop" not in sanitize_plain_text(log)

    payload = json.dumps({
        "compile_workdir": r"C:\Users\alice\project",
        "authorization": "Bearer abcdefghijklmnopqrstuvwxyz",
        "codex_account_email": "alice@example.test",
        "nested": [r"/home/alice/cache/run.log"],
    })
    cleaned = json.loads(sanitize_json_text(payload))
    assert cleaned["authorization"] == SECRET_PLACEHOLDER
    assert cleaned["codex_account_email"] == SECRET_PLACEHOLDER
    assert cleaned["compile_workdir"] == LOCAL_PATH_PLACEHOLDER
    assert cleaned["nested"] == [LOCAL_PATH_PLACEHOLDER]


def test_gate_requires_byte_identity_when_no_legal_sanitization_occurs():
    source = (
        r"\begin{document}"
        "\n"
        r"u\in V:\lvert N(u)\cap B\rvert and $x+y=z$."
        "\n"
        r"\end{document}"
    ).encode()
    gate = AuditPackagingIntegrityGate()
    artifact = gate.check_tex_artifact(
        source,
        source,
        artifact_id="current-tex",
        artifact_role="CURRENT_TEX",
        path="stages/30_current.tex",
    )

    digest = hashlib.sha256(source).hexdigest()
    assert artifact.source_bytes_sha256 == digest
    assert artifact.packaged_bytes_sha256 == digest
    assert artifact.bytes_equal is True
    assert artifact.sanitization_applied is False
    assert artifact.valid is True
    assert gate.finalize().packaging_status == PackagingStatus.SUCCESS
    assert gate.finalize().audit_package_status == AuditPackageStatus.VALID


def test_gate_accepts_only_recomputed_known_path_spans_and_never_reports_raw_path():
    known = r"C:\Users\FixtureUser\Sharp Bounds"
    source = (
        r"\documentclass{article}"
        "\n"
        r"\begin{document}Compiled under C:\Users\FixtureUser\Sharp Bounds\tmp.\end{document}"
    )
    sanitized = sanitize_tex_text_with_spans(source, [known])
    gate = AuditPackagingIntegrityGate()
    artifact = gate.check_tex_artifact(
        source,
        sanitized.text,
        artifact_id="source-tex",
        path="inputs/source.tex",
        authorized_spans=sanitized.spans,
        known_paths=[known],
    )

    assert artifact.valid is True
    assert artifact.bytes_equal is False
    assert artifact.sanitization_applied is True
    report = json.dumps(gate.machine_result(), ensure_ascii=False)
    assert known not in report
    assert sanitized.spans[0].original_sha256 in report


def test_gate_accepts_recomputed_credential_span_without_known_paths():
    source = r"\begin{document}API_KEY=sk-abcdefghijklmnop\end{document}"
    sanitized = sanitize_tex_text_with_spans(source)
    result = AuditPackagingIntegrityGate().check_tex_artifact(
        source,
        sanitized.text,
        authorized_spans=sanitized.spans,
    )
    assert result.valid is True
    assert result.check("body_text_ordered_conservation").passed is True
    assert result.check("latex_command_token_conservation").passed is True


def test_gate_support_files_require_environment_conservation_not_document_balance():
    # Class/style files routinely place begin/end tokens in separate macro
    # definitions; treating the source file itself as a document is a false
    # positive. Unchanged bytes and token conservation remain mandatory.
    source = r"\def\startbox{\begin{tcolorbox}}"
    artifact = AuditPackagingIntegrityGate().check_tex_artifact(
        source,
        source,
        artifact_role="PROJECT_FILE",
        path="project/class-style-assets/example.cls",
    )

    assert artifact.valid is True
    assert artifact.check("environment_balance").passed is True
    assert artifact.check("environment_token_conservation").passed is True


def test_unapproved_tex_change_fails_closed():
    source = r"\begin{document}Every widget works.\end{document}"
    packaged = source.replace("works", "fails")
    gate = AuditPackagingIntegrityGate()
    artifact = gate.check_tex_artifact(source, packaged, path="stages/30_current.tex")
    result = gate.finalize()

    assert artifact.valid is False
    assert "unauthorized_tex_change" in artifact.failure_codes
    assert artifact.check("body_text_ordered_conservation").passed is False
    assert result.packaging_status == PackagingStatus.FAILED
    assert result.audit_package_status == AuditPackageStatus.INVALID
    assert result.valid is False


def test_math_token_change_fails_closed():
    source = r"\begin{document}The value is $x+y=z$.\end{document}"
    packaged = source.replace("x+y", "x-y")
    artifact = AuditPackagingIntegrityGate().check_tex_artifact(source, packaged)

    assert artifact.valid is False
    assert artifact.check("math_token_conservation").passed is False
    assert "math_token_conservation_failed" in artifact.failure_codes


def test_body_text_order_change_fails_closed():
    source = r"\begin{document}First statement. Second statement.\end{document}"
    packaged = r"\begin{document}Second statement. First statement.\end{document}"
    artifact = AuditPackagingIntegrityGate().check_tex_artifact(source, packaged)

    assert artifact.valid is False
    assert artifact.check("body_text_ordered_conservation").passed is False
    assert "body_text_ordered_conservation_failed" in artifact.failure_codes


@pytest.mark.parametrize(
    "source,packaged,check_name,failure_code",
    [
        (
            r"\begin{document}\label{a}\end{document}",
            r"\begin{document}\label{b}\end{document}",
            "label_conservation",
            "label_conservation_failed",
        ),
        (
            r"\begin{document}\ref{a}\end{document}",
            r"\begin{document}\ref{b}\end{document}",
            "ref_conservation",
            "ref_conservation_failed",
        ),
        (
            r"\begin{document}\cite{a}\end{document}",
            r"\begin{document}\cite{b}\end{document}",
            "cite_conservation",
            "cite_conservation_failed",
        ),
        (
            r"\begin{theorem}Text.\end{theorem}",
            r"\begin{theorem}Text.\end{lemma}",
            "environment_balance",
            "environment_balance_failed",
        ),
        (
            r"\textbf{Text}",
            r"\textbf{Text",
            "brace_balance",
            "brace_balance_failed",
        ),
        (
            r"\emph{Text}",
            r"\textbf{Text}",
            "latex_command_token_conservation",
            "latex_command_token_conservation_failed",
        ),
    ],
)
def test_gate_checks_structural_conservation_dimensions(
    source,
    packaged,
    check_name,
    failure_code,
):
    artifact = AuditPackagingIntegrityGate().check_tex_artifact(source, packaged)
    assert artifact.check(check_name).passed is False
    assert failure_code in artifact.failure_codes
    assert artifact.valid is False


def test_forged_authorized_span_is_rejected():
    source = r"\begin{document}Every theorem remains.\end{document}"
    start = source.index("Every theorem")
    end = start + len("Every theorem")
    packaged = source[:start] + SECRET_PLACEHOLDER + source[end:]
    forged = {
        "source_start": start,
        "source_end": end,
        "replacement": SECRET_PLACEHOLDER,
        "category": "credential",
        "reason": "named_credential",
    }
    artifact = AuditPackagingIntegrityGate().check_tex_artifact(
        source,
        packaged,
        authorized_spans=[forged],
    )
    assert "authorized_span_not_evidence_backed" in artifact.failure_codes
    assert artifact.valid is False


def test_gate_batch_evaluate_returns_machine_readable_statuses():
    good = r"\begin{document}Good.\end{document}"
    bad = good.replace("Good", "Changed")
    result = AuditPackagingIntegrityGate().evaluate([
        TexArtifactPackagingInput(good, good, artifact_id="good", path="good.tex"),
        TexArtifactPackagingInput(good, bad, artifact_id="bad", path="bad.tex"),
    ])
    payload = result.to_dict()
    assert payload["schema_version"] == "latexstruct-audit-packaging-integrity-v1"
    assert payload["packaging_status"] == "FAILED"
    assert payload["audit_package_status"] == "INVALID"
    assert payload["checked_tex_artifact_count"] == 2
    assert payload["failed_tex_artifact_count"] == 1

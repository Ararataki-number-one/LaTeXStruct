from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import zipfile
from io import BytesIO
from pathlib import Path

import pytest


TOOL = Path(__file__).resolve().parents[1] / "tools" / "v2_analysis_acceptance.py"
SPEC = importlib.util.spec_from_file_location("v2_analysis_acceptance", TOOL)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

TEST_COMMIT = "c" * 40
TEST_BUILD_ID = "200"
PROJECT_ID = "d" * 32
RUN_ID = "e" * 12


def _config(tmp_path: Path) -> MODULE.AnalysisAcceptanceConfig:
    source = tmp_path / "source.pdf"
    source.write_bytes(b"%PDF-1.7\nsource\n")
    executable = tmp_path / "LaTeXStruct.exe"
    executable.write_bytes(b"candidate executable")
    return MODULE.AnalysisAcceptanceConfig(
        base_url="http://127.0.0.1:8080",
        source=source,
        profile="analysis-17",
        output_dir=tmp_path / "evidence",
        expected_version="2.0.0",
        expected_commit=TEST_COMMIT,
        expected_build_id=TEST_BUILD_ID,
        executable=executable,
        expected_executable_sha256=MODULE._sha256_file(executable),
    )


def _artifact(role: str, path: str, body: bytes, **extra):
    return {
        "artifact_role": role,
        "path": path,
        "bytes_sha256": MODULE._sha256_bytes(body),
        "source_bytes_sha256": MODULE._sha256_bytes(body),
        "byte_count": len(body),
        **extra,
    }


def _verified_bundle(config: MODULE.AnalysisAcceptanceConfig):
    page_ids = [f"page-{page:04d}" for page in range(1, 18)]
    source = config.source.read_bytes()
    current_tex = b"\\documentclass{article}\n\\begin{document}x\\end{document}\n"
    current_pdf = b"%PDF-1.7\ncompiled\n"
    compile_log = b"pass 1 ok\npass 2 ok\n"
    source_sha = MODULE._sha256_bytes(source)
    tex_sha = MODULE._sha256_bytes(current_tex)
    pdf_sha = MODULE._sha256_bytes(current_pdf)
    reviews = [
        {
            "pass_number": pass_number,
            "context_id": f"independent-context-{pass_number}",
            "candidate_hash": tex_sha,
            "checked_page_ids": page_ids,
            "compile_passes": 2,
            "content_conservation_ok": True,
            "math_conservation_ok": True,
            "formal_inventory_ok": True,
            "visual_review_ok": True,
            "new_high_risk_issues": 0,
            "prior_pass_conclusion_visible": False,
        }
        for pass_number in (1, 2)
    ]
    transport = [
        {"role": "AI-1", "operation": "structure"},
        {"role": "AI-2", "operation": "analysis"},
        {"role": "AI-3", "operation": "visual-review"},
    ]
    for pass_number in (1, 2):
        transport.extend(
            {
                "role": "AI-5",
                "operation": f"final-review-{pass_number}",
                "page_id": page_id,
            }
            for page_id in page_ids
        )
    machine_evidence = {
        "final_reviews": reviews,
        "raw_ocr_frozen": True,
        "candidate_hash": tex_sha,
        "current_candidate_hash": tex_sha,
        "expected_page_ids": page_ids,
        "checked_page_ids": page_ids,
        "best_compile_passes": 2,
        "best_pdf_openable": True,
        "silent_page_omissions": 0,
        "silent_text_losses": 0,
        "unauthorized_math_changes": 0,
        "formal_errors": 0,
        "open_critical": 0,
        "open_high": 0,
        "regressions": 0,
        "severe_equation_number_errors": 0,
        "silent_footnote_losses": 0,
        "silent_figure_caption_losses": 0,
        "silent_bibliography_losses": 0,
    }
    verification = {
        "terminal_status": "SUCCESS",
        "verification": {
            "safe_to_export": True,
            "compile_after": {
                "available": True,
                "ok": True,
                "preview_status": "COMPILED",
                "exit_code": 0,
                "timed_out": False,
                "passes_completed": 2,
                "pdf_sha256": pdf_sha,
                "log": compile_log.decode("utf-8"),
            },
            "analysis_v2": {
                "required": True,
                "executed": True,
                "ok": True,
                "verified": True,
                "status": "VERIFIED",
                "result_tex_sha256": tex_sha,
                "result_pdf_sha256": pdf_sha,
                "decision": {"verified": True, "status": "VERIFIED", "failures": []},
                "snapshot": {
                    "source_pdf_hash": source_sha,
                    "page_range": list(range(1, 18)),
                    "page_count": 17,
                    "models": [
                        {"role": "AI-1", "model_id": "structure-model"},
                        {"role": "AI-2", "model_id": "analysis-model"},
                        {"role": "AI-3", "model_id": "visual-model"},
                        {"role": "AI-5", "model_id": "final-review-model"},
                    ],
                },
                "transport_invocations": transport,
                "compile_invocations": [
                    {
                        "candidate_hash": tex_sha,
                        "run_number": run_number,
                        "ok": True,
                        "pdf_hash": pdf_sha,
                    }
                    for run_number in (1, 2)
                ],
                "final_reviews": reviews,
                "verification_evidence": machine_evidence,
            },
        },
    }
    verification_bytes = (json.dumps(verification) + "\n").encode()
    members = {
        "inputs/source.pdf": source,
        "stages/30_current.tex": current_tex,
        "previews/current.pdf": current_pdf,
        "audit/compile_current.log": compile_log,
        "audit/verification.json": verification_bytes,
    }
    manifest = {
        "workflow": "OCR_ANALYSIS_REVIEW",
        "source_run_status": "SUCCESS",
        "terminal_status": "SUCCESS",
        "verification_status": "VERIFIED",
        "packaging_status": "SUCCESS",
        "audit_package_status": "VALID",
        "project_id": PROJECT_ID,
        "run_id": RUN_ID,
        "app_version": "2.0.0",
        "blockers": [],
        "missing_expected_roles": [],
        "provenance": {
            "runtime": {
                "identity_status": "RECORDED",
                "app_version": "2.0.0",
                "git_commit": TEST_COMMIT,
                "build_id": TEST_BUILD_ID,
            }
        },
        "source_pdf": {
            "page_count": 17,
            "selected_page_range": {
                "start": 1,
                "end": 17,
                "pages": list(range(1, 18)),
            },
        },
        "artifacts": [
            _artifact("SOURCE_PDF", "inputs/source.pdf", source),
            _artifact("CURRENT_TEX", "stages/30_current.tex", current_tex),
            _artifact(
                "CURRENT_PREVIEW",
                "previews/current.pdf",
                current_pdf,
                preview_status="COMPILED",
            ),
            _artifact(
                "COMPILE_CURRENT_LOG", "audit/compile_current.log", compile_log
            ),
            _artifact(
                "VERIFICATION", "audit/verification.json", verification_bytes
            ),
        ],
    }
    return members, manifest


def _audit_zip(*, corrupt_digest: bool = False) -> bytes:
    source = b"%PDF-1.7\nsource\n"
    manifest = {
        "artifacts": [
            {
                "artifact_role": "SOURCE_PDF",
                "path": "inputs/source.pdf",
                "bytes_sha256": MODULE._sha256_bytes(source),
                "byte_count": len(source),
            }
        ]
    }
    members = {
        "submission_manifest.json": MODULE._json_bytes(manifest),
        "audit/packaging-integrity.json": MODULE._json_bytes(
            {
                "valid": True,
                "packaging_status": "SUCCESS",
                "audit_package_status": "VALID",
            }
        ),
        "inputs/source.pdf": source,
    }
    sums = []
    for name, body in members.items():
        digest = MODULE._sha256_bytes(body)
        if corrupt_digest and name == "inputs/source.pdf":
            digest = "0" * 64
        sums.append(f"{digest}  {name}")
    members["audit/SHA256SUMS"] = ("\n".join(sums) + "\n").encode()
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, body in members.items():
            archive.writestr(name, body)
    return buffer.getvalue()


def test_direct_cli_help_can_import_workspace_package():
    result = subprocess.run(
        [sys.executable, str(TOOL), "--help"],
        cwd=TOOL.parents[1],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert "analysis-17" in result.stdout
    assert "--exe-sha256" in result.stdout


def test_local_http_api_post_json_uses_real_post_body(monkeypatch):
    captured = {}

    # Return the concrete transport value expected by ``post_json`` while
    # retaining the outgoing request for assertions.
    def request_json(_self, path, **kwargs):
        captured.update(path=path, **kwargs)
        http_module = sys.modules[MODULE.LocalHttpApi.__module__]
        return http_module.HttpDownload(b'{"ok":true}', {}, 201)

    monkeypatch.setattr(MODULE.LocalHttpApi, "_request", request_json)
    api = MODULE.LocalHttpApi("http://127.0.0.1:8080")

    value = api.post_json("/api/example", {"标题": "测试"})

    assert value == {"ok": True}
    assert captured["path"] == "/api/example"
    assert captured["method"] == "POST"
    assert json.loads(captured["body"].decode("utf-8")) == {"标题": "测试"}
    assert captured["headers"]["Content-Type"].startswith("application/json")


def test_audit_zip_requires_recomputable_sha256sums():
    members, manifest = MODULE._read_audit_zip(_audit_zip())

    assert manifest["artifacts"][0]["artifact_role"] == "SOURCE_PDF"
    assert members["inputs/source.pdf"].startswith(b"%PDF-")
    with pytest.raises(MODULE.AcceptanceError, match="digest mismatch"):
        MODULE._read_audit_zip(_audit_zip(corrupt_digest=True))


def test_verified_bundle_can_publish_schema_compatible_attestation(tmp_path: Path):
    config = _config(tmp_path)
    config.output_dir.mkdir()
    members, manifest = _verified_bundle(config)
    facts = MODULE._verified_bundle_facts(
        config=config,
        members=members,
        manifest=manifest,
        source_pages=17,
        source_sha256=MODULE._sha256_file(config.source),
        backend="api",
        expected_project_id=PROJECT_ID,
        expected_run_id=RUN_ID,
    )
    evidence = MODULE.AnalysisRunEvidence(
        measurement_started_at="2026-08-24T00:00:00Z",
        ended_at="2026-08-24T00:02:00Z",
        wall_time_seconds=120.0,
        completed_terminal_run=True,
        real_execution=True,
    )

    validation = MODULE._publish_pass(config, evidence, facts)
    verified = MODULE.RELEASE_INTEGRITY.verify_analysis_attestation(
        config.output_dir,
        expected_pages=17,
        version="2.0.0",
        commit=TEST_COMMIT,
    )

    assert validation["terminal_status"] == "VERIFIED"
    assert verified["result"] == "PASS"
    assert verified["profile"] == "analysis-17"
    assert len(verified["independent_final_reviews"]) == 2
    expected_artifacts = {
        "candidate_tex": members["stages/30_current.tex"],
        "candidate_pdf": members["previews/current.pdf"],
        "compile_log": members["audit/compile_current.log"],
    }
    for role, payload in expected_artifacts.items():
        record = verified["artifacts"][role]
        path = config.output_dir / record["filename"]
        assert path.read_bytes() == payload
        assert record["bytes"] == len(payload)
        assert record["sha256"] == MODULE._sha256_bytes(payload)


def test_verified_bundle_rejects_current_tex_that_is_not_the_packaged_candidate(
    tmp_path: Path,
):
    config = _config(tmp_path)
    members, manifest = _verified_bundle(config)
    current = next(
        item for item in manifest["artifacts"]
        if item["artifact_role"] == "CURRENT_TEX"
    )
    current["source_bytes_sha256"] = "f" * 64

    with pytest.raises(
        MODULE.AcceptanceError,
        match="CURRENT_TEX bytes differ from the compiled candidate",
    ):
        MODULE._verified_bundle_facts(
            config=config,
            members=members,
            manifest=manifest,
            source_pages=17,
            source_sha256=MODULE._sha256_file(config.source),
            backend="api",
            expected_project_id=PROJECT_ID,
            expected_run_id=RUN_ID,
        )


def test_test_doubles_only_emit_fail_diagnostics(tmp_path: Path):
    class FakeApi:
        pass

    class FakeUi:
        pass

    config = _config(tmp_path)
    result = MODULE.run_analysis_acceptance(
        config,
        api=FakeApi(),
        ui_driver=FakeUi(),
        pdf_page_counter=lambda _path: 17,
    )
    attestation = json.loads(
        (config.output_dir / "analysis-attestation.json").read_text(encoding="utf-8")
    )

    assert result["acceptance_passed"] is False
    assert result["terminal_status"] == "UNVERIFIED"
    assert attestation["result"] == "FAIL"
    assert attestation["execution"]["real_execution"] is False
    assert not (config.output_dir / MODULE.AUDIT_ZIP_FILENAME).exists()
    with pytest.raises(MODULE.RELEASE_INTEGRITY.ReleaseIntegrityError):
        MODULE.RELEASE_INTEGRITY.verify_analysis_attestation(
            config.output_dir,
            expected_pages=17,
            version="2.0.0",
            commit=TEST_COMMIT,
        )


def test_unverified_audit_manifest_is_never_promoted(tmp_path: Path):
    config = _config(tmp_path)
    members, manifest = _verified_bundle(config)
    manifest["verification_status"] = "UNVERIFIED"

    with pytest.raises(MODULE.AcceptanceError, match="not VERIFIED"):
        MODULE._verified_bundle_facts(
            config=config,
            members=members,
            manifest=manifest,
            source_pages=17,
            source_sha256=MODULE._sha256_file(config.source),
            backend="api",
            expected_project_id=PROJECT_ID,
            expected_run_id=RUN_ID,
        )

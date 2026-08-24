from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import zipfile
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "packaging" / "release_integrity.py"
SPEC = importlib.util.spec_from_file_location("release_integrity", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

VERSION = "2.0.0"
COMMIT = "d" * 40


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _valid_run(
    root: Path,
    pages: int,
    *,
    real_execution: bool = True,
    executable_sha256: str = "e" * 64,
    source_sha256: str = "a" * 64,
    build_id: str = "200",
) -> Path:
    run_dir = root / f"run-{pages}"
    runtime = {
        "version": VERSION,
        "commit": COMMIT,
        "build_id": build_id,
        "executable_filename": "LaTeXStruct.exe",
        "executable_sha256": executable_sha256,
    }
    model = {"id": "qwen-vl-real", "backend": "dashscope", "calls": pages}
    source = {
        "filename": "release-source.pdf",
        "sha256": source_sha256,
        "total_pages": 600,
    }
    selected = {"start_page": 1, "end_page": pages, "expected_pages": pages}
    page_evidence = {
        "successful": pages,
        "needs_review": 0,
        "failed": 0,
        "pending": 0,
        "failed_page_numbers": [],
        "needs_review_page_numbers": [],
    }
    performance = {
        "schema_version": "latexstruct-v2-ocr-acceptance/2",
        "result": "PASS",
        "acceptance_passed": True,
        "runtime_identity": runtime,
        "model": model,
        "source": source,
        "selected_range": selected,
        "pages": page_evidence,
        "wall_time_seconds": 1800 if pages == 600 else 60,
        "successful_pages_per_minute": 20 if pages == 600 else 17,
        "thresholds": {
            "minimum_successful_pages_per_minute": 20 if pages == 600 else None,
            "maximum_wall_time_seconds": 1800 if pages == 600 else None,
        },
    }
    validation = {
        "schema_version": "latexstruct-v2-ocr-acceptance/2",
        "result": "PASS",
        "acceptance_passed": True,
        "runtime_identity": runtime,
        "model": model,
        "execution": {
            "real_execution": real_execution,
            "test_double": not real_execution,
            "simulated": not real_execution,
            "api_client": "LocalHttpApi",
            "ui_driver": "PlaywrightUiDriver",
        },
    }
    performance_path = run_dir / "performance.json"
    validation_path = run_dir / "validation-report.json"
    _write_json(performance_path, performance)
    _write_json(validation_path, validation)
    attestation = {
        "schema_version": MODULE.RUN_ATTESTATION_SCHEMA,
        "profile_kind": "ocr",
        "result": "PASS",
        "acceptance_passed": True,
        "generated_at": "2026-08-24T00:00:00Z",
        "execution": validation["execution"],
        "runtime_identity": runtime,
        "source": source,
        "selected_range": selected,
        "pages": page_evidence,
        "model": model,
        "compilation": {
            "status": "COMPILED",
            "successful_passes": 2,
            "exit_code": 0,
            "compile_log_sha256": "b" * 64,
            "baseline_pdf_sha256": "c" * 64,
        },
        "timing": {
            "measurement": (
                "external monotonic wall clock started before browser upload/start "
                "click and stopped only after terminal compile"
            ),
            "started_at": "2026-08-24T00:00:00Z",
            "ended_at": "2026-08-24T00:30:00Z",
            "wall_time_seconds": 1800,
            "successful_pages_per_minute": pages / 30,
            "timed_out": False,
            "completed_terminal_run": True,
        },
        "reports": {
            "performance": {
                "filename": "performance.json",
                "sha256": MODULE._sha256_file(performance_path),
            },
            "validation": {
                "filename": "validation-report.json",
                "sha256": MODULE._sha256_file(validation_path),
            },
        },
    }
    _write_json(run_dir / "acceptance-attestation.json", attestation)
    return run_dir


def _valid_analysis_run(
    root: Path,
    pages: int,
    *,
    real_execution: bool = True,
    terminal_status: str = "VERIFIED",
    executable_sha256: str = "e" * 64,
    source_sha256: str = "a" * 64,
    build_id: str = "200",
) -> Path:
    run_dir = root / f"analysis-run-{pages}"
    runtime = {
        "version": VERSION,
        "commit": COMMIT,
        "build_id": build_id,
        "executable_filename": "LaTeXStruct.exe",
        "executable_sha256": executable_sha256,
    }
    source = {
        "filename": "release-source.pdf",
        "sha256": source_sha256,
        "total_pages": 600,
    }
    selected = {"start_page": 1, "end_page": pages, "expected_pages": pages}
    models = {
        "calls_total": 3,
        "roles": [
            {
                "role": "analysis",
                "model_id": "deepseek-real",
                "backend": "deepseek",
                "calls": 1,
            },
            {
                "role": "review",
                "model_id": "deepseek-review-real",
                "backend": "deepseek",
                "calls": 2,
            },
        ],
    }
    artifact_bytes = {
        "candidate_tex": (
            b"\\documentclass{article}\n"
            b"\\begin{document}\nVerified candidate\n\\end{document}\n"
        ),
        "candidate_pdf": b"%PDF-1.7\n% immutable candidate fixture\n%%EOF\n",
        "compile_log": b"XeLaTeX pass 1: exit 0\nXeLaTeX pass 2: exit 0\n",
    }
    artifacts = {}
    for role, (filename, _compilation_field) in MODULE.ANALYSIS_ARTIFACT_SPECS.items():
        artifact_path = run_dir / filename
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        artifact_path.write_bytes(artifact_bytes[role])
        artifacts[role] = {
            "filename": filename,
            "bytes": artifact_path.stat().st_size,
            "sha256": MODULE._sha256_file(artifact_path),
        }
    compilation = {
        "status": "COMPILED",
        "successful_passes": 2,
        "pass_exit_codes": [0, 0],
        "compile_log_sha256": artifacts["compile_log"]["sha256"],
        "candidate_tex_sha256": artifacts["candidate_tex"]["sha256"],
        "candidate_pdf_sha256": artifacts["candidate_pdf"]["sha256"],
    }
    timing = {
        "measurement": (
            "external monotonic wall clock started before browser upload/start click "
            "and stopped after VERIFIED"
        ),
        "started_at": "2026-08-24T00:00:00Z",
        "ended_at": "2026-08-24T02:00:00Z",
        "wall_time_seconds": 7200 if pages == 600 else 600,
        "timed_out": False,
        "completed_terminal_run": True,
    }
    reviews = [
        {
            "review_id": "final-review-a",
            "context_id": "context-a",
            "context_sha256": "1" * 64,
            "independent": True,
            "result": "PASS",
            "candidate_tex_sha256": artifacts["candidate_tex"]["sha256"],
            "pages_checked": pages,
            "model_id": "deepseek-review-real",
            "backend": "deepseek",
            "calls": 1,
        },
        {
            "review_id": "final-review-b",
            "context_id": "context-b",
            "context_sha256": "2" * 64,
            "independent": True,
            "result": "PASS",
            "candidate_tex_sha256": artifacts["candidate_tex"]["sha256"],
            "pages_checked": pages,
            "model_id": "deepseek-review-real",
            "backend": "deepseek",
            "calls": 1,
        },
    ]
    verification_report = {
        "schema_version": MODULE.ANALYSIS_MACHINE_VERIFICATION_SCHEMA,
        "result": "PASS",
        "candidate_tex_sha256": artifacts["candidate_tex"]["sha256"],
        "pages_checked": pages,
        "silent_omissions": 0,
        "text_loss": 0,
        "unauthorized_math_changes": 0,
        "unclosed_formal_environments": 0,
        "open_critical_issues": 0,
        "open_high_issues": 0,
        "regressions": 0,
    }
    verification_path = run_dir / "analysis-machine-verification.json"
    _write_json(verification_path, verification_report)
    machine = {
        "passed": True,
        **{
            key: value
            for key, value in verification_report.items()
            if key not in {"schema_version", "result"}
        },
        "verification_json_sha256": MODULE._sha256_file(verification_path),
    }
    execution = {
        "real_execution": real_execution,
        "test_double": not real_execution,
        "simulated": not real_execution,
        "api_client": "LocalHttpApi",
        "ui_driver": "PlaywrightUiDriver",
        "workflow": "OCR_ANALYSIS_REVIEW",
        "producer": (
            "tools/v2_analysis_acceptance.py"
            if real_execution
            else "tests/fake_analysis_runner.py"
        ),
    }
    performance = {
        "schema_version": MODULE.ANALYSIS_PERFORMANCE_SCHEMA,
        "result": "PASS",
        "acceptance_passed": True,
        "runtime_identity": runtime,
        "source": source,
        "selected_range": selected,
        "models": models,
        "compilation": compilation,
        "timing": timing,
        "thresholds": {"maximum_wall_time_seconds": 10800},
        "target_met": True,
    }
    validation = {
        "schema_version": MODULE.ANALYSIS_VALIDATION_SCHEMA,
        "result": "PASS",
        "acceptance_passed": True,
        "runtime_identity": runtime,
        "source": source,
        "execution": execution,
        "terminal_status": terminal_status,
        "independent_final_reviews": reviews,
        "machine_verification": machine,
    }
    performance_path = run_dir / "analysis-performance.json"
    validation_path = run_dir / "analysis-validation-report.json"
    _write_json(performance_path, performance)
    _write_json(validation_path, validation)
    attestation = {
        "schema_version": MODULE.ANALYSIS_ATTESTATION_SCHEMA,
        "profile_kind": "analysis",
        "profile": f"analysis-{pages}",
        "result": "PASS",
        "acceptance_passed": True,
        "terminal_status": terminal_status,
        "generated_at": "2026-08-24T02:00:00Z",
        "execution": execution,
        "runtime_identity": runtime,
        "source": source,
        "selected_range": selected,
        "models": models,
        "compilation": compilation,
        "artifacts": artifacts,
        "timing": timing,
        "independent_final_reviews": reviews,
        "machine_verification": machine,
        "reports": {
            "performance": {
                "filename": "analysis-performance.json",
                "sha256": MODULE._sha256_file(performance_path),
            },
            "validation": {
                "filename": "analysis-validation-report.json",
                "sha256": MODULE._sha256_file(validation_path),
            },
            "verification": {
                "filename": "analysis-machine-verification.json",
                "sha256": MODULE._sha256_file(verification_path),
            },
        },
    }
    _write_json(run_dir / "analysis-attestation.json", attestation)
    return run_dir


def _candidate_release_fixture(tmp_path: Path) -> dict[str, Path]:
    executable = tmp_path / "candidate-inputs" / "LaTeXStruct.exe"
    license_file = tmp_path / "candidate-inputs" / "LICENSE"
    notices_file = tmp_path / "candidate-inputs" / "THIRD_PARTY_NOTICES.txt"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"MZ-four-profile-tested")
    license_file.write_text("license", encoding="utf-8")
    notices_file.write_text("notices", encoding="utf-8")
    executable_sha = MODULE._sha256_file(executable)

    candidate_dir = tmp_path / "candidate-artifact"
    candidate_dir.mkdir()
    portable = candidate_dir / f"LaTeXStruct-portable-{VERSION}.zip"
    setup = candidate_dir / f"LaTeXStruct-setup-{VERSION}.exe"
    MODULE.build_portable_archive(
        executable=executable,
        license_file=license_file,
        notices_file=notices_file,
        output=portable,
    )
    setup.write_bytes(b"MZ-tested-setup-wrapper")
    assets_manifest = candidate_dir / "release-assets.json"
    checksums = candidate_dir / "SHA256SUMS.txt"
    MODULE.write_asset_manifest(
        assets=[portable, setup],
        version=VERSION,
        commit=COMMIT,
        build_id="200",
        output=assets_manifest,
        checksums_output=checksums,
    )

    attestation = tmp_path / "release" / "release-attestation.json"
    MODULE.assemble_release_attestation(
        version=VERSION,
        commit=COMMIT,
        run_dirs={
            "ocr-17": _valid_run(
                tmp_path / "ocr17", 17, executable_sha256=executable_sha
            ),
            "ocr-600": _valid_run(
                tmp_path / "ocr600", 600, executable_sha256=executable_sha
            ),
            "analysis-17": _valid_analysis_run(
                tmp_path / "analysis17", 17, executable_sha256=executable_sha
            ),
            "analysis-600": _valid_analysis_run(
                tmp_path / "analysis600", 600, executable_sha256=executable_sha
            ),
        },
        output=attestation,
    )
    return {
        "attestation": attestation,
        "candidate_dir": candidate_dir,
        "portable": portable,
        "setup": setup,
        "assets_manifest": assets_manifest,
        "checksums": checksums,
    }


def test_portable_archive_has_exact_root_license_and_notice_bytes(tmp_path: Path):
    executable = tmp_path / "LaTeXStruct.exe"
    license_file = tmp_path / "LICENSE"
    notices = tmp_path / "THIRD_PARTY_NOTICES.txt"
    executable.write_bytes(b"MZ-test")
    license_file.write_text("project license", encoding="utf-8")
    notices.write_text("third party notices", encoding="utf-8")
    output = tmp_path / "portable.zip"

    digests = MODULE.build_portable_archive(
        executable=executable,
        license_file=license_file,
        notices_file=notices,
        output=output,
    )

    with zipfile.ZipFile(output) as archive:
        assert archive.namelist() == [
            "LaTeXStruct.exe",
            "LICENSE",
            "THIRD_PARTY_NOTICES.txt",
        ]
        assert archive.read("LICENSE") == b"project license"
        assert archive.read("THIRD_PARTY_NOTICES.txt") == b"third party notices"
    assert digests["LaTeXStruct.exe"] == _sha(b"MZ-test")


def test_asset_manifest_and_sha256sums_are_generated_from_final_bytes(tmp_path: Path):
    portable = tmp_path / "LaTeXStruct-portable-2.0.0.zip"
    setup = tmp_path / "LaTeXStruct-setup-2.0.0.exe"
    portable.write_bytes(b"portable")
    setup.write_bytes(b"setup")

    manifest = MODULE.write_asset_manifest(
        assets=[portable, setup],
        version=VERSION,
        commit=COMMIT,
        build_id="12345",
        output=tmp_path / "release-assets.json",
        checksums_output=tmp_path / "SHA256SUMS.txt",
    )

    by_name = {item["filename"]: item for item in manifest["assets"]}
    assert by_name[portable.name]["sha256"] == _sha(b"portable")
    assert by_name[setup.name]["sha256"] == _sha(b"setup")
    sums = (tmp_path / "SHA256SUMS.txt").read_text(encoding="utf-8")
    assert f"{_sha(b'portable')}  {portable.name}" in sums
    assert f"{_sha(b'setup')}  {setup.name}" in sums


def test_tag_release_reuses_and_verifies_exact_attested_candidate_bytes(
    tmp_path: Path,
):
    fixture = _candidate_release_fixture(tmp_path)

    verified = MODULE.verify_candidate_release_assets(
        manifest=fixture["attestation"],
        version=VERSION,
        commit=COMMIT,
        assets_manifest=fixture["assets_manifest"],
        checksums=fixture["checksums"],
        assets_dir=fixture["candidate_dir"],
    )

    assert verified["build_id"] == "200"
    assert verified["tested_executable_sha256"] == _sha(
        b"MZ-four-profile-tested"
    )
    assert verified["portable_executable_sha256"] == verified[
        "tested_executable_sha256"
    ]
    assert {item["filename"] for item in verified["assets"]} == {
        f"LaTeXStruct-portable-{VERSION}.zip",
        f"LaTeXStruct-setup-{VERSION}.exe",
    }
    assert (
        MODULE.main(
            [
                "verify-candidate-assets",
                "--manifest",
                str(fixture["attestation"]),
                "--version",
                VERSION,
                "--commit",
                COMMIT,
                "--assets-manifest",
                str(fixture["assets_manifest"]),
                "--checksums",
                str(fixture["checksums"]),
                "--assets-dir",
                str(fixture["candidate_dir"]),
            ]
        )
        == 0
    )


def test_candidate_asset_verification_rejects_tampering_and_wrong_run_identity(
    tmp_path: Path,
):
    fixture = _candidate_release_fixture(tmp_path / "tampered")
    fixture["setup"].write_bytes(b"MZ-replaced-after-acceptance")
    with pytest.raises(MODULE.ReleaseIntegrityError, match="byte count mismatch"):
        MODULE.verify_candidate_release_assets(
            manifest=fixture["attestation"],
            version=VERSION,
            commit=COMMIT,
            assets_manifest=fixture["assets_manifest"],
            checksums=fixture["checksums"],
            assets_dir=fixture["candidate_dir"],
        )

    fixture = _candidate_release_fixture(tmp_path / "extra-file")
    (fixture["candidate_dir"] / "unreviewed.exe").write_bytes(b"MZ-extra")
    with pytest.raises(MODULE.ReleaseIntegrityError, match="exactly portable"):
        MODULE.verify_candidate_release_assets(
            manifest=fixture["attestation"],
            version=VERSION,
            commit=COMMIT,
            assets_manifest=fixture["assets_manifest"],
            checksums=fixture["checksums"],
            assets_dir=fixture["candidate_dir"],
        )

    fixture = _candidate_release_fixture(tmp_path / "wrong-run")
    payload = json.loads(fixture["assets_manifest"].read_text(encoding="utf-8"))
    payload["build_id"] = "201"
    _write_json(fixture["assets_manifest"], payload)
    with pytest.raises(MODULE.ReleaseIntegrityError, match="build id differs"):
        MODULE.verify_candidate_release_assets(
            manifest=fixture["attestation"],
            version=VERSION,
            commit=COMMIT,
            assets_manifest=fixture["assets_manifest"],
            checksums=fixture["checksums"],
            assets_dir=fixture["candidate_dir"],
        )


def test_candidate_asset_verification_recomputes_checksums_and_portable_exe(
    tmp_path: Path,
):
    fixture = _candidate_release_fixture(tmp_path / "checksums")
    fixture["checksums"].write_text("0" * 64 + "  forged.exe\n", encoding="utf-8")
    with pytest.raises(MODULE.ReleaseIntegrityError, match="SHA256SUMS"):
        MODULE.verify_candidate_release_assets(
            manifest=fixture["attestation"],
            version=VERSION,
            commit=COMMIT,
            assets_manifest=fixture["assets_manifest"],
            checksums=fixture["checksums"],
            assets_dir=fixture["candidate_dir"],
        )

    fixture = _candidate_release_fixture(tmp_path / "wrong-exe")
    bad_executable = tmp_path / "wrong-exe" / "bad.exe"
    bad_executable.write_bytes(b"MZ-not-four-profile-tested")
    MODULE.build_portable_archive(
        executable=bad_executable,
        license_file=tmp_path / "wrong-exe" / "candidate-inputs" / "LICENSE",
        notices_file=(
            tmp_path
            / "wrong-exe"
            / "candidate-inputs"
            / "THIRD_PARTY_NOTICES.txt"
        ),
        output=fixture["portable"],
    )
    MODULE.write_asset_manifest(
        assets=[fixture["portable"], fixture["setup"]],
        version=VERSION,
        commit=COMMIT,
        build_id="200",
        output=fixture["assets_manifest"],
        checksums_output=fixture["checksums"],
    )
    with pytest.raises(MODULE.ReleaseIntegrityError, match="tested by all four"):
        MODULE.verify_candidate_release_assets(
            manifest=fixture["attestation"],
            version=VERSION,
            commit=COMMIT,
            assets_manifest=fixture["assets_manifest"],
            checksums=fixture["checksums"],
            assets_dir=fixture["candidate_dir"],
        )


def test_release_attestation_requires_numeric_github_run_id(tmp_path: Path):
    with pytest.raises(MODULE.ReleaseIntegrityError, match="numeric GitHub Actions"):
        MODULE.verify_run_attestation(
            _valid_run(tmp_path, 17, build_id="build-200"),
            expected_pages=17,
            version=VERSION,
            commit=COMMIT,
        )


def test_release_executable_and_portable_must_equal_four_profile_tested_bytes(
    tmp_path: Path,
):
    executable = tmp_path / "LaTeXStruct.exe"
    executable.write_bytes(b"MZ-exact-tested-release")
    executable_sha = MODULE._sha256_file(executable)
    license_file = tmp_path / "LICENSE"
    notices = tmp_path / "THIRD_PARTY_NOTICES.txt"
    license_file.write_text("license", encoding="utf-8")
    notices.write_text("notices", encoding="utf-8")
    portable = tmp_path / "LaTeXStruct-portable-2.0.0.zip"
    MODULE.build_portable_archive(
        executable=executable,
        license_file=license_file,
        notices_file=notices,
        output=portable,
    )
    manifest = tmp_path / "release" / "release-attestation.json"
    MODULE.assemble_release_attestation(
        version=VERSION,
        commit=COMMIT,
        run_dirs={
            "ocr-17": _valid_run(
                tmp_path, 17, executable_sha256=executable_sha
            ),
            "ocr-600": _valid_run(
                tmp_path, 600, executable_sha256=executable_sha
            ),
            "analysis-17": _valid_analysis_run(
                tmp_path, 17, executable_sha256=executable_sha
            ),
            "analysis-600": _valid_analysis_run(
                tmp_path, 600, executable_sha256=executable_sha
            ),
        },
        output=manifest,
    )
    assert json.loads(manifest.read_text(encoding="utf-8"))[
        "tested_executable_sha256"
    ] == executable_sha

    result = MODULE.verify_release_executable(
        manifest=manifest,
        version=VERSION,
        commit=COMMIT,
        executable=executable,
        portable=portable,
    )
    assert set(result.values()) == {executable_sha}

    executable.write_bytes(b"MZ-rebuilt-but-never-accepted")
    with pytest.raises(MODULE.ReleaseIntegrityError, match="release executable SHA"):
        MODULE.verify_release_executable(
            manifest=manifest,
            version=VERSION,
            commit=COMMIT,
            executable=executable,
            portable=portable,
        )

    executable.write_bytes(b"MZ-exact-tested-release")
    untested = tmp_path / "untested.exe"
    untested.write_bytes(b"MZ-untested-portable")
    bad_portable = tmp_path / "bad-portable.zip"
    MODULE.build_portable_archive(
        executable=untested,
        license_file=license_file,
        notices_file=notices,
        output=bad_portable,
    )
    with pytest.raises(MODULE.ReleaseIntegrityError, match="portable LaTeXStruct"):
        MODULE.verify_release_executable(
            manifest=manifest,
            version=VERSION,
            commit=COMMIT,
            executable=executable,
            portable=bad_portable,
        )


def test_release_notes_reject_hard_coded_current_ci_asset_digest(tmp_path: Path):
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(
        f"## v{VERSION}（待发布）\n\nLaTeXStruct-portable asset SHA-256: "
        f"{'f' * 64}\n\n## v1.0.0（旧）\nold\n",
        encoding="utf-8",
    )

    with pytest.raises(MODULE.ReleaseIntegrityError, match="hard-codes"):
        MODULE.verify_release_notes(changelog, VERSION)

    changelog.write_text(
        f"## v{VERSION}（待发布）\n\n摘要由 CI 的 SHA256SUMS.txt 动态生成。\n",
        encoding="utf-8",
    )
    MODULE.verify_release_notes(changelog, VERSION)


def test_release_attestation_requires_four_real_profiles_and_detects_tampering(
    tmp_path: Path,
):
    run17 = _valid_run(tmp_path, 17)
    run600 = _valid_run(tmp_path, 600)
    analysis17 = _valid_analysis_run(tmp_path, 17)
    analysis600 = _valid_analysis_run(tmp_path, 600)
    manifest = tmp_path / "release" / "release-attestation.json"

    MODULE.assemble_release_attestation(
        version=VERSION,
        commit=COMMIT,
        run_dirs={
            "ocr-17": run17,
            "ocr-600": run600,
            "analysis-17": analysis17,
            "analysis-600": analysis600,
        },
        output=manifest,
    )
    MODULE.verify_release_attestation(manifest, version=VERSION, commit=COMMIT)

    copied_performance = manifest.parent / "ocr-600" / "performance.json"
    copied_performance.write_text("{}\n", encoding="utf-8")
    with pytest.raises(MODULE.ReleaseIntegrityError, match="digest mismatch"):
        MODULE.verify_release_attestation(manifest, version=VERSION, commit=COMMIT)


def test_release_allows_distinct_17_and_600_sources_but_keeps_each_pair_bound(
    tmp_path: Path,
):
    source17 = "1" * 64
    source600 = "6" * 64
    manifest = tmp_path / "release" / "release-attestation.json"

    MODULE.assemble_release_attestation(
        version=VERSION,
        commit=COMMIT,
        run_dirs={
            "ocr-17": _valid_run(tmp_path / "ocr17", 17, source_sha256=source17),
            "ocr-600": _valid_run(
                tmp_path / "ocr600", 600, source_sha256=source600
            ),
            "analysis-17": _valid_analysis_run(
                tmp_path / "analysis17", 17, source_sha256=source17
            ),
            "analysis-600": _valid_analysis_run(
                tmp_path / "analysis600", 600, source_sha256=source600
            ),
        },
        output=manifest,
    )

    verified = MODULE.verify_release_attestation(
        manifest, version=VERSION, commit=COMMIT
    )
    assert verified["sources"]["17"]["sha256"] == source17
    assert verified["sources"]["600"]["sha256"] == source600


def test_test_double_run_is_rejected_as_release_attestation(tmp_path: Path):
    run_dir = _valid_run(tmp_path, 17, real_execution=False)
    with pytest.raises(MODULE.ReleaseIntegrityError, match="test-double"):
        MODULE.verify_run_attestation(
            run_dir,
            expected_pages=17,
            version=VERSION,
            commit=COMMIT,
        )


def test_release_attestation_rejects_different_executables_between_runs(
    tmp_path: Path,
):
    run17 = _valid_run(tmp_path, 17)
    run600 = _valid_run(tmp_path, 600)
    analysis17 = _valid_analysis_run(tmp_path, 17)
    analysis600 = _valid_analysis_run(tmp_path, 600)
    path = run600 / "acceptance-attestation.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["runtime_identity"]["executable_sha256"] = "f" * 64
    for report_name in ("performance.json", "validation-report.json"):
        report_path = run600 / report_name
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["runtime_identity"]["executable_sha256"] = "f" * 64
        _write_json(report_path, report)
        report_key = "performance" if report_name == "performance.json" else "validation"
        payload["reports"][report_key]["sha256"] = MODULE._sha256_file(report_path)
    _write_json(path, payload)

    with pytest.raises(MODULE.ReleaseIntegrityError, match="same commit/build_id/executable"):
        MODULE.assemble_release_attestation(
            version=VERSION,
            commit=COMMIT,
            run_dirs={
                "ocr-17": run17,
                "ocr-600": run600,
                "analysis-17": analysis17,
                "analysis-600": analysis600,
            },
            output=tmp_path / "release" / "release-attestation.json",
        )


def test_missing_analysis_profiles_fail_closed_with_actionable_error(tmp_path: Path):
    with pytest.raises(MODULE.ReleaseIntegrityError, match="analysis-17"):
        MODULE.assemble_release_attestation(
            version=VERSION,
            commit=COMMIT,
            run_dirs={
                "ocr-17": _valid_run(tmp_path, 17),
                "ocr-600": _valid_run(tmp_path, 600),
            },
            output=tmp_path / "release" / "release-attestation.json",
        )
    assert not (tmp_path / "release" / "release-attestation.json").exists()

    old_manifest = tmp_path / "old-release-attestation.json"
    _write_json(
        old_manifest,
        {
            "schema_version": "latexstruct-release-acceptance/1",
            "version": VERSION,
            "commit": COMMIT,
            "runs": {"ocr-17": {}, "ocr-600": {}},
        },
    )
    with pytest.raises(MODULE.ReleaseIntegrityError, match="analysis-17, analysis-600"):
        MODULE.verify_release_attestation(
            old_manifest, version=VERSION, commit=COMMIT
        )


def test_analysis_test_double_and_unverified_terminal_cannot_mint_pass(tmp_path: Path):
    fake = _valid_analysis_run(tmp_path / "fake", 17, real_execution=False)
    with pytest.raises(MODULE.ReleaseIntegrityError, match="test-double"):
        MODULE.verify_analysis_attestation(
            fake,
            expected_pages=17,
            version=VERSION,
            commit=COMMIT,
        )

    unverified = _valid_analysis_run(
        tmp_path / "unverified", 17, terminal_status="UNVERIFIED"
    )
    with pytest.raises(MODULE.ReleaseIntegrityError, match="VERIFIED"):
        MODULE.verify_analysis_attestation(
            unverified,
            expected_pages=17,
            version=VERSION,
            commit=COMMIT,
        )


def test_analysis_requires_real_calls_distinct_contexts_and_machine_pass(tmp_path: Path):
    run_dir = _valid_analysis_run(tmp_path, 17)
    path = run_dir / "analysis-attestation.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["models"]["calls_total"] = 0
    _write_json(path, payload)
    with pytest.raises(MODULE.ReleaseIntegrityError, match="call total"):
        MODULE.verify_analysis_attestation(
            run_dir, expected_pages=17, version=VERSION, commit=COMMIT
        )

    run_dir = _valid_analysis_run(tmp_path / "contexts", 17)
    path = run_dir / "analysis-attestation.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["independent_final_reviews"][1]["context_id"] = "context-a"
    _write_json(path, payload)
    with pytest.raises(MODULE.ReleaseIntegrityError, match="distinct context ids"):
        MODULE.verify_analysis_attestation(
            run_dir, expected_pages=17, version=VERSION, commit=COMMIT
        )

    run_dir = _valid_analysis_run(tmp_path / "machine", 17)
    path = run_dir / "analysis-attestation.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["machine_verification"]["passed"] = False
    _write_json(path, payload)
    with pytest.raises(MODULE.ReleaseIntegrityError, match="machine verification"):
        MODULE.verify_analysis_attestation(
            run_dir, expected_pages=17, version=VERSION, commit=COMMIT
        )


def test_analysis_requires_recomputable_compilation_artifacts(tmp_path: Path):
    hash_only = _valid_analysis_run(tmp_path / "hash-only", 17)
    attestation_path = hash_only / "analysis-attestation.json"
    payload = json.loads(attestation_path.read_text(encoding="utf-8"))
    payload.pop("artifacts")
    _write_json(attestation_path, payload)
    with pytest.raises(MODULE.ReleaseIntegrityError, match="missing fields: artifacts"):
        MODULE.verify_analysis_attestation(
            hash_only, expected_pages=17, version=VERSION, commit=COMMIT
        )

    missing = _valid_analysis_run(tmp_path / "missing", 17)
    (missing / "candidate.pdf").unlink()
    with pytest.raises(MODULE.ReleaseIntegrityError, match="artifact is missing: candidate.pdf"):
        MODULE.verify_analysis_attestation(
            missing, expected_pages=17, version=VERSION, commit=COMMIT
        )

    tampered = _valid_analysis_run(tmp_path / "tampered", 17)
    candidate_path = tampered / "candidate.tex"
    candidate_bytes = candidate_path.read_bytes()
    candidate_path.write_bytes(b"X" + candidate_bytes[1:])
    with pytest.raises(MODULE.ReleaseIntegrityError, match="artifact digest mismatch: candidate.tex"):
        MODULE.verify_analysis_attestation(
            tampered, expected_pages=17, version=VERSION, commit=COMMIT
        )

    wrong_size = _valid_analysis_run(tmp_path / "wrong-size", 17)
    attestation_path = wrong_size / "analysis-attestation.json"
    payload = json.loads(attestation_path.read_text(encoding="utf-8"))
    payload["artifacts"]["compile_log"]["bytes"] += 1
    _write_json(attestation_path, payload)
    with pytest.raises(MODULE.ReleaseIntegrityError, match="byte count mismatch: compile.log"):
        MODULE.verify_analysis_attestation(
            wrong_size, expected_pages=17, version=VERSION, commit=COMMIT
        )


def test_release_assembly_copies_and_reverifies_analysis_artifacts(tmp_path: Path):
    ocr17 = _valid_run(tmp_path / "runs", 17)
    ocr600 = _valid_run(tmp_path / "runs", 600)
    analysis17 = _valid_analysis_run(tmp_path / "runs", 17)
    analysis600 = _valid_analysis_run(tmp_path / "runs", 600)
    manifest = tmp_path / "release" / "release-attestation.json"

    MODULE.assemble_release_attestation(
        version=VERSION,
        commit=COMMIT,
        run_dirs={
            "ocr-17": ocr17,
            "ocr-600": ocr600,
            "analysis-17": analysis17,
            "analysis-600": analysis600,
        },
        output=manifest,
    )

    for profile, source_dir in (
        ("analysis-17", analysis17),
        ("analysis-600", analysis600),
    ):
        for filename, _compilation_field in MODULE.ANALYSIS_ARTIFACT_SPECS.values():
            assert (manifest.parent / profile / filename).read_bytes() == (
                source_dir / filename
            ).read_bytes()
    MODULE.verify_release_attestation(manifest, version=VERSION, commit=COMMIT)

    (manifest.parent / "analysis-17" / "candidate.pdf").write_bytes(
        b"%PDF-1.7\ntampered after assembly\n"
    )
    with pytest.raises(MODULE.ReleaseIntegrityError, match="artifact .*candidate.pdf"):
        MODULE.verify_release_attestation(manifest, version=VERSION, commit=COMMIT)


def test_analysis_source_pdf_must_match_paired_ocr_profile(tmp_path: Path):
    run17 = _valid_run(tmp_path, 17)
    run600 = _valid_run(tmp_path, 600)
    analysis17 = _valid_analysis_run(tmp_path, 17)
    analysis600 = _valid_analysis_run(tmp_path, 600)
    path = analysis17 / "analysis-attestation.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["source"]["sha256"] = "f" * 64
    for report_name in (
        "analysis-performance.json",
        "analysis-validation-report.json",
    ):
        report_path = analysis17 / report_name
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["source"]["sha256"] = "f" * 64
        _write_json(report_path, report)
        report_key = "performance" if "performance" in report_name else "validation"
        payload["reports"][report_key]["sha256"] = MODULE._sha256_file(report_path)
    _write_json(path, payload)

    with pytest.raises(MODULE.ReleaseIntegrityError, match="source PDF SHA"):
        MODULE.assemble_release_attestation(
            version=VERSION,
            commit=COMMIT,
            run_dirs={
                "ocr-17": run17,
                "ocr-600": run600,
                "analysis-17": analysis17,
                "analysis-600": analysis600,
            },
            output=tmp_path / "release" / "release-attestation.json",
        )


def test_analysis_schema_is_strict_and_cli_can_write_it(tmp_path: Path):
    schema = MODULE.analysis_attestation_json_schema()
    assert schema["additionalProperties"] is False
    assert schema["properties"]["execution"]["additionalProperties"] is False
    assert schema["properties"]["terminal_status"] == {"const": "VERIFIED"}
    assert schema["properties"]["independent_final_reviews"]["minItems"] == 2
    assert schema["properties"]["independent_final_reviews"]["maxItems"] == 2
    assert schema["properties"]["models"]["properties"]["calls_total"]["minimum"] == 1
    assert "artifacts" in schema["required"]
    artifacts = schema["properties"]["artifacts"]
    assert artifacts["additionalProperties"] is False
    assert artifacts["required"] == list(MODULE.ANALYSIS_ARTIFACT_SPECS)
    assert (
        artifacts["properties"]["candidate_tex"]["properties"]["filename"]
        == {"const": "candidate.tex"}
    )

    output = tmp_path / "analysis-attestation.schema.json"
    assert MODULE.main(["analysis-schema", "--output", str(output)]) == 0
    assert json.loads(output.read_text(encoding="utf-8")) == schema


def test_release_docs_declare_playwright_acceptance_environment():
    root = Path(__file__).resolve().parents[1]
    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
    readme = (root / "README.md").read_text(encoding="utf-8")

    assert "acceptance = [" in pyproject
    assert '"playwright>=' in pyproject
    assert 'pip install -e ".[server,acceptance]"' in readme
    assert "python -m playwright install chromium" in readme
    assert "浏览器二进制" in readme and "不进入仓库" in readme


def test_build_workflow_guards_tag_release_and_publishes_dynamic_hashes():
    workflow = (
        Path(__file__).resolve().parents[1] / ".github" / "workflows" / "build.yml"
    ).read_text(encoding="utf-8")
    release_action = workflow.index("softprops/action-gh-release@v2")
    tag_job = workflow.index("release_attested_candidate:")
    candidate_job = workflow.index("build_candidate:")
    assert workflow.index("git merge-base --is-ancestor") < release_action
    assert workflow.index("verify-attestation") < release_action
    assert workflow.index("record-assets") < workflow.index(
        "actions/upload-artifact@v4"
    ) < tag_job
    assert tag_job < workflow.index("actions/download-artifact@v4") < workflow.index(
        "verify-candidate-assets"
    ) < release_action
    assert "if: github.event_name == 'workflow_dispatch'" in workflow[
        candidate_job:tag_job
    ]
    assert (
        "if: startsWith(github.ref, 'refs/tags/v') && "
        "!contains(github.ref_name, '-')"
    ) in workflow[tag_job:release_action]
    assert "run-id: ${{ env.CANDIDATE_RUN_ID }}" in workflow[tag_job:]
    assert "[string]$candidateRun.event -ne 'workflow_dispatch'" in workflow
    assert "[string]$candidateRun.status -ne 'completed'" in workflow
    assert "[string]$candidateRun.conclusion -ne 'success'" in workflow
    assert "[string]$candidateRun.path -ne '.github/workflows/build.yml'" in workflow
    assert "[int]$candidateRun.run_attempt -ne 1" in workflow
    assert "candidateRun.head_sha" in workflow
    assert "PyInstaller" not in workflow[tag_job:]
    assert "iscc" not in workflow[tag_job:]
    assert "record-assets" not in workflow[tag_job:]
    assert "verify-release-executable" not in workflow
    assert "真实验收后仍修改了运行时文件" in workflow
    assert "ocr-17、ocr-600、analysis-17、analysis-600" in workflow
    assert "缺少 analysis-17/analysis-600" in workflow
    assert "release/acceptance/v$env:APP_VERSION/" in workflow
    assert "dist/SHA256SUMS.txt" in workflow
    assert "dist/release-assets.json" in workflow
    assert "build-portable" in workflow
    assert "LaTeXStruct-portable-${{ env.APP_VERSION }}.zip" in workflow[tag_job:]
    assert "LaTeXStruct-setup-${{ env.APP_VERSION }}.exe" in workflow[tag_job:]

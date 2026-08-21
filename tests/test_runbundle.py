from __future__ import annotations

import csv
import hashlib
import io
import json
import zipfile

import pytest

from latexstruct.core.preview import preview_artifact_path
from latexstruct.core.runbundle import (
    RUN_BUNDLE_NAMES,
    append_run_bundle,
    preview_state_from_verification,
)


def _archive(files: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return output.getvalue()


def test_preview_states_never_call_source_text_a_compiled_preview():
    assert preview_state_from_verification({}) == "SOURCE_PREVIEW"
    assert preview_state_from_verification({
        "compile_after": {"available": False, "ok": False},
    }) == "SOURCE_PREVIEW"
    assert preview_state_from_verification({
        "compile_after": {"available": True, "ok": False},
    }) == "SOURCE_PREVIEW"
    assert preview_state_from_verification({
        "compile_after": {
            "available": True,
            "ok": False,
            "preview_status": "PARTIAL_COMPILED",
        },
    }) == "SOURCE_PREVIEW"
    assert preview_state_from_verification({
        "compile_after": {"available": True, "ok": True},
    }) == "SOURCE_PREVIEW"
    assert preview_state_from_verification({
        "compile_after": {
            "available": True,
            "ok": False,
            "preview_status": "PARTIAL_COMPILED",
        },
        "preview_artifact": {"status": "PARTIAL_COMPILED"},
    }) == "PARTIAL_COMPILED"
    assert preview_state_from_verification({
        "compile_after": {
            "available": True,
            "ok": False,
            "preview_status": "COMPILED",
        },
        "preview_artifact": {"status": "COMPILED"},
    }) == "SOURCE_PREVIEW"


def test_run_bundle_contains_recomputable_audit_artifacts_and_issues_csv():
    partial_pdf = b"%PDF-1.7\npartial artifact\n"
    partial_digest = hashlib.sha256(partial_pdf).hexdigest()
    partial_path = preview_artifact_path("PARTIAL_COMPILED", partial_digest)
    base = {
        "main.tex": b"\\documentclass{article}\n",
        "LATEXSTRUCT-REPORT.md": b"# report\n",
        "LATEXSTRUCT-PROVENANCE.json": b"{}\n",
        partial_path: partial_pdf,
    }
    info = {
        "verification": {
            "safe_to_export": False,
            "compile_after": {
                "available": True,
                "ok": False,
                "preview_status": "PARTIAL_COMPILED",
            },
            "preview_artifact": {
                "status": "PARTIAL_COMPILED",
                "filename": partial_path,
                "sha256": partial_digest,
                "bytes": len(partial_pdf),
            },
            "checks": [{"id": "compile", "ok": False}],
            "failures": [{
                "id": "compile",
                "summary": "compile failed",
                "action": "fix the first error",
            }],
            "structure_decisions": {"formal_total": 13, "formal_wrapped": 10},
        },
        "ambiguous": [{"candidate_id": "t-3.8", "line": 490, "reason": "residual"}],
        "rejected": [],
        "items": [],
    }
    provenance = {
        "schema_version": "latexstruct-export-provenance-v2",
        "producer_app_version": "1.2.5",
        "producer_build_id": "run-1",
        "producer_commit": "a" * 40,
        "exporter_app_version": "1.2.5",
        "exporter_build_id": "run-1",
        "exporter_commit": "a" * 40,
    }

    bundled = append_run_bundle(
        _archive(base),
        info=info,
        provenance=provenance,
        terminal_status="blocked",
        attempt="blocked",
        main_path="main.tex",
    )
    with zipfile.ZipFile(io.BytesIO(bundled)) as archive:
        assert RUN_BUNDLE_NAMES.issubset(archive.namelist())
        report = json.loads(archive.read("LATEXSTRUCT-REPORT.json"))
        assert report["verification_status"] == "UNVERIFIED"
        assert report["terminal_status"] == "UNVERIFIED"
        assert report["preview_state"] == "PARTIAL_COMPILED"
        assert report["blocker_count"] == 1
        run = json.loads(archive.read("LATEXSTRUCT-RUN.json"))
        assert run["producer_identity"]["commit"] == "a" * 40
        assert run["exporter_identity"]["commit"] == "a" * 40
        assert run["preview"] == {
            "state": "PARTIAL_COMPILED",
            "artifact": partial_path,
            "compiled_pdf_included": True,
        }
        assert [item["role"] for item in run["lineage"]][-2:] == [
            "unstamped-result-tex",
            "exported-main-tex",
        ]
        assert run["lineage"][-1]["parent_artifact_ids"] == [
            run["lineage"][-2]["artifact_id"]
        ]
        rows = list(csv.DictReader(io.StringIO(
            archive.read("LATEXSTRUCT-ISSUES.csv").decode("utf-8")
        )))
        assert [row["issue_id"] for row in rows] == [
            "BLOCKER-001",
            "AMBIGUOUS-001",
        ]
        sums = {}
        for line in archive.read("SHA256SUMS").decode("ascii").splitlines():
            digest, name = line.split("  ", 1)
            sums[name] = digest
        assert "SHA256SUMS" not in sums
        assert set(sums) == set(archive.namelist()) - {"SHA256SUMS"}
        for name, digest in sums.items():
            assert hashlib.sha256(archive.read(name)).hexdigest() == digest


def test_run_bundle_rejects_reserved_user_file_collision():
    with pytest.raises(ValueError, match="reserved run-bundle"):
        append_run_bundle(
            _archive({"main.tex": b"x", "LATEXSTRUCT-RUN.json": b"user"}),
            info={},
            provenance={},
            terminal_status="source",
            attempt="source",
            main_path="main.tex",
        )


def test_run_bundle_rejects_case_variant_of_reserved_filename():
    with pytest.raises(ValueError, match="reserved run-bundle"):
        append_run_bundle(
            _archive({"main.tex": b"x", "latexstruct-run.json": b"user"}),
            info={},
            provenance={},
            terminal_status="source",
            attempt="source",
            main_path="main.tex",
        )


@pytest.mark.parametrize(
    "descendant",
    [
        "latexstruct-run.JSON/child.tex",
        "LATEXSTRUCT-RUN.json\\child.tex",
    ],
)
def test_run_bundle_rejects_reserved_file_descendant_collision(descendant):
    with pytest.raises(ValueError, match="file/directory path collision"):
        append_run_bundle(
            _archive({"main.tex": b"x", descendant: b"user"}),
            info={},
            provenance={},
            terminal_status="source",
            attempt="source",
            main_path="main.tex",
        )


def test_run_bundle_rejects_file_that_blocks_compiled_artifact_directory():
    digest = "a" * 64
    artifact = preview_artifact_path("COMPILED", digest)
    with pytest.raises(ValueError, match="file/directory path collision"):
        append_run_bundle(
            _archive({
                "main.tex": b"x",
                "LATEXSTRUCT-ARTIFACTS": b"user-file",
                artifact: b"%PDF-preview",
            }),
            info={"verification": {"safe_to_export": False}},
            provenance={},
            terminal_status="source",
            attempt="source",
            main_path="main.tex",
        )


def test_run_bundle_allows_explicit_directory_and_its_child():
    bundled = append_run_bundle(
        _archive({
            "main.tex": b"x",
            "assets/": b"",
            "assets/figure.pdf": b"%PDF-user",
        }),
        info={"verification": {"safe_to_export": False}},
        provenance={},
        terminal_status="source",
        attempt="source",
        main_path="main.tex",
    )
    with zipfile.ZipFile(io.BytesIO(bundled)) as archive:
        assert "assets/" in archive.namelist()
        assert "assets/figure.pdf" in archive.namelist()


@pytest.mark.parametrize(
    "unsafe_name",
    [
        "LATEXSTRUCT-RUN.json.",
        "LATEXSTRUCT-RUN.json ",
        "folder./child.tex",
        "folder /child.tex",
    ],
)
def test_run_bundle_rejects_windows_trailing_dot_or_space_aliases(unsafe_name):
    with pytest.raises(ValueError, match="Windows-unsafe trailing dot or space"):
        append_run_bundle(
            _archive({"main.tex": b"x", unsafe_name: b"user"}),
            info={},
            provenance={},
            terminal_status="source",
            attempt="source",
            main_path="main.tex",
        )


def test_source_preview_does_not_claim_an_unbound_user_pdf():
    bundled = append_run_bundle(
        _archive({
            "main.tex": b"x",
            "compiled.pdf": b"%PDF-user-file",
        }),
        info={"verification": {"safe_to_export": False}},
        provenance={},
        terminal_status="source",
        attempt="source",
        main_path="main.tex",
    )
    with zipfile.ZipFile(io.BytesIO(bundled)) as archive:
        run = json.loads(archive.read("LATEXSTRUCT-RUN.json"))
    assert run["preview"] == {
        "state": "SOURCE_PREVIEW",
        "artifact": "main.tex",
        "compiled_pdf_included": False,
    }


def test_legacy_successful_compile_exports_as_source_preview_without_pdf():
    bundled = append_run_bundle(
        _archive({"main.tex": b"x"}),
        info={
            "verification": {
                "safe_to_export": True,
                "compile_after": {"available": True, "ok": True},
            }
        },
        provenance={},
        terminal_status="done",
        attempt="done",
        main_path="main.tex",
    )
    with zipfile.ZipFile(io.BytesIO(bundled)) as archive:
        run = json.loads(archive.read("LATEXSTRUCT-RUN.json"))
    assert run["preview"] == {
        "state": "SOURCE_PREVIEW",
        "artifact": "main.tex",
        "compiled_pdf_included": False,
    }


def test_hash_manifest_supports_unicode_filenames():
    bundled = append_run_bundle(
        _archive({"main.tex": b"x", "章节.tex": "正文".encode()}),
        info={"verification": {"safe_to_export": False}},
        provenance={},
        terminal_status="source",
        attempt="source",
        main_path="main.tex",
    )
    with zipfile.ZipFile(io.BytesIO(bundled)) as archive:
        manifest = archive.read("SHA256SUMS").decode("utf-8")
    assert f"{hashlib.sha256('正文'.encode()).hexdigest()}  章节.tex\n" in manifest


def test_hash_manifest_rejects_line_breaks_in_filenames():
    with pytest.raises(ValueError, match="cannot contain CR or LF"):
        append_run_bundle(
            _archive({"main.tex": b"x", "bad\nname.tex": b"unsafe"}),
            info={"verification": {"safe_to_export": False}},
            provenance={},
            terminal_status="source",
            attempt="source",
            main_path="main.tex",
        )


def test_compiled_preview_requires_hash_bound_archive_member():
    evidence = {
        "status": "COMPILED",
        "filename": preview_artifact_path("COMPILED", "0" * 64),
        "sha256": "0" * 64,
    }
    with pytest.raises(ValueError, match="recorded digest"):
        append_run_bundle(
            _archive({"main.tex": b"x", evidence["filename"]: b"%PDF-real"}),
            info={
                "verification": {
                    "compile_after": {"available": True, "ok": True},
                    "preview_artifact": evidence,
                }
            },
            provenance={},
            terminal_status="done",
            attempt="done",
            main_path="main.tex",
        )

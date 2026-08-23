# -*- coding: utf-8 -*-
"""Optional acceptance test using the user's real 17-page Sharp Bounds run.

The large PDF and historical run artifacts deliberately remain outside Git.
CI hosts without those exact files skip this test instead of substituting a
smaller synthetic document.
"""

from __future__ import annotations

import json

import pytest


pytest.importorskip("pymupdf")

from benchmark.sharp_bounds_audit_acceptance import (  # noqa: E402
    RealSharpBoundsPaths,
    run_acceptance,
)


def _real_paths_or_skip() -> RealSharpBoundsPaths:
    paths = RealSharpBoundsPaths.discover()
    missing = [str(path) for path in paths.required() if not path.is_file()]
    if missing:
        pytest.skip("real 17-page Sharp Bounds artifacts are not installed")
    return paths


def test_real_sharp_bounds_standard_bundle_preserves_truth() -> None:
    paths = _real_paths_or_skip()
    report = run_acceptance(paths)

    assert report["real_artifacts"]["source_pdf_pages"] == 17
    assert report["real_artifacts"]["source_pdf_byte_count"] == 263763
    assert report["real_artifacts"]["source_pdf_sha256"] == (
        "7c2514f15a8565cda741f385a51679790fec0f240f3c2458e7e0e64cecb01a8a"
    )
    assert report["source_pdf"]["selected_page_range"]["pages"] == list(range(1, 18))
    assert report["source_pdf_artifact"] == {
        "path": "inputs/source.pdf",
        "bytes_sha256": (
            "7c2514f15a8565cda741f385a51679790fec0f240f3c2458e7e0e64cecb01a8a"
        ),
        "byte_count": 263763,
    }
    assert report["source_run_status"] == "SUCCESS"
    assert report["verification_status"] == "VERIFIED"
    assert report["outline"] == {
        "accepted_count": 9,
        "rejected_count": 1,
        "unresolved_count": 0,
    }
    assert report["metrics"] == {
        "source_pages": 17,
        "selected_pages": list(range(1, 18)),
        "outline_total": 10,
        "outline_accepted": 9,
        "outline_rejected": 1,
        "outline_unresolved": 0,
        "compile_raw_status": "PARTIAL_COMPILED",
        "compile_current_status": "COMPILED",
    }
    assert report["stages"]["review"]["status"] == "SKIPPED"
    assert report["stages"]["review"]["canonical_artifact_id"] is None
    assert report["compile_input_bindings"] == {
        "current": {
            "manifest_sha256": (
                "a2462956e1410b5dec705c011d8b94c20ce1ce79cf4535d3075c96d6c2e406b0"
            ),
            "recorded_compile_input_sha256": (
                "a2462956e1410b5dec705c011d8b94c20ce1ce79cf4535d3075c96d6c2e406b0"
            ),
            "recomputed_manifest_sha256": (
                "a2462956e1410b5dec705c011d8b94c20ce1ce79cf4535d3075c96d6c2e406b0"
            ),
            "valid": True,
        },
        "raw": {
            "manifest_sha256": (
                "95db395145cc7888603ebadfec2162271aa70bb89fcb8db751548b5926d5537f"
            ),
            "recorded_compile_input_sha256": (
                "95db395145cc7888603ebadfec2162271aa70bb89fcb8db751548b5926d5537f"
            ),
            "recomputed_manifest_sha256": (
                "95db395145cc7888603ebadfec2162271aa70bb89fcb8db751548b5926d5537f"
            ),
            "valid": True,
        },
    }
    assert report["current_preview_binding_evidence"] == "audit/verification.json"
    current_qa = json.loads(paths.current_qa.read_text(encoding="utf-8"))
    # Historical QA did not persist the engine.  Preserve that uncertainty;
    # the fresh v1.2.7 acceptance override records the real LuaLaTeX engine.
    assert report["current_preview_engine"] == str(
        current_qa.get("compile_engine") or "unknown"
    )

    assert report["all_primary_artifacts_byte_identical"] is True
    assert report["raw_math_token_preserved"] is True
    assert report["current_math_token_preserved"] is True
    assert report["diff_math_token_preserved"] is True
    assert report["forbidden_tex_token_absent"] is True
    assert report["forbidden_token_absent_all_text_evidence"] is True
    assert report["absolute_path_leaks"] == []
    assert report["tex_content_gate_valid"] is True
    assert report["packaging_integrity_valid"] is (
        report["audit_package_status"] == "VALID"
    )
    assert report["prompt_references_existing_files_only"] is True
    assert report["prompt_missing_paths"] == []
    assert report["template_class_member"] is True
    assert report["template_license_member"] is True
    assert report["sha256sums"] == {
        "listed_count": report["sha256sums"]["expected_count"],
        "expected_count": report["sha256sums"]["expected_count"],
        "coverage": 1.0,
        "missing": [],
        "unexpected": [],
        "mismatches": [],
    }

    if report["real_artifacts"]["current_compile_log_present"]:
        assert report["packaging_status"] == "SUCCESS"
        assert report["audit_package_status"] == "VALID"
        assert "COMPILE_CURRENT_LOG" not in report["missing_expected_roles"]
    else:
        # The historical v1.2.5 run did not retain this log.  The v1.2.7
        # packager must report that evidence gap instead of fabricating one.
        assert report["packaging_status"] == "PARTIAL"
        assert report["audit_package_status"] == "INCOMPLETE"
        assert "COMPILE_CURRENT_LOG" in report["missing_expected_roles"]

    if report["real_artifacts"]["report_md_bound_to_current"]:
        assert "REPORT" not in report["missing_expected_roles"]
    else:
        # The available attachment explicitly identifies a v1.2.4,
        # UNVERIFIED result and must not be relabeled as the v1.2.5 report.
        assert "REPORT" in report["missing_expected_roles"]

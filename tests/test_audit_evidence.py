from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from latexstruct.core.audit_evidence import (
    build_metrics,
    build_outline_evidence,
    compile_input_manifest_sha256,
    issues_csv_bytes,
    outline_evidence_errors,
    project_dependency_path,
    structured_blockers,
    template_manifest,
    template_manifest_sha256,
)


ROOT = Path(__file__).resolve().parents[1]


def _sharp_truth() -> dict:
    return json.loads(
        (ROOT / "benchmark" / "sharp_bounds_audit_truth_v1.json").read_text(
            encoding="utf-8"
        )
    )


def test_sharp_bounds_real_outline_truth_is_9_accepted_and_1_rejected():
    truth = _sharp_truth()
    source_outline = [
        {key: item[key] for key in ("level", "title", "page")}
        for item in truth["outline"]
    ]
    current_tex = "\n".join(
        item["matched_command"]
        for item in truth["outline"]
        if item["status"] == "ACCEPTED"
    )
    rejected = [
        {
            "title": item["title"],
            "page": item["page"],
            "reason": item["reason"],
        }
        for item in truth["outline"]
        if item["status"] == "REJECTED"
    ]
    evidence = build_outline_evidence(
        source_outline,
        current_tex,
        {
            "ocr_structure": {
                "expected": truth["outline_accepted"],
                "matched": truth["outline_accepted"],
                "rejected_outline": rejected,
            }
        },
    )

    assert evidence is not None
    assert len(evidence["source_outline"]) == truth["outline_total"] == 10
    assert evidence["accepted_count"] == truth["outline_accepted"] == 9
    assert evidence["rejected_count"] == truth["outline_rejected"] == 1
    assert evidence["unresolved_count"] == truth["outline_unresolved"] == 0
    assert evidence["verification_consistency"]["consistent"] is True


def test_empty_outline_is_missing_evidence_not_an_empty_claim():
    assert build_outline_evidence([], r"\chapter{Introduction}", {}) is None


def test_outline_validator_rejects_empty_and_count_inconsistent_claims():
    assert outline_evidence_errors({"source_outline": []})
    truth = _sharp_truth()
    source_outline = [
        {key: item[key] for key in ("level", "title", "page")}
        for item in truth["outline"]
    ]
    current_tex = "\n".join(
        item["matched_command"]
        for item in truth["outline"]
        if item["status"] == "ACCEPTED"
    )
    evidence = build_outline_evidence(
        source_outline,
        current_tex,
        {
            "ocr_structure": {
                "expected": 9,
                "matched": 9,
                "rejected_outline": [truth["outline"][0]],
            }
        },
    )
    assert outline_evidence_errors(evidence) == []
    evidence["accepted_count"] = 8
    assert "does not match" in "; ".join(outline_evidence_errors(evidence))


def test_metrics_keep_pdf_total_separate_from_selected_pages():
    metrics = build_metrics(
        source_pdf={
            "page_count": 40,
            "selected_page_range": {"start": 4, "end": 6, "pages": [4, 5, 6]},
        },
        outline_evidence=None,
        verification={
            "compile_before": {"preview_status": "PARTIAL_COMPILED"},
            "compile_after": {"preview_status": "COMPILED"},
            "structure_decisions": {
                "formal_total": 3,
                "formal_wrapped": 2,
                "formal_residual_ids": ["c-3"],
            },
        },
        current_tex=r"\begin{proof}x\end{proof}\bibitem{a} A",
    )

    assert metrics["source_pages"] == 40
    assert metrics["selected_pages"] == [4, 5, 6]
    assert metrics["formal_residual"] == 1
    assert metrics["compile_raw_status"] == "PARTIAL_COMPILED"


def test_blockers_and_issues_csv_use_required_machine_columns():
    blockers = structured_blockers(
        [
            {
                "id": "residual-formal-items",
                "summary": "3 formal items remain",
                "candidate_ids": ["c-2", "c-13", "c-18"],
                "action": "repair boundaries",
                "acceptance": "formal_residual == 0",
            }
        ]
    )
    rows = list(csv.DictReader(io.StringIO(issues_csv_bytes(blockers).decode())))

    assert {row["candidate_id"] for row in rows} == {"c-2", "c-13", "c-18"}
    assert rows[0]["acceptance"] == "formal_residual == 0"
    assert set(rows[0]) == {
        "id",
        "severity",
        "module",
        "candidate_id",
        "source_page",
        "source_line",
        "expected",
        "actual",
        "evidence",
        "recommended_fix",
        "acceptance",
    }


def test_structured_blocker_keeps_explicit_evidence_and_source_location():
    blockers = structured_blockers([
        {
            "id": "residual-formal-items",
            "severity": "P0",
            "module": "structure",
            "summary": "one formal item remains",
            "candidate_ids": ["c-7"],
            "source_page": 9,
            "source_line": 314,
            "expected": "formal_residual == 0",
            "actual": "formal_residual == 1",
            "evidence": ["audit/report.md", "audit/decisions.json"],
        }
    ])
    rows = list(csv.DictReader(io.StringIO(issues_csv_bytes(blockers).decode())))
    assert blockers[0]["evidence"] == ["audit/report.md", "audit/decisions.json"]
    assert rows[0]["source_page"] == "9"
    assert rows[0]["source_line"] == "314"
    assert rows[0]["actual"] == "formal_residual == 1"


def test_compile_dependencies_have_stable_standard_subdirectories():
    assert project_dependency_path("elegantbook.cls") == (
        "project/class-style-assets/elegantbook.cls"
    )
    assert project_dependency_path("figures/a.png") == (
        "project/images/figures/a.png"
    )
    assert project_dependency_path("refs/main.bib") == (
        "project/bibliography/refs/main.bib"
    )
    assert project_dependency_path("chapters/one.tex") == (
        "project/subfiles/chapters/one.tex"
    )


def test_compile_and_template_manifest_hashes_are_independently_recomputable():
    compile_payload = {
        "schema": "latexstruct-compile-inputs-v1",
        "file_count": 1,
        "files": [{"path": "main.tex", "bytes": 4, "sha256": "a" * 64}],
    }
    claimed = compile_input_manifest_sha256(compile_payload)
    compile_payload["manifest_sha256"] = claimed
    assert compile_input_manifest_sha256(compile_payload) == claimed

    template_payload = template_manifest(
        template_id="elegantbook",
        template_version="4.5",
        assets=[{
            "path": "elegantbook.cls",
            "packaged_path": "project/class-style-assets/elegantbook.cls",
            "bytes_sha256": "b" * 64,
            "artifact_role": "PROJECT_FILE",
            "license_path": "project/LICENSES/ELEGANTBOOK-LICENSE.txt",
            "required_for_compile": True,
            "source": "vendored compile closure",
        }],
    )
    assert template_payload["assets"][0]["artifact_path"] == (
        "project/class-style-assets/elegantbook.cls"
    )
    assert template_payload["assets"][0]["role"] == "PROJECT_FILE"
    assert template_manifest_sha256(template_payload) == template_payload[
        "asset_manifest_sha256"
    ]

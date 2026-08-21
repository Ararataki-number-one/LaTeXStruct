from __future__ import annotations

import pytest

from latexstruct.core.ocr_quality import assess_ocr_quality, normalize_ocr_quality_profile


def _job(profile: str = "publication") -> dict:
    return {
        "status": "done",
        "quality_profile": profile,
        "_source_sha256": "c" * 64,
        "selected_pages": [3, 4],
        "pages": {
            3: {
                "status": "done",
                "attempts": 1,
                "image_size_pixels": [1200, 1800],
                "visual_input_sha256": "a" * 64,
                "quality_flags": [],
            },
            4: {
                "status": "done",
                "attempts": 2,
                "image_size_pixels": [1200, 1800],
                "visual_input_sha256": "b" * 64,
                "quality_flags": [{
                    "type": "relation_local_visual_evidence",
                    "status": "corrected_after_local_visual_retry",
                    "needs_review": False,
                }],
            },
        },
    }


def test_publication_profile_passes_workflow_but_never_claims_publication_accuracy():
    report = assess_ocr_quality(_job())

    assert report["status"] == "ready_for_structuring"
    assert report["page_gate_passed"] is True
    assert report["resource_gate_passed"] is None
    assert report["workflow_gate_passed"] is True
    assert report["publication_readiness"] == "not_established"
    assert report["accuracy_measurement"] == "not_performed"
    assert report["counts"]["local_evidence_pages"] == 1
    assert report["limitations"]


def test_publication_profile_blocks_low_confidence_review_and_missing_provenance():
    job = _job()
    job["pages"][3]["low_conf"] = True
    job["pages"][3]["needs_review"] = True
    job["pages"][4]["attempts"] = 0

    report = assess_ocr_quality(job)

    assert report["status"] == "blocked"
    assert report["page_gate_passed"] is False
    assert {item["code"] for item in report["blockers"]} == {
        "low_confidence", "needs_review", "provenance_missing",
    }
    assert report["pages"]["low_confidence"] == [3]
    assert report["pages"]["missing_provenance"] == [4]


def test_standard_profile_keeps_findings_as_visible_warnings():
    job = _job("standard")
    job["pages"][3]["low_conf"] = True
    job["pages"][3]["needs_review"] = True

    report = assess_ocr_quality(job)

    assert report["page_gate_passed"] is True
    assert report["workflow_gate_passed"] is True
    assert report["blockers"] == []
    assert {item["code"] for item in report["warnings"]} == {
        "low_confidence", "needs_review",
    }


def test_publication_requires_frozen_source_identity_but_standard_only_warns():
    publication = _job()
    publication["_source_sha256"] = ""
    standard = _job("standard")
    standard["_source_sha256"] = ""

    strict_report = assess_ocr_quality(publication)
    compatibility_report = assess_ocr_quality(standard)

    assert strict_report["page_gate_passed"] is False
    assert "source_provenance_missing" in {
        item["code"] for item in strict_report["blockers"]
    }
    assert compatibility_report["page_gate_passed"] is True
    assert "source_provenance_missing" in {
        item["code"] for item in compatibility_report["warnings"]
    }


def test_bundle_resource_failure_blocks_both_profiles():
    resources = {
        "assets": [{
            "path": "images/page_3_1.png",
            "format_matches_extension": False,
        }],
        "source_pages": [],
        "unresolved": ["images/page_4_1.png"],
        "errors": ["missing crop"],
    }

    report = assess_ocr_quality(_job("standard"), resources)

    assert report["resource_gate_passed"] is False
    assert report["workflow_gate_passed"] is False
    assert report["resources"]["assets"] == 1
    assert report["resources"]["unresolved"] == 1
    assert report["resources"]["errors"] == 1
    assert report["resources"]["format_mismatches"] == 1
    assert report["blockers"][0]["code"] == "resources_unresolved"


def test_incomplete_job_is_never_ready_and_profile_is_allowlisted():
    job = _job()
    job["status"] = "running"
    job["pages"][4]["status"] = "running"

    report = assess_ocr_quality(job)

    assert report["status"] == "running"
    assert report["page_gate_passed"] is False
    assert report["pages"]["failed_or_incomplete"] == [4]
    with pytest.raises(ValueError, match="standard.*publication"):
        normalize_ocr_quality_profile("publication; rm")


def test_publication_document_inventory_requires_matching_equation_and_footnote_evidence():
    job = _job()
    job["pages"][3].update({
        "equation_tag_regions": [
            {"evidence_id": "p3-equation-tag-1", "label_hint": "3"},
        ],
        "footnote_regions": [
            {"evidence_id": "p3-footnote-1", "marker_hint": "1"},
        ],
        "quality_flags": [
            {
                "type": "equation_tag_integrity_evidence",
                "status": "source_geometry_and_active_match",
                "evidence_id": "p3-equation-tag-1",
                "needs_review": False,
            },
            {
                "type": "footnote_structure_evidence",
                "status": "source_geometry_and_active_match",
                "evidence_id": "p3-footnote-1",
                "needs_review": False,
            },
        ],
    })

    report = assess_ocr_quality(job)

    assert report["page_gate_passed"] is True
    assert report["document_inventory"] == {
        "equation_tags": {
            "expected": 1,
            "verified": 1,
            "matched": True,
            "extractor_ok": True,
        },
        "footnotes": {"expected": 1, "verified": 1, "matched": True},
    }
    assert report["counts"]["equation_tags_verified"] == 1
    assert report["counts"]["footnotes_verified"] == 1


def test_publication_blocks_but_standard_warns_on_document_inventory_mismatch():
    publication = _job()
    publication["pages"][3]["equation_tag_regions"] = [
        {"evidence_id": "p3-equation-tag-1", "label_hint": "3"},
    ]
    publication["pages"][4]["footnote_regions"] = [
        {"evidence_id": "p4-footnote-1", "marker_hint": "2"},
    ]
    standard = _job("standard")
    standard["pages"][3]["equation_tag_regions"] = list(
        publication["pages"][3]["equation_tag_regions"]
    )
    standard["pages"][4]["footnote_regions"] = list(
        publication["pages"][4]["footnote_regions"]
    )

    strict_report = assess_ocr_quality(publication)
    compatibility_report = assess_ocr_quality(standard)

    assert strict_report["page_gate_passed"] is False
    assert {item["code"] for item in strict_report["blockers"]} == {
        "equation_tag_inventory_mismatch",
        "footnote_inventory_mismatch",
    }
    assert compatibility_report["page_gate_passed"] is True
    assert {item["code"] for item in compatibility_report["warnings"]} == {
        "equation_tag_inventory_mismatch",
        "footnote_inventory_mismatch",
    }


def test_publication_blocks_when_equation_tag_extractor_failed_before_empty_inventory():
    publication = _job()
    publication["pages"][3]["equation_tag_extraction_status"] = "error"
    standard = _job("standard")
    standard["pages"][3]["equation_tag_extraction_status"] = "error"

    strict_report = assess_ocr_quality(publication)
    compatibility_report = assess_ocr_quality(standard)

    assert strict_report["page_gate_passed"] is False
    assert {item["code"] for item in strict_report["blockers"]} == {
        "equation_tag_extractor_failed",
    }
    assert compatibility_report["page_gate_passed"] is True
    assert {item["code"] for item in compatibility_report["warnings"]} == {
        "equation_tag_extractor_failed",
    }


def test_publication_pdf_requires_successful_equation_inventory_status_on_done_pages():
    publication = _job()
    publication["source_type"] = "pdf"
    publication["pages"][3]["equation_tag_extraction_status"] = "ok"
    publication["pages"][4]["equation_tag_extraction_status"] = "pending"

    report = assess_ocr_quality(publication)

    assert report["page_gate_passed"] is False
    assert report["pages"]["equation_tag_extractor_failed"] == [4]

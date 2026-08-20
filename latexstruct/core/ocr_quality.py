# -*- coding: utf-8 -*-
"""Honest, fail-closed quality summaries for OCR jobs.

This module deliberately separates a workflow gate from a publication claim.
Passing the gate means that LaTeXStruct preserved the selected pages, recorded
visual provenance, and found no known page-level blocker.  It never means that
an independent accuracy audit has established publication readiness.
"""

from __future__ import annotations

import re
from typing import Any, Mapping

OCR_QUALITY_STANDARD = "standard"
OCR_QUALITY_PUBLICATION = "publication"
OCR_QUALITY_PROFILES = frozenset({OCR_QUALITY_STANDARD, OCR_QUALITY_PUBLICATION})


def normalize_ocr_quality_profile(value: str) -> str:
    """Return an allowlisted OCR quality profile or raise a user-facing error."""
    profile = str(value or OCR_QUALITY_STANDARD).strip().lower()
    if profile not in OCR_QUALITY_PROFILES:
        raise ValueError("OCR 工作流只能是 standard 或 publication")
    return profile


def _page_numbers(values: list[int]) -> list[int]:
    return sorted({int(value) for value in values})


def assess_ocr_quality(job: Mapping[str, Any], resources: Mapping[str, Any] | None = None) -> dict:
    """Build a bounded, JSON-safe OCR evidence report.

    ``resources`` is supplied only after the self-contained bundle has been
    assembled.  Live status therefore reports a page preflight, while bundle
    reports additionally prove whether every referenced local asset was saved.
    """
    profile = normalize_ocr_quality_profile(str(job.get("quality_profile") or "standard"))
    pages = job.get("pages") if isinstance(job.get("pages"), Mapping) else {}
    selected = [int(page) for page in (job.get("selected_pages") or pages.keys())]
    selected = _page_numbers(selected)

    done_pages: list[int] = []
    error_pages: list[int] = []
    low_confidence_pages: list[int] = []
    review_pages: list[int] = []
    missing_provenance_pages: list[int] = []
    quality_flag_count = 0
    local_evidence_pages: list[int] = []
    source_sha256 = str(job.get("_source_sha256") or "").lower()
    source_provenance_recorded = re.fullmatch(r"[0-9a-f]{64}", source_sha256) is not None

    for page_no in selected:
        page = pages.get(page_no, pages.get(str(page_no), {}))
        page = page if isinstance(page, Mapping) else {}
        status = str(page.get("status") or "pending")
        if status == "done":
            done_pages.append(page_no)
        else:
            error_pages.append(page_no)
        if bool(page.get("low_conf")):
            low_confidence_pages.append(page_no)
        flags = [flag for flag in (page.get("quality_flags") or []) if isinstance(flag, Mapping)]
        quality_flag_count += len(flags)
        if flags:
            local_evidence_pages.append(page_no)
        if bool(page.get("needs_review")) or any(bool(flag.get("needs_review")) for flag in flags):
            review_pages.append(page_no)
        if status == "done" and (
            int(page.get("attempts") or 0) < 1
            or len(page.get("image_size_pixels") or []) != 2
            or re.fullmatch(
                r"[0-9a-f]{64}", str(page.get("visual_input_sha256") or "").lower()
            ) is None
        ):
            missing_provenance_pages.append(page_no)

    status = str(job.get("status") or "")
    terminal_complete = bool(selected) and status == "done" and len(done_pages) == len(selected)
    blockers: list[dict] = []
    warnings: list[dict] = []

    if not terminal_complete:
        blockers.append({
            "code": "pages_incomplete",
            "message": "所选页面尚未全部成功转写",
            "pages": error_pages[:100],
        })

    strict_findings = (
        ("low_confidence", "仍有低置信页面", low_confidence_pages),
        ("needs_review", "仍有需要人工复核的页面", review_pages),
        ("provenance_missing", "部分完成页缺少完整视觉来源记录", missing_provenance_pages),
    )
    for code, message, page_numbers in strict_findings:
        if not page_numbers:
            continue
        target = blockers if profile == OCR_QUALITY_PUBLICATION else warnings
        target.append({"code": code, "message": message, "pages": page_numbers[:100]})

    if not source_provenance_recorded:
        target = blockers if profile == OCR_QUALITY_PUBLICATION else warnings
        target.append({
            "code": "source_provenance_missing",
            "message": "原始 OCR 输入缺少可核验的冻结哈希",
            "pages": [],
        })

    resource_gate_passed = None
    resource_summary = {
        "verified": resources is not None,
        "assets": 0,
        "source_pages": 0,
        "unresolved": 0,
        "errors": 0,
        "format_mismatches": 0,
    }
    if resources is not None:
        unresolved = [str(item) for item in (resources.get("unresolved") or []) if str(item)]
        resource_errors = [str(item) for item in (resources.get("errors") or []) if str(item)]
        format_mismatches = sum(
            1
            for item in (resources.get("assets") or [])
            if isinstance(item, Mapping)
            and item.get("format_matches_extension") is False
        )
        resource_summary.update({
            "assets": len(resources.get("assets") or []),
            "source_pages": len(resources.get("source_pages") or []),
            "unresolved": len(unresolved),
            "errors": len(resource_errors),
            "format_mismatches": format_mismatches,
        })
        resource_gate_passed = not unresolved and not resource_errors and not format_mismatches
        if not resource_gate_passed:
            blockers.append({
                "code": "resources_unresolved",
                "message": "存在未验证或未保存的局部图片资源",
                "count": len(unresolved) + len(resource_errors) + format_mismatches,
            })

    page_gate_passed = terminal_complete and not blockers
    if profile == OCR_QUALITY_STANDARD:
        # Standard mode keeps its compatibility promise: warnings remain
        # visible but do not turn a complete OCR snapshot into an error.
        page_gate_passed = terminal_complete and not any(
            item.get("code") in {"pages_incomplete", "resources_unresolved"}
            for item in blockers
        )
    workflow_gate_passed = page_gate_passed and resource_gate_passed is not False

    if not terminal_complete:
        report_status = "running" if status in {"starting", "running", "pausing", "paused"} else "blocked"
    elif not workflow_gate_passed:
        report_status = "blocked"
    elif resources is None:
        report_status = "ready_for_structuring"
    else:
        report_status = "evidence_complete"

    return {
        "schema_version": 1,
        "profile": profile,
        "status": report_status,
        "page_gate_passed": page_gate_passed,
        "resource_gate_passed": resource_gate_passed,
        "workflow_gate_passed": workflow_gate_passed,
        "publication_readiness": "not_established",
        "accuracy_measurement": "not_performed",
        "source": {
            "sha256_recorded": source_provenance_recorded,
        },
        "counts": {
            "selected_pages": len(selected),
            "completed_pages": len(done_pages),
            "failed_or_incomplete_pages": len(error_pages),
            "low_confidence_pages": len(low_confidence_pages),
            "needs_review_pages": len(review_pages),
            "missing_provenance_pages": len(missing_provenance_pages),
            "quality_flags": quality_flag_count,
            "local_evidence_pages": len(set(local_evidence_pages)),
        },
        "pages": {
            "failed_or_incomplete": error_pages[:100],
            "low_confidence": low_confidence_pages[:100],
            "needs_review": review_pages[:100],
            "missing_provenance": missing_provenance_pages[:100],
        },
        "resources": resource_summary,
        "blockers": blockers,
        "warnings": warnings,
        "limitations": [
            "流程门只检查已知错误、来源记录与资源完整性，不测量文字或数学语义准确率。",
            "达到出版水平仍需独立逐页对照、数学公式复核与最终 PDF 视觉验收。",
        ],
    }

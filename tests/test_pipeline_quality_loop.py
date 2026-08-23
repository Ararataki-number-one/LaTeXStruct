# -*- coding: utf-8 -*-
"""Core pipeline really compiles, renders, audits every page, and gates export."""

from __future__ import annotations

import hashlib
import re
from types import SimpleNamespace
from unittest.mock import patch

import pymupdf

from latexstruct.core.ai import AIConfig, LLMError
from latexstruct.core.full_review import FullDocumentReviewResult
from latexstruct.core.ocrstruct import encode_ocr_metadata
from latexstruct.core.patch import Decision
from latexstruct.core.pipeline import (
    IMAGE_TO_VISUAL_PDF_DERIVATION_ID,
    PDF_IDENTITY_VISUAL_DERIVATION_ID,
    VISUAL_SOURCE_PROVENANCE_SCHEMA,
    _merge_usage_summaries,
    run_pipeline,
)
from latexstruct.core.verify import verification_failures


SOURCE_TEX = "\n".join([
    r"\documentclass{article}",
    encode_ocr_metadata(
        [], "article", [1], False, equation_tag_evidence=[],
    ),
    r"\begin{document}",
    "% Page 1",
    "A short publication-quality reconstruction test page.",
    r"\end{document}",
])

TWO_FORMAL_ITEMS_TEX = "\n".join([
    r"\documentclass{article}",
    r"\begin{document}",
    "Theorem 1. Every red-blue colouring has a monochromatic edge.",
    "",
    "Lemma 2. Every complete graph has a vertex.",
    r"\end{document}",
])

PLAIN_TEX = "\n".join([
    r"\documentclass{article}",
    r"\begin{document}",
    "This document has no formal mathematical items.",
    r"\end{document}",
])


def _pdf(
    text: str,
    *,
    x: float,
    width: float = 595,
    height: float = 842,
) -> bytes:
    document = pymupdf.open()
    try:
        page = document.new_page(width=width, height=height)
        page.insert_text((x, 90), text, fontsize=11)
        return document.tobytes(garbage=4, deflate=True)
    finally:
        document.close()


def _multi_page_pdf(texts: list[str], *, x: float = 72) -> bytes:
    document = pymupdf.open()
    try:
        for text in texts:
            page = document.new_page(width=595, height=842)
            page.insert_text((x, 90), text, fontsize=11)
        return document.tobytes(garbage=4, deflate=True)
    finally:
        document.close()


def _pdf_source_provenance(source_pdf: bytes) -> dict:
    digest = hashlib.sha256(source_pdf).hexdigest()
    return {
        "schema": VISUAL_SOURCE_PROVENANCE_SCHEMA,
        "source_type": "pdf",
        "original_upload_bytes": len(source_pdf),
        "original_upload_sha256": digest,
        "visual_pdf_bytes": len(source_pdf),
        "visual_pdf_sha256": digest,
        "visual_pdf_is_derived": False,
        "derivation_id": PDF_IDENTITY_VISUAL_DERIVATION_ID,
    }


def _image_source_provenance(original_image: bytes, visual_pdf: bytes) -> dict:
    return {
        "schema": VISUAL_SOURCE_PROVENANCE_SCHEMA,
        "source_type": "image",
        "original_upload_bytes": len(original_image),
        "original_upload_sha256": hashlib.sha256(original_image).hexdigest(),
        "visual_pdf_bytes": len(visual_pdf),
        "visual_pdf_sha256": hashlib.sha256(visual_pdf).hexdigest(),
        "visual_pdf_is_derived": True,
        "derivation_id": IMAGE_TO_VISUAL_PDF_DERIVATION_ID,
    }


class FullAndVisualClient:
    def __init__(self, *, manual=False):
        self.cfg = SimpleNamespace(model="fake-visual")
        self.manual = manual
        self.visual_calls = 0

    def chat_json(self, _system, user):
        chunk_id = re.search(r"^chunk_id: (\S+)$", user, re.M).group(1)
        start = int(re.search(r"^inspected_start_line: (\d+)$", user, re.M).group(1))
        end = int(re.search(r"^inspected_end_line: (\d+)$", user, re.M).group(1))
        return {
            "chunk_id": chunk_id,
            "inspected_start_line": start,
            "inspected_end_line": end,
            "findings": [],
            "unlisted_formal_lines": [],
        }, {"total_tokens": 1}

    def chat_vision_json_bytes(self, _system, _user, _image, _schema=None):
        import json

        self.visual_calls += 1
        request = json.loads(_user)
        checked_codes = [
            item["code"]
            for item in request.get("deterministic_findings_to_close", [])
        ]
        if self.manual:
            return {
                "source_page": request["source_page"],
                "candidate_page": request["candidate_page"],
                "verdict": "manual",
                "reason": "formula content needs manual confirmation",
                "issues": [{
                    "inventory_id": "",
                    "problem": "formula",
                    "env": "",
                    "confidence": 0.99,
                    "evidence": "formula differs visibly",
                }],
                "checked_finding_codes": checked_codes,
            }, {"total_tokens": 2}
        return {
            "source_page": request["source_page"],
            "candidate_page": request["candidate_page"],
            "verdict": "ok",
            "reason": "all visible content is present",
            "issues": [],
            "checked_finding_codes": checked_codes,
        }, {"total_tokens": 2}


def _compiler(candidate_pdf: bytes, calls: list):
    document = pymupdf.open(stream=candidate_pdf, filetype="pdf")
    try:
        candidate_pages = int(document.page_count)
    finally:
        document.close()

    def fake_compile(text, **kwargs):
        calls.append((text, dict(kwargs)))
        payload = candidate_pdf if kwargs.get("include_pdf") else b""
        return {
            "available": True,
            "ok": True,
            "pages": candidate_pages,
            "page_count": candidate_pages,
            "errors": [],
            "log": "compiled",
            "preview_status": "COMPILED",
            "pdf_sha256": hashlib.sha256(candidate_pdf).hexdigest(),
            "pdf_bytes": payload,
            "passes_attempted": 2,
            "exit_code": 0,
        }

    return fake_compile


def _clean_full_review_result(*, decisions=(), reviewed_candidate_ids=()):
    return FullDocumentReviewResult(
        ok=True,
        checked=True,
        decisions=list(decisions),
        reviewed_candidate_ids=list(reviewed_candidate_ids),
        invalid=[],
        escalations=[],
        inventory={"counts": {}},
    )


def test_visual_usage_summaries_accumulate_rounds_without_extra_calls():
    first = {
        "model": "vision-model",
        "calls": 2,
        "prompt_tokens": 20,
        "completion_tokens": 4,
        "estimated_cost_cny": 0.12,
        "pricing_source": "test-pricing",
    }
    second = {
        "model": "vision-model",
        "calls": 3,
        "prompt_tokens": 30,
        "completion_tokens": 6,
        "estimated_cost_cny": 0.18,
        "billing_mode": "chatgpt_subscription",
    }

    merged = _merge_usage_summaries(first, second)

    assert merged == {
        "model": "vision-model",
        "calls": 5,
        "prompt_tokens": 50,
        "completion_tokens": 10,
        "estimated_cost_cny": 0.3,
        "pricing_source": "test-pricing",
        "billing_mode": "chatgpt_subscription",
    }
    assert first["calls"] == 2


def test_pipeline_quality_loop_reuses_final_compile_and_records_page_audit():
    source_pdf = _pdf("A short publication-quality reconstruction test page.", x=72)
    candidate_pdf = _pdf("A short publication-quality reconstruction test page.", x=92)
    calls = []
    client = FullAndVisualClient()
    with patch(
        "latexstruct.core.compilecheck.compile_latex",
        side_effect=_compiler(candidate_pdf, calls),
    ):
        result = run_pipeline(
            SOURCE_TEX,
            mode="ai",
            ai_config=AIConfig(review_enabled=False),
            review_client=client,
            visual_client=client,
            source_pdf_bytes=source_pdf,
            source_pdf_page_range=(1, 1),
            source_visual_provenance=_pdf_source_provenance(source_pdf),
            quality_loop=True,
        )

    assert result.ok is True, result.report_md
    assert result.compiled_pdf == candidate_pdf
    assert client.visual_calls == 1
    # One candidate compile belongs to the loop; the later audit compile phase
    # only compiles the before snapshot and reuses the immutable final artifact.
    assert len(calls) == 2
    loop = result.verification["visual_quality_loop"]
    assert loop["checked"] is True and loop["ok"] is True
    assert loop["rounds"][0]["ai_audit"]["page_count"] == 1
    assert result.verification["ai_usage"]["visual_review"]["calls"] == 1
    assert result.verification["ai_usage"]["visual_review"]["total_tokens"] == 2
    provenance = result.verification["source_visual_provenance"]
    assert provenance == {
        **_pdf_source_provenance(source_pdf),
        "checked": True,
        "ok": True,
        "issues": [],
    }
    assert "原始上传与视觉 PDF 证据链" in result.report_md
    assert hashlib.sha256(source_pdf).hexdigest() in result.report_md
    check = next(
        item for item in result.verification["checks"]
        if item["id"] == "compile-render-visual-repair"
    )
    assert check == {
        "id": "compile-render-visual-repair",
        "label": "真实编译、逐页视觉复核与定点修复闭环",
        "ok": True,
        "skipped": False,
    }


def test_pipeline_preserves_failed_visual_transport_usage_in_verification():
    source_pdf = _pdf("A short publication-quality reconstruction test page.", x=72)
    candidate_pdf = _pdf("A short publication-quality reconstruction test page.", x=92)
    calls = []

    class FailedVisualClient(FullAndVisualClient):
        def __init__(self):
            super().__init__()
            self.last_usage = {}

        def chat_vision_json_bytes(self, *_args, **_kwargs):
            self.visual_calls += 1
            self.last_usage = {"total_tokens": 9}
            raise LLMError("未配置 API Key")

    client = FailedVisualClient()
    with patch(
        "latexstruct.core.compilecheck.compile_latex",
        side_effect=_compiler(candidate_pdf, calls),
    ):
        result = run_pipeline(
            SOURCE_TEX,
            mode="ai",
            ai_config=AIConfig(review_enabled=False),
            review_client=client,
            visual_client=client,
            source_pdf_bytes=source_pdf,
            source_pdf_page_range=(1, 1),
            source_visual_provenance=_pdf_source_provenance(source_pdf),
            quality_loop=True,
        )

    assert result.ok is False
    assert client.visual_calls == 1
    visual_usage = result.verification["ai_usage"]["visual_review"]
    assert visual_usage["calls"] == 1
    assert visual_usage["total_tokens"] == 9
    loop = result.verification["visual_quality_loop"]
    assert any("API Key" in item["reason"] for item in loop["unresolved"])
    assert loop["rounds"][0]["ai_audit"]["usage"] == visual_usage


def test_pipeline_fails_closed_when_visual_pdf_provenance_hash_is_tampered():
    source_pdf = _pdf("Immutable visual source.", x=72)
    candidate_pdf = _pdf("Immutable visual source.", x=92)
    provenance = _pdf_source_provenance(source_pdf)
    provenance["visual_pdf_sha256"] = "0" * 64
    client = FullAndVisualClient()
    with patch(
        "latexstruct.core.compilecheck.compile_latex",
        side_effect=_compiler(candidate_pdf, []),
    ):
        result = run_pipeline(
            SOURCE_TEX,
            mode="ai",
            ai_config=AIConfig(review_enabled=False),
            review_client=client,
            visual_client=client,
            source_pdf_bytes=source_pdf,
            source_pdf_page_range=(1, 1),
            source_visual_provenance=provenance,
            quality_loop=True,
        )

    assert result.ok is False
    record = result.verification["source_visual_provenance"]
    assert record["ok"] is False
    assert record["visual_pdf_sha256"] == hashlib.sha256(source_pdf).hexdigest()
    assert "记录的视觉 PDF SHA-256" in record["issues"][0]
    check = next(
        item for item in result.verification["checks"]
        if item["id"] == "source-visual-provenance"
    )
    assert check["ok"] is False and check["skipped"] is False
    assert "来源哈希或派生关系不完整" in result.report_md
    failure = next(
        item for item in verification_failures(result.verification)
        if item["id"] == "source-visual-provenance"
    )
    assert "记录的视觉 PDF SHA-256" in failure["summary"]
    assert "冻结的原始 OCR 上传" in failure["action"]


def test_image_wrapper_size_difference_reaches_ai_page_review():
    source_visual_pdf = _pdf(
        "A short publication-quality reconstruction test page.",
        x=24,
        width=240,
        height=320,
    )
    candidate_pdf = _pdf(
        "A short publication-quality reconstruction test page.",
        x=92,
    )
    original_image = b"\x89PNG\r\n\x1a\nimmutable-raster-upload"
    client = FullAndVisualClient()
    with patch(
        "latexstruct.core.compilecheck.compile_latex",
        side_effect=_compiler(candidate_pdf, []),
    ):
        result = run_pipeline(
            SOURCE_TEX,
            mode="ai",
            ai_config=AIConfig(review_enabled=False),
            review_client=client,
            visual_client=client,
            source_pdf_bytes=source_visual_pdf,
            source_pdf_page_range=(1, 1),
            source_visual_provenance=_image_source_provenance(
                original_image,
                source_visual_pdf,
            ),
            quality_loop=True,
        )

    assert result.ok is True, result.report_md
    assert client.visual_calls == 1
    deterministic = result.verification["visual_quality_loop"]["rounds"][0][
        "deterministic"
    ]
    assert deterministic["status"] == "REVIEW"
    assert deterministic["aggregate_metrics"]["source_geometry_authoritative"] is False
    codes = {
        finding["code"]
        for page in deterministic["pages"]
        for finding in page["findings"]
    }
    assert "SOURCE_PAGE_SIZE_NON_AUTHORITATIVE" in codes
    assert result.verification["visual_quality_loop"]["rounds"][0]["ai_audit"][
        "checked"
    ] is True


def test_explicit_layout_template_routes_pdf_size_change_to_page_review():
    source_pdf = _pdf(
        "A source page whose original stock size is not the requested template.",
        x=24,
        width=240,
        height=320,
    )
    candidate_pdf = _pdf(
        "A source page whose original stock size is not the requested template.",
        x=92,
    )
    client = FullAndVisualClient()
    with patch(
        "latexstruct.core.compilecheck.compile_latex",
        side_effect=_compiler(candidate_pdf, []),
    ):
        result = run_pipeline(
            SOURCE_TEX,
            mode="ai",
            template="elegantbook",
            ai_config=AIConfig(review_enabled=False),
            review_client=client,
            visual_client=client,
            source_pdf_bytes=source_pdf,
            source_pdf_page_range=(1, 1),
            source_visual_provenance=_pdf_source_provenance(source_pdf),
            quality_loop=True,
        )

    assert result.ok is True, result.report_md
    assert client.visual_calls == 1
    assert (
        result.verification["visual_quality_loop"]["geometry_policy"]
        == "template_reflow"
    )
    deterministic = result.verification["visual_quality_loop"]["rounds"][0][
        "deterministic"
    ]
    assert deterministic["status"] == "REVIEW"
    assert deterministic["aggregate_metrics"]["source_geometry_authoritative"] is False
    codes = {
        finding["code"]
        for page in deterministic["pages"]
        for finding in page["findings"]
    }
    assert "TEMPLATE_REFLOW_PAGE_SIZE" in codes


def test_layout_template_allows_and_reviews_a_new_toc_page():
    source_pdf = _pdf(
        "A short publication-quality reconstruction test page.",
        x=72,
    )
    candidate_pdf = _multi_page_pdf([
        "Contents: reconstruction test page",
        "A short publication-quality reconstruction test page.",
    ], x=92)
    client = FullAndVisualClient()
    with patch(
        "latexstruct.core.compilecheck.compile_latex",
        side_effect=_compiler(candidate_pdf, []),
    ):
        result = run_pipeline(
            SOURCE_TEX,
            mode="ai",
            template="elegantbook",
            ai_config=AIConfig(review_enabled=False),
            review_client=client,
            visual_client=client,
            source_pdf_bytes=source_pdf,
            source_pdf_page_range=(1, 1),
            source_visual_provenance=_pdf_source_provenance(source_pdf),
            quality_loop=True,
        )

    assert result.ok is True, result.report_md
    assert client.visual_calls == 2
    loop = result.verification["visual_quality_loop"]
    assert loop["candidate_scope"] == "reflow"
    deterministic = loop["rounds"][0]["deterministic"]
    assert deterministic["candidate_page_count"] == 2
    assert deterministic["compared_page_count"] == 2
    assert {
        page["candidate_page"] for page in deterministic["pages"]
    } == {1, 2}
    assert "EXTRA_CANDIDATE_PAGES" not in {
        finding["code"] for finding in deterministic["findings"]
    }
    assert loop["rounds"][0]["ai_audit"]["alignment_sha256"] == (
        deterministic["page_alignment"]["mapping_sha256"]
    )


def test_pdf_size_change_without_reflow_policy_remains_a_hard_failure():
    source_pdf = _pdf("Strict source geometry.", x=24, width=240, height=320)
    candidate_pdf = _pdf("Strict source geometry.", x=92)
    client = FullAndVisualClient()
    with patch(
        "latexstruct.core.compilecheck.compile_latex",
        side_effect=_compiler(candidate_pdf, []),
    ):
        result = run_pipeline(
            SOURCE_TEX,
            mode="ai",
            ai_config=AIConfig(review_enabled=False),
            review_client=client,
            visual_client=client,
            source_pdf_bytes=source_pdf,
            source_pdf_page_range=(1, 1),
            source_visual_provenance=_pdf_source_provenance(source_pdf),
            quality_loop=True,
        )

    assert result.ok is False
    assert client.visual_calls == 0
    loop = result.verification["visual_quality_loop"]
    assert loop["geometry_policy"] == "strict_source"
    deterministic = loop["rounds"][0]["deterministic"]
    assert deterministic["status"] == "FAIL"
    assert deterministic["aggregate_metrics"]["source_geometry_authoritative"] is True
    codes = {
        finding["code"]
        for page in deterministic["pages"]
        for finding in page["findings"]
    }
    assert "PAGE_SIZE_MISMATCH" in codes


def test_pipeline_selected_range_rejects_full_source_candidate_before_ai_audit():
    source_pdf = _multi_page_pdf([
        "source page one",
        "source page two selected",
        "source page three",
    ])
    candidate_pdf = _multi_page_pdf([
        "candidate page one",
        "candidate page two",
        "candidate page three",
    ], x=92)
    client = FullAndVisualClient()
    with patch(
        "latexstruct.core.compilecheck.compile_latex",
        side_effect=_compiler(candidate_pdf, []),
    ):
        result = run_pipeline(
            SOURCE_TEX,
            mode="ai",
            ai_config=AIConfig(review_enabled=False),
            review_client=client,
            visual_client=client,
            source_pdf_bytes=source_pdf,
            source_pdf_page_range=(2, 2),
            source_visual_provenance=_pdf_source_provenance(source_pdf),
            quality_loop=True,
        )

    assert result.ok is False
    assert client.visual_calls == 0
    deterministic = result.verification["visual_quality_loop"]["rounds"][0][
        "deterministic"
    ]
    assert deterministic["status"] == "FAIL"
    assert deterministic["aggregate_metrics"]["candidate_scope"] == "selected_range"
    assert deterministic["aggregate_metrics"]["expected_candidate_page_count"] == 1
    codes = {finding["code"] for finding in deterministic["findings"]}
    assert "EXTRA_CANDIDATE_PAGES" in codes


def test_pipeline_quality_loop_blocks_unresolved_visual_formula_issue():
    source_pdf = _pdf("One mathematical formula must remain visible.", x=72)
    candidate_pdf = _pdf("One mathematical formula must remain visible.", x=92)
    calls = []
    client = FullAndVisualClient(manual=True)
    with patch(
        "latexstruct.core.compilecheck.compile_latex",
        side_effect=_compiler(candidate_pdf, calls),
    ):
        result = run_pipeline(
            SOURCE_TEX,
            mode="ai",
            ai_config=AIConfig(review_enabled=False),
            review_client=client,
            visual_client=client,
            source_pdf_bytes=source_pdf,
            source_visual_provenance=_pdf_source_provenance(source_pdf),
            quality_loop=True,
        )

    assert result.ok is False
    assert result.result == SOURCE_TEX
    loop = result.verification["visual_quality_loop"]
    assert loop["ok"] is False
    assert loop["unresolved"][0]["problem"] == "formula"


def test_core_ocr_quality_loop_cannot_skip_missing_source_pdf():
    client = FullAndVisualClient()
    result = run_pipeline(
        SOURCE_TEX,
        mode="ai",
        ai_config=AIConfig(review_enabled=False),
        review_client=client,
        visual_client=client,
        source_pdf_bytes=b"",
        quality_loop=False,
        ocr_project=True,
    )

    assert result.ok is False
    contract = result.verification["ocr_project_contract"]
    assert contract["required"] is True and contract["ok"] is False
    assert any("缺少不可变原始视觉输入" in issue for issue in contract["issues"])
    loop = result.verification["visual_quality_loop"]
    assert loop["required"] is True
    assert loop["checked"] is False
    assert "缺少不可变原始视觉输入" in loop["unresolved"][0]["reason"]
    check = next(
        item for item in result.verification["checks"]
        if item["id"] == "compile-render-visual-repair"
    )
    assert check["skipped"] is False


def test_structure_manual_required_counts_unique_candidate_ids():
    target = {}

    def fake_decide(_client, _doc, _ctx, candidates, *_args, **_kwargs):
        candidate = min(candidates, key=lambda item: item.span.start_line)
        target["id"] = candidate.id
        return [], [
            {
                "candidate_id": candidate.id,
                "line": candidate.span.start_line,
                "reason": "范围未通过边界门",
            },
            {
                "candidate_id": candidate.id,
                "line": candidate.span.start_line,
                "reason": "同一候选仍未形成环境",
            },
        ], [], {}

    client = FullAndVisualClient()
    with patch(
        "latexstruct.core.pipeline.decide_candidates",
        side_effect=fake_decide,
    ):
        result = run_pipeline(
            TWO_FORMAL_ITEMS_TEX,
            mode="ai",
            ai_config=AIConfig(review_enabled=False),
            ai_client=client,
        )

    structure = result.verification["structure_decisions"]
    assert structure["manual_required"] == 1
    assert structure["manual_candidate_ids"] == [target["id"]]
    assert len([
        item for item in result.ambiguous
        if item.get("candidate_id") == target["id"]
    ]) == 2


def test_explicit_ocr_project_cannot_hide_as_plain_tex_or_disable_visual_gate():
    """Immutable host kind outranks a missing OCR marker in the TEX payload."""
    source_pdf = _pdf("host-declared OCR source", x=72)
    client = FullAndVisualClient()

    result = run_pipeline(
        PLAIN_TEX,
        mode="ai",
        ai_config=AIConfig(review_enabled=False),
        review_client=client,
        visual_client=client,
        source_pdf_bytes=source_pdf,
        source_pdf_page_range=(1, 1),
        source_visual_provenance=_pdf_source_provenance(source_pdf),
        # A caller-provided False must not downgrade an AI OCR project.
        quality_loop=False,
        ocr_project=True,
    )

    assert result.ok is False
    assert result.result == PLAIN_TEX
    contract = result.verification["ocr_project_contract"]
    assert contract["required"] is True
    assert contract["explicit_ocr_project"] is True
    assert contract["metadata_present"] is False
    assert contract["source_evidence_present"] is True
    assert contract["ok"] is False
    assert "缺少有效" in contract["issues"][0]
    # Explicit OCR semantics enable the stronger body invariant even though
    # is_ocr_document(PLAIN_TEX) is false.
    assert result.verification["invariants"]["body_text"]["checked"] is True
    loop = result.verification["visual_quality_loop"]
    assert loop["required"] is True
    assert loop["checked"] is False
    assert loop["ok"] is False
    assert "metadata" in loop["unresolved"][0]["reason"]
    assert client.visual_calls == 0
    check = next(
        item for item in result.verification["checks"]
        if item["id"] == "ocr-project-contract"
    )
    assert check["ok"] is False and check["skipped"] is False
    failure = next(
        item for item in verification_failures(result.verification)
        if item["id"] == "ocr-project-contract"
    )
    assert "缺少有效" in failure["summary"]
    assert "不能把 OCR 项目改作普通 TEX" in failure["action"]


def test_ordinary_review_cannot_drop_authoritative_full_review_decision():
    """A later candidate review never owns IDs already settled by full review."""

    locked = {}

    def fake_decide(_client, _doc, _ctx, candidates, *_args, **_kwargs):
        ordered = sorted(candidates, key=lambda item: item.span.start_line)
        assert len(ordered) == 2
        second = ordered[1]
        return [Decision(
            candidate_id=second.id,
            action="wrap",
            env="lemma",
            body_span=(second.span.start_line, second.span.end_line),
            source="ai",
            reason="initial analysis",
            confidence=0.99,
        )], [], [], {}

    def fake_full_review(_client, _doc, _inventory, candidates_by_id, *_args, **_kwargs):
        first = min(candidates_by_id.values(), key=lambda item: item.span.start_line)
        locked["id"] = first.id
        decision = Decision(
            candidate_id=first.id,
            action="wrap",
            env="theorem",
            body_span=(first.span.start_line, first.span.end_line),
            source="full-review",
            reason="authoritative full-document decision",
            confidence=0.99,
        )
        return _clean_full_review_result(
            decisions=[decision],
            reviewed_candidate_ids=[first.id],
        )

    def fake_review(
        _client, _doc, _ctx, decisions, apply_decisions, _ambiguous,
        *_args, **_kwargs,
    ):
        # The ordinary review receives only IDs that it owns.  Its returned list
        # deliberately omits the full-review ID; the host must merge the locked
        # decision back into both previews and the final decision set.
        assert locked["id"] not in {item.candidate_id for item in decisions}
        out, applied, rejected, _dropped = apply_decisions(list(decisions))
        assert r"\begin{theorem}" in "\n".join(out)
        return {
            "out": out,
            "applied": applied,
            "rejected": rejected,
            "decisions": list(decisions),
            "invalid": [],
            "escalations": [],
            "usage": {},
            "preserved_candidate_ids": [],
            "preserved_findings": {},
        }

    client = FullAndVisualClient()
    with (
        patch("latexstruct.core.pipeline.decide_candidates", side_effect=fake_decide),
        patch(
            "latexstruct.core.full_review.run_full_document_review",
            side_effect=fake_full_review,
        ),
        patch("latexstruct.core.pipeline.run_review", side_effect=fake_review),
    ):
        result = run_pipeline(
            TWO_FORMAL_ITEMS_TEX,
            mode="ai",
            ai_config=AIConfig(review_enabled=True),
            ai_client=client,
            review_client=client,
            quality_loop=True,
        )

    assert result.ok is True, result.report_md
    assert r"\begin{theorem}" in result.result
    assert r"\begin{lemma}" in result.result
    assert sum(
        item.candidate_id == locked["id"] for item in result.decisions
    ) == 1
    final_gate = next(
        item for item in result.verification["checks"]
        if item["id"] == "final-formal-inventory"
    )
    assert final_gate["ok"] is True


def test_full_review_wrap_cannot_cross_the_next_formal_heading():
    """Full-document AI output is still subordinate to host span legalization."""

    target = {}

    def fake_decide(_client, _doc, _ctx, candidates, *_args, **_kwargs):
        return [
            Decision(
                candidate_id=item.id,
                action="none",
                source="ai",
                reason="initial conservative answer",
                confidence=0.9,
            )
            for item in candidates
        ], [], [], {}

    def fake_full_review(_client, _doc, _inventory, candidates_by_id, *_args, **_kwargs):
        first = min(candidates_by_id.values(), key=lambda item: item.span.start_line)
        target["id"] = first.id
        unsafe = Decision(
            candidate_id=first.id,
            action="wrap",
            env="theorem",
            # The requested range deliberately swallows the next Lemma heading.
            body_span=(first.span.start_line, 5),
            source="full-review",
            reason="maliciously over-wide full review span",
            confidence=0.99,
        )
        return _clean_full_review_result(
            decisions=[unsafe],
            reviewed_candidate_ids=[first.id],
        )

    client = FullAndVisualClient()
    with (
        patch("latexstruct.core.pipeline.decide_candidates", side_effect=fake_decide),
        patch(
            "latexstruct.core.full_review.run_full_document_review",
            side_effect=fake_full_review,
        ),
    ):
        result = run_pipeline(
            TWO_FORMAL_ITEMS_TEX,
            mode="ai",
            ai_config=AIConfig(review_enabled=True),
            ai_client=client,
            review_client=client,
            quality_loop=True,
        )

    assert result.ok is False
    assert result.result == TWO_FORMAL_ITEMS_TEX
    assert not any(
        patch_item.decision.candidate_id == target["id"]
        for patch_item in result.applied
    )
    blocker = next(
        item for item in result.ambiguous
        if item.get("candidate_id") == target["id"]
    )
    assert "跨越" in blocker["reason"] or "下一结构" in blocker["reason"]
    assert result.verification["safe_to_export"] is False


def test_cached_decisions_still_run_independent_full_review_when_enabled():
    calls = []

    def fake_full_review(*_args, **_kwargs):
        calls.append("full-review")
        return _clean_full_review_result()

    client = FullAndVisualClient()
    with patch(
        "latexstruct.core.full_review.run_full_document_review",
        side_effect=fake_full_review,
    ):
        result = run_pipeline(
            PLAIN_TEX,
            mode="ai",
            ai_config=AIConfig(review_enabled=True),
            review_client=client,
            decisions_override=[],
            quality_loop=True,
        )

    assert calls == ["full-review"]
    assert result.ok is True, result.report_md
    assert result.verification["decisions_reused"] is True
    assert result.verification["full_document_review"]["checked"] is True
    gate = next(
        item for item in result.verification["checks"]
        if item["id"] == "full-document-review"
    )
    assert gate == {
        "id": "full-document-review",
        "label": "独立复核覆盖全文与全部现有 formal 环境",
        "ok": True,
        "skipped": False,
    }


def test_review_opt_out_never_builds_or_calls_text_review_and_is_not_reported_checked():
    with (
        patch(
            "latexstruct.core.pipeline.build_text_client",
            side_effect=AssertionError("review client must not be constructed"),
        ) as build_client,
        patch(
            "latexstruct.core.full_review.run_full_document_review",
            side_effect=AssertionError("full review must not run"),
        ) as full_review,
        patch(
            "latexstruct.core.pipeline.run_review",
            side_effect=AssertionError("candidate review must not run"),
        ) as candidate_review,
    ):
        result = run_pipeline(
            PLAIN_TEX,
            mode="ai",
            ai_config=AIConfig(review_enabled=False),
            decisions_override=[],
            quality_loop=True,
        )

    assert result.ok is True, result.report_md
    build_client.assert_not_called()
    full_review.assert_not_called()
    candidate_review.assert_not_called()
    full = result.verification["full_document_review"]
    assert full["checked"] is False
    assert full["ok"] is False
    assert full["status"] == "USER_DISABLED"
    assert full["status_message"] == "用户未启用第二遍复查"
    assert "full_document_review" not in result.verification["ai_usage"]
    gate = next(
        item for item in result.verification["checks"]
        if item["id"] == "full-document-review"
    )
    assert gate["skipped"] is True
    assert gate["ok"] is None
    assert gate["skip_reason"] == "user-disabled"
    assert gate["reason"] == "用户未启用第二遍复查"
    final_inventory_gate = next(
        item for item in result.verification["checks"]
        if item["id"] == "final-formal-inventory"
    )
    assert final_inventory_gate["skipped"] is False
    assert final_inventory_gate["ok"] is True
    assert "用户未启用第二遍复查（不是检查通过）" in result.report_md
    assert "状态：通过；已逐段复核" not in result.report_md


def test_residual_final_inventory_finding_blocks_quality_export():
    from latexstruct.core import formal_inventory as formal_inventory_module

    real_inventory = formal_inventory_module.inventory_document
    calls = []

    class ResidualFinding:
        kind = "missing"

        @staticmethod
        def as_dict():
            return {
                "id": "final-residual",
                "kind": "missing",
                "line": 3,
                "reason": "synthetic residual used to prove the final gate",
            }

    class ResidualInventory:
        findings = (ResidualFinding(),)

        @staticmethod
        def as_dict():
            return {
                "counts": {"findings": 1},
                "findings": [ResidualFinding.as_dict()],
            }

    def inventory_with_final_residual(document, structured_envs=()):
        calls.append("inventory")
        # scanner.scan() and the pipeline's immutable input inventory each run
        # once before the post-repair inventory gate.
        if len(calls) <= 2:
            return real_inventory(document, structured_envs=structured_envs)
        return ResidualInventory()

    client = FullAndVisualClient()
    with (
        patch(
            "latexstruct.core.formal_inventory.inventory_document",
            side_effect=inventory_with_final_residual,
        ),
        patch(
            "latexstruct.core.full_review.run_full_document_review",
            side_effect=AssertionError("disabled review must not run"),
        ),
    ):
        result = run_pipeline(
            PLAIN_TEX,
            mode="ai",
            ai_config=AIConfig(review_enabled=False),
            review_client=client,
            decisions_override=[],
            quality_loop=True,
        )

    assert calls == ["inventory", "inventory", "inventory"]
    assert result.ok is False
    assert result.result == PLAIN_TEX
    assert result.verification["safe_to_export"] is False
    assert result.verification["rolled_back"] is True
    gate = next(
        item for item in result.verification["checks"]
        if item["id"] == "final-formal-inventory"
    )
    assert gate["ok"] is False
    assert gate["blockers"] == 1

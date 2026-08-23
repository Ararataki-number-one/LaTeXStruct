# -*- coding: utf-8 -*-
"""User-facing v1.2.8 quality-loop report tests."""

from latexstruct.core.report import build_report


def _base_verification():
    invariant = {"equal": True, "before_count": 1, "after_count": 1}
    return {
        "safe_to_export": False,
        "checks": [],
        "content_invariant": True,
        "env_balance": {"ok": True, "after_unbalanced": []},
        "braces": {"ok": True},
        "invariants": {
            "math": dict(invariant),
            "labels": dict(invariant),
            "refs": dict(invariant),
            "cites": dict(invariant),
            "images": dict(invariant),
        },
        "display_tags": {"ok": True, "issues": []},
        "ocr_structure": {"checked": False, "ok": True},
        "resources": {"checked": False, "ok": True},
        "structure_decisions": {
            "formal_total": 0,
            "formal_wrapped": 0,
            "formal_residual_ids": [],
        },
        "known_issues": [],
    }


def test_report_explains_full_review_visual_rounds_and_final_inventory_blocker():
    verification = _base_verification()
    verification.update({
        "checks": [
            {
                "id": "full-document-review",
                "label": "独立复核覆盖全文与全部现有 formal 环境",
                "ok": True,
                "skipped": False,
            },
            {
                "id": "compile-render-visual-repair",
                "label": "真实编译、逐页视觉复核与定点修复闭环",
                "ok": False,
                "skipped": False,
            },
            {
                "id": "final-formal-inventory",
                "label": "最终 TEX formal 清点",
                "ok": False,
                "skipped": False,
            },
        ],
        "full_document_review": {
            "checked": True,
            "ok": True,
            "chunks": [{"id": "chunk-1"}, {"id": "chunk-2"}],
            "invalid": [],
            "escalations": [],
            "inventory": {
                "counts": {"anchors": 8, "environments": 5, "findings": 2},
            },
        },
        "ai_usage": {
            "full_document_review": {"model": "review-model", "total_tokens": 321},
        },
        "visual_quality_loop": {
            "required": True,
            "checked": False,
            "ok": False,
            "repair_count": 1,
            "invalid": [],
            "unresolved": [{"round": 2, "page": 7, "reason": "第 7 页底部截断"}],
            "rounds": [{
                "round": 1,
                "compile": {"ok": True, "preview_status": "COMPILED", "pages": 17},
                "deterministic": {"status": "REVIEW", "compared_page_count": 17},
                "ai_audit": {
                    "checked": True,
                    "page_count": 17,
                    "suggestions": [{"inventory_id": "a-1"}],
                    "unresolved": [],
                },
            }, {
                "round": 2,
                "compile": {"ok": False, "preview_status": "PARTIAL_COMPILED", "pages": 7},
                "deterministic": {},
                "ai_audit": {},
            }],
        },
        "final_formal_inventory": {
            "counts": {"anchors": 9, "environments": 8, "findings": 1},
            "findings": [{
                "kind": "wrong-env",
                "start_line": 88,
                "end_line": 90,
                "original_env": "lemma",
                "suggested_env": "theorem",
                "reason": "显式 Theorem 标题与 lemma 环境冲突",
            }],
        },
    })

    report = build_report([], [], [], verification, "ai")

    assert "全文独立结构复核" in report
    assert "已逐段复核 2 个全文分段" in report
    assert "formal 标题 8；既有环境 5；初始发现 2" in report
    assert "真实编译与逐页视觉质量闭环" in report
    assert "运行轮次：2；已执行可逆定点修复 1 项" in report
    assert "第 1 轮真实编译：成功（17 页，COMPILED）" in report
    assert "第 2 轮真实编译：未得到完整 COMPILED PDF" in report
    assert "源 PDF 第 7 页：第 7 页底部截断" in report
    assert "最终 formal 结构清单" in report
    assert "发现 1；阻断项 1" in report
    assert "第 88–90 行：环境类型不符（lemma → theorem）" in report


def test_report_calls_skipped_quality_stages_not_run_instead_of_passed():
    verification = _base_verification()
    verification.update({
        "checks": [
            {
                "id": "full-document-review",
                "label": "全文复核",
                "ok": True,
                "skipped": True,
            },
            {
                "id": "compile-render-visual-repair",
                "label": "视觉闭环",
                "ok": True,
                "skipped": True,
            },
            {
                "id": "final-formal-inventory",
                "label": "最终清点",
                "ok": True,
                "skipped": True,
            },
        ],
        "full_document_review": {"checked": False, "ok": True},
        "visual_quality_loop": {"required": False, "checked": False, "ok": True},
        "final_formal_inventory": {
            "counts": {"anchors": 0, "environments": 0, "findings": 0},
            "findings": [],
        },
    })

    report = build_report([], [], [], verification, "rule")

    assert "本次工作流未要求出版级全文复核（不是检查通过）" in report
    assert "本次工作流未要求逐页视觉闭环（不是视觉检查通过）" in report
    assert "本次未启用出版级最终清点门；下列库存仅供诊断" in report
    assert "未验证原因：最终导出门禁未明确通过" in report
    assert "阻断项：0" not in report


def test_report_distinguishes_uploaded_image_from_derived_visual_pdf():
    verification = _base_verification()
    verification.update({
        "checks": [{
            "id": "compile-render-visual-repair",
            "label": "视觉闭环",
            "ok": False,
            "skipped": False,
        }],
        "source_visual_provenance": {
            "checked": True,
            "ok": True,
            "source_type": "image",
            "original_upload_bytes": 123,
            "original_upload_sha256": "a" * 64,
            "visual_pdf_bytes": 456,
            "visual_pdf_sha256": "b" * 64,
            "visual_pdf_is_derived": True,
            "derivation_id": "latexstruct.raster-image-to-single-page-visual-pdf.v1",
            "issues": [],
        },
        "visual_quality_loop": {
            "required": True,
            "checked": False,
            "ok": False,
            "rounds": [],
            "repair_count": 0,
            "invalid": [],
            "unresolved": [{"page": 1, "reason": "页面底部被截断"}],
        },
    })

    report = build_report([], [], [], verification, "ai")

    assert "原始上传与视觉 PDF 证据链" in report
    assert "原始上传类型：`IMAGE`" in report
    assert "不是用户上传的 PDF，也不是 LaTeX 编译产物" in report
    assert "原始图片（视觉页 1）：页面底部被截断" in report
    assert "源 PDF 第 1 页" not in report

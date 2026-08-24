import assert from "node:assert/strict";
import test from "node:test";

import {
  buildOcrArtifacts,
  buildOcrProgress,
  buildOcrRecoveryPresentation,
  legacyOcrQualityProfile,
  normalizeOcrQualityTier,
  ocrPagePresentation,
} from "../src/ocrPresentation.js";

test("three plain-language OCR tiers keep legacy backend compatibility", () => {
  assert.equal(normalizeOcrQualityTier("recommended"), "recommended");
  assert.equal(normalizeOcrQualityTier("high"), "high");
  assert.equal(normalizeOcrQualityTier("", "standard"), "fast");
  assert.equal(normalizeOcrQualityTier("", "publication"), "recommended");
  assert.equal(legacyOcrQualityProfile("fast"), "standard");
  assert.equal(legacyOcrQualityProfile("recommended"), "standard");
  assert.equal(legacyOcrQualityProfile("high"), "publication");
});

test("OCR progress prefers host metrics and never counts pending pages as success", () => {
  const progress = buildOcrProgress({
    status: "running",
    total: 6,
    progress_metrics: {
      success_pages: 2,
      auto_retry_pages: 1,
      needs_review_pages: 1,
      failed_pages: 0,
      current_pages: [4, 5],
      average_pages_per_minute: 18.5,
      recent_pages_per_minute: 20,
      eta_seconds: 90,
      current_concurrency: 2,
      current_dpi: 300,
    },
    pages: {
      1: { status: "SUCCESS" },
      2: { status: "done" },
      3: { status: "NEEDS_REVIEW" },
      4: { status: "OCR_RUNNING" },
      5: { status: "RETRYING", retry_count: 1 },
      6: { status: "PENDING" },
    },
  });
  assert.equal(progress.success, 2);
  assert.equal(progress.needsReview, 1);
  assert.equal(progress.retryPages, 1);
  assert.deepEqual(progress.currentPages, [4, 5]);
  assert.equal(progress.pending, 1);
  assert.equal(progress.averageRate, 18.5);
  assert.equal(progress.etaSeconds, 90);
});

test("failed terminal pages do not override the host recognition progress", () => {
  const pages = Object.fromEntries(Array.from({ length: 37 }, (_, index) => [
    index + 1,
    { final_status: index < 3 ? "SUCCESS" : "FAILED" },
  ]));
  const progress = buildOcrProgress({
    status: "partial",
    total: 37,
    progress_metrics: {
      total_pages: 37,
      success_pages: 3,
      failed_pages: 34,
      progress: 0.091351,
    },
    pages,
  });

  assert.equal(progress.completed, 37);
  assert.equal(progress.success, 3);
  assert.equal(progress.failed, 34);
  assert.equal(progress.progress, 0.091351);
});

test("new and legacy page states share one user-facing status", () => {
  assert.equal(ocrPagePresentation({ status: "SUCCESS" }).label, "成功");
  assert.equal(ocrPagePresentation({ status: "done", low_conf: true }).label, "待确认");
  assert.equal(ocrPagePresentation({ status: "FAILED" }).failed, true);
  assert.equal(ocrPagePresentation({ status: "pending" }).pending, true);
});

test("OCR artifacts use new URLs while preserving the legacy raw TEX endpoint", () => {
  const modern = buildOcrArtifacts({
    id: "abc",
    status: "done",
    artifacts: {
      source_pdf: { url: "/source" },
      raw_ocr_tex: { url: "/raw" },
      baseline_tex: { url: "/baseline.tex" },
      baseline_pdf: { url: "/baseline.pdf", status: "COMPILED" },
    },
  });
  assert.equal(modern.source.url, "/source");
  assert.equal(modern.compileStatus, "COMPILED");

  const legacy = buildOcrArtifacts({ id: "legacy", status: "partial", raw_revision: 2 });
  assert.equal(legacy.raw.available, true);
  assert.equal(legacy.raw.url, "/api/ocr/jobs/legacy/result");
  assert.equal(legacy.baselinePdf.available, false);
});

test("restart recovery counts PENDING records even when stale metrics say zero", () => {
  const progress = buildOcrProgress({
    status: "partial",
    total: 2,
    progress: 0,
    progress_metrics: {
      total_pages: 2,
      success_pages: 1,
      pending_pages: 0,
      failed_pages: 0,
      active_pages: 0,
      progress: 0,
    },
    pages: {
      1: { status: "done", final_status: "SUCCESS" },
      2: { status: "pending", final_status: "PENDING" },
    },
  });
  assert.equal(progress.success, 1);
  assert.equal(progress.pending, 1);
  assert.equal(progress.failed, 0);
  assert.equal(progress.progress, 0.5);
});

test("restart recovery offers one explicit resume action and never claims completion", () => {
  const presentation = buildOcrRecoveryPresentation({
    status: "partial",
    can_resume: true,
    total: 3,
    progress_metrics: {
      total_pages: 3,
      success_pages: 1,
      pending_pages: 0,
      failed_pages: 1,
    },
    pages: {
      7: { source_page: 7, status: "done", final_status: "SUCCESS" },
      8: { source_page: 8, status: "pending", final_status: "PENDING", can_retry: false },
      9: { source_page: 9, status: "error", final_status: "FAILED", can_retry: false },
    },
  });
  assert.equal(presentation.complete, false);
  assert.equal(presentation.canResumeIncomplete, true);
  assert.equal(presentation.incompleteCount, 2);
  assert.deepEqual(presentation.incompletePageNumbers, [8, 9]);
  assert.equal(presentation.statusLabel, "未完成，可继续");
  assert.match(presentation.title, /尚未完成/);
  assert.equal(presentation.actionLabel, "继续未完成页面（2）");
});

test("review-only terminal state remains below 100% and offers targeted retry", () => {
  const presentation = buildOcrRecoveryPresentation({
    status: "partial",
    raw_frozen: false,
    total: 1,
    progress_metrics: { progress: 0.9, needs_review_pages: 1 },
    pages: {
      1: {
        status: "done",
        final_status: "NEEDS_REVIEW",
        needs_review: true,
        can_retry: true,
      },
    },
  });
  assert.equal(presentation.incompleteCount, 0);
  assert.equal(presentation.canResumeIncomplete, false);
  assert.equal(presentation.canRetryReview, true);
  assert.equal(presentation.statusLabel, "已完成，待确认");
  assert.match(presentation.title, /1 页待确认/);
  assert.match(presentation.detail, /只重试待确认页/);
  assert.equal(buildOcrProgress({
    status: "done",
    total: 1,
    progress_metrics: { progress: 0.9, needs_review_pages: 1 },
    pages: { 1: { final_status: "NEEDS_REVIEW", needs_review: true } },
  }).progress, 0.9);
});

test("active OCR keeps its running label instead of being presented as a terminal failure", () => {
  const presentation = buildOcrRecoveryPresentation({
    status: "running",
    total: 2,
    pages: {
      1: { status: "OCR_RUNNING" },
      2: { status: "PENDING" },
    },
  });
  assert.equal(presentation.incompleteCount, 2);
  assert.equal(presentation.statusLabel, "");
  assert.equal(presentation.title, "");
});

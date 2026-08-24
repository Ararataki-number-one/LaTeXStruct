import assert from "node:assert/strict";
import test from "node:test";

import {
  buildOcrArtifacts,
  buildOcrEstimate,
  buildOcrProgress,
  buildOcrRecoveryPresentation,
  formatOcrCost,
  formatOcrInteger,
  legacyOcrQualityProfile,
  normalizeOcrQualityTier,
  openOcrProjectWithoutAnalysis,
  ocrStrategyLabel,
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

test("start estimate uses only backend ranges and never invents zero for missing data", () => {
  const estimate = buildOcrEstimate({
    ocr_estimates: {
      recommended: {
        basis_pages: 37,
        calls: { min: 8, max: 12 },
        duration_seconds: [90, 180],
        cost: { min: 0.1, max: 0.2, currency: "USD" },
      },
    },
  }, 37, "recommended");
  assert.equal(estimate.callsText, "8–12 次");
  assert.equal(estimate.durationText, "1 分 30 秒–3 分 0 秒");
  assert.equal(estimate.costText, "$0.1–0.2");

  const missing = buildOcrEstimate({}, 37, "recommended");
  assert.equal(missing.callsText, "待后端评估");
  assert.equal(missing.durationText, "待后端评估");
  assert.equal(missing.costText, "无法估算");
  assert.doesNotMatch(`${missing.callsText}${missing.durationText}${missing.costText}`, /\b0\b/);

  const wrongSelection = buildOcrEstimate({
    estimate: { basis_pages: 600, calls: [100, 120] },
  }, 37, "recommended");
  assert.equal(wrongSelection.callsText, "待后端评估");
});

test("per-page estimates are scaled only when the backend explicitly marks them per page", () => {
  const estimate = buildOcrEstimate({
    estimate: {
      per_page: {
        calls: [0.2, 0.3],
        duration_seconds: [5, 8],
        cost: [0.001, 0.002],
      },
      currency: "CNY",
    },
  }, 10, "recommended");
  assert.equal(estimate.callsText, "2–3 次");
  assert.equal(estimate.durationText, "50 秒–1 分 20 秒");
  assert.equal(estimate.costText, "¥0.01–0.02");
});

test("nested measured metrics expose all runtime fields without turning missing values into zero", () => {
  const progress = buildOcrProgress({
    status: "running",
    progress_metrics: {
      current_pages: [11, 12],
      current_concurrency: 3,
      current_batch_size: 4,
      current_dpi: 160,
      rate_limited: false,
      current_strategy: "object_layer_verified",
    },
    performance_metrics: {
      elapsed_ms: 120000,
      pages: {
        selected: 37,
        coverage_completed: 10,
        by_final_status: { SUCCESS: 8, NEEDS_REVIEW: 1, FAILED: 1 },
      },
      throughput: {
        average_pages_per_minute: 5,
        recent_pages_per_minute: 6,
        eta_seconds: 324,
      },
      requests: { total: 7 },
      usage: {
        input_tokens: 1000,
        output_tokens: 250,
        cost: 0.125,
        currency: "USD",
        cost_coverage: { complete: true },
      },
    },
    cost_report: {
      measurement_coverage: {
        input_tokens: { complete: true },
        output_tokens: { complete: true },
        cost: { complete: true },
      },
    },
  });
  assert.equal(progress.selectedPages, 37);
  assert.equal(progress.completed, 10);
  assert.equal(progress.inFlight, 0);
  assert.equal(progress.failed, 1);
  assert.equal(progress.concurrency, 3);
  assert.equal(progress.batchSize, 4);
  assert.equal(progress.dpi, 160);
  assert.equal(progress.rateLimitStatus, "未限流");
  assert.equal(progress.totalTokens, 1250);
  assert.equal(progress.tokenCoverageComplete, true);
  assert.equal(progress.cost, 0.125);
  assert.equal(progress.costCoverageComplete, true);
  assert.equal(progress.strategyLabel, "对象层验证");
  assert.equal(progress.requestCount, 7);

  const unknown = buildOcrProgress({ status: "running" });
  assert.equal(unknown.concurrency, null);
  assert.equal(unknown.batchSize, null);
  assert.equal(unknown.totalTokens, null);
  assert.equal(unknown.cost, null);
  assert.equal(unknown.rateLimitStatus, "未知");
  assert.equal(unknown.strategyLabel, "未知");
  assert.equal(formatOcrInteger(unknown.totalTokens), "未知");
  assert.equal(formatOcrCost(unknown.cost), "未知");
  assert.equal(ocrStrategyLabel("crop_review"), "局部裁片识别");
});

test("final artifacts distinguish syntax baseline and evidence correction and retain failed compile status", () => {
  const artifacts = buildOcrArtifacts({
    status: "done",
    compile_status: "compile_failed",
    baseline_project_id: "project-123",
    artifacts: {
      raw_ocr_tex: { url: "/raw.tex" },
      baseline_tex: { url: "/baseline.tex" },
      evidence_corrected_tex: { url: "/corrected.tex" },
      baseline_pdf: { available: false, status: "COMPILE_FAILED" },
      baseline_project_zip: { url: "/baseline.zip" },
    },
  });
  assert.equal(artifacts.raw.label, "不可变 OCR 原稿 TEX");
  assert.equal(artifacts.baselineTex.label, "纯语法恢复 OCR 基线 TEX");
  assert.equal(artifacts.evidenceCorrectedTex.available, true);
  assert.equal(artifacts.baselineProject.url, "/baseline.zip");
  assert.equal(artifacts.compileStatus, "COMPILE_FAILED");
  assert.equal(artifacts.projectId, "project-123");
});

test("open project creates an OCR project through /open and never calls /import", async () => {
  const calls = [];
  const opened = [];
  const result = await openOcrProjectWithoutAnalysis({
    jobId: "ocr-job-123",
    request: async (url, options) => {
      calls.push({ url, options });
      return { json: async () => ({ id: "project-456", reused: false }) };
    },
    navigate: (projectId) => opened.push(projectId),
  });
  assert.deepEqual(calls, [{
    url: "/api/ocr/jobs/ocr-job-123/open",
    options: { method: "POST" },
  }]);
  assert.equal(calls.some(({ url }) => url.includes("/import")), false);
  assert.deepEqual(opened, ["project-456"]);
  assert.equal(result.id, "project-456");
});

test("open project navigates an existing project without making any API request", async () => {
  let requestCount = 0;
  const opened = [];
  const result = await openOcrProjectWithoutAnalysis({
    jobId: "ocr-job-123",
    existingProjectId: "project-existing",
    request: async () => {
      requestCount += 1;
      throw new Error("request must not run");
    },
    navigate: (projectId) => opened.push(projectId),
  });
  assert.equal(requestCount, 0);
  assert.deepEqual(opened, ["project-existing"]);
  assert.deepEqual(result, { id: "project-existing", reused: true });
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

test("cancelled OCR remains terminal but is never presented as completed", () => {
  const presentation = buildOcrRecoveryPresentation({
    status: "cancelled",
    total: 3,
    pages: {
      1: { source_page: 1, final_status: "SUCCESS" },
      2: { source_page: 2, final_status: "CANCELLED" },
      3: { source_page: 3, final_status: "PENDING" },
    },
  });
  assert.equal(presentation.complete, false);
  assert.equal(presentation.statusLabel, "已安全取消");
  assert.match(presentation.title, /OCR 已取消/);
  assert.match(presentation.detail, /不会显示为成功完成/);

  const artifacts = buildOcrArtifacts({ id: "cancelled", status: "cancelled", raw_revision: 1 });
  assert.equal(artifacts.raw.available, true);
});

export const OCR_QUALITY_TIERS = Object.freeze([
  {
    id: "fast",
    label: "快速",
    description: "优先吞吐量；问题页仍会自动单页重试。",
  },
  {
    id: "recommended",
    label: "推荐",
    description: "速度与数学保真平衡，问题页会自动提高清晰度。",
    recommended: true,
  },
  {
    id: "high",
    label: "高质量",
    description: "加强公式、脚注、双栏和疑难区域复核。",
  },
]);

const VALID_TIERS = new Set(OCR_QUALITY_TIERS.map((item) => item.id));
const TERMINAL_PAGE_STATES = new Set(["SUCCESS", "NEEDS_REVIEW", "FAILED", "CANCELLED", "DONE", "ERROR"]);
const SUCCESS_PAGE_STATES = new Set(["SUCCESS", "DONE"]);
const REVIEW_PAGE_STATES = new Set(["NEEDS_REVIEW"]);
const FAILED_PAGE_STATES = new Set(["FAILED", "ERROR"]);
const ACTIVE_PAGE_STATES = new Set(["RENDERING", "QUEUED", "OCR_RUNNING", "VALIDATING", "RETRYING", "RUNNING"]);

function finiteNumber(...values) {
  for (const value of values) {
    if (value === "" || value == null) continue;
    const number = Number(value);
    if (Number.isFinite(number)) return number;
  }
  return null;
}

function nonNegativeInteger(...values) {
  const number = finiteNumber(...values);
  return number == null ? null : Math.max(0, Math.trunc(number));
}

function statusOf(page = {}) {
  const raw = String(page.final_status || page.status || "PENDING").trim().toUpperCase();
  if (raw === "PARTIAL") return "NEEDS_REVIEW";
  return raw;
}

function pageRecords(job = {}) {
  const records = job.page_records || job.pages || job.snapshot?.pages || {};
  if (Array.isArray(records)) return records.filter(Boolean);
  return Object.entries(records).map(([pageNumber, page]) => ({
    source_page_number: nonNegativeInteger(page?.source_page_number, pageNumber),
    ...page,
  }));
}

function countFromArray(...values) {
  for (const value of values) {
    if (Array.isArray(value)) return value.length;
  }
  return null;
}

function durationSeconds(job = {}, metrics = {}) {
  const explicit = finiteNumber(
    metrics.elapsed_seconds,
    metrics.total_elapsed_seconds,
    job.elapsed_seconds,
    job.duration_seconds,
  );
  if (explicit != null) return Math.max(0, explicit);
  const started = Date.parse(job.started_at || job.snapshot?.started_at || "");
  const ended = Date.parse(job.finished_at || job.completed_at || "");
  if (!Number.isFinite(started)) return null;
  return Math.max(0, ((Number.isFinite(ended) ? ended : Date.now()) - started) / 1000);
}

export function normalizeOcrQualityTier(value, legacyProfile = "") {
  const normalized = String(value || "").trim().toLowerCase();
  if (VALID_TIERS.has(normalized)) return normalized;
  if (normalized === "standard" || String(legacyProfile).toLowerCase() === "standard") return "fast";
  return "recommended";
}

export function legacyOcrQualityProfile(tier) {
  return normalizeOcrQualityTier(tier) === "high" ? "publication" : "standard";
}

export function qualityTierLabel(tier) {
  return OCR_QUALITY_TIERS.find((item) => item.id === normalizeOcrQualityTier(tier))?.label || "推荐";
}

export function ocrPagePresentation(page = {}) {
  const state = statusOf(page);
  const retrying = page.retrying === true || state === "RETRYING";
  const needsReview = page.needs_review === true || page.low_conf === true || state === "NEEDS_REVIEW";
  const success = SUCCESS_PAGE_STATES.has(state);
  const failed = FAILED_PAGE_STATES.has(state);
  const pending = state === "PENDING";
  const label = retrying
    ? "重试中"
    : success && needsReview ? "待确认"
    : success ? "成功"
    : needsReview ? "待确认"
    : failed ? "失败，可重试"
    : pending ? "等待处理"
    : ACTIVE_PAGE_STATES.has(state) ? "处理中" : "等待处理";
  return { state, retrying, needsReview, success, failed, pending, label };
}

export function formatOcrDuration(seconds) {
  const value = finiteNumber(seconds);
  if (value == null) return "暂无";
  const rounded = Math.max(0, Math.round(value));
  if (rounded < 60) return `${rounded} 秒`;
  const hours = Math.floor(rounded / 3600);
  const minutes = Math.floor((rounded % 3600) / 60);
  const secs = rounded % 60;
  if (hours) return `${hours} 小时 ${minutes} 分`;
  return `${minutes} 分 ${secs} 秒`;
}

export function formatPagesPerMinute(value) {
  const number = finiteNumber(value);
  if (number == null || number < 0) return "暂无";
  return `${number < 10 ? number.toFixed(1) : number.toFixed(0)} 页/分钟`;
}

export function buildOcrProgress(job = {}) {
  const metrics = job.progress_metrics || job.performance_metrics || job.metrics || {};
  const records = pageRecords(job);
  const statuses = records.map(statusOf);
  const total = nonNegativeInteger(
    metrics.total_pages,
    metrics.selected_pages,
    job.total,
    job.selected_pages?.length,
    records.length,
  ) || 0;
  const success = nonNegativeInteger(
    metrics.success_pages,
    metrics.success_count,
    job.success_pages,
    job.success_count,
  ) ?? statuses.filter((status) => SUCCESS_PAGE_STATES.has(status)).length;
  const needsReview = nonNegativeInteger(
    metrics.needs_review_pages,
    metrics.needs_review_count,
    job.needs_review_pages,
    countFromArray(job.needs_review_page_ids, job.quality_report?.pages?.needs_review),
  ) ?? records.filter((page, index) => (
    REVIEW_PAGE_STATES.has(statuses[index]) || page.needs_review === true || page.low_conf === true
  )).length;
  const failed = nonNegativeInteger(
    metrics.failed_pages,
    metrics.failed_count,
    job.failed_pages,
    countFromArray(job.failed_page_ids, job.quality_report?.pages?.failed_or_incomplete),
  ) ?? statuses.filter((status) => FAILED_PAGE_STATES.has(status)).length;
  const active = nonNegativeInteger(
    metrics.active_pages,
    metrics.running_pages,
    job.active_pages,
  ) ?? statuses.filter((status) => ACTIVE_PAGE_STATES.has(status)).length;
  const terminal = statuses.filter((status) => TERMINAL_PAGE_STATES.has(status)).length;
  const completed = Math.min(total, Math.max(success + needsReview + failed, terminal, Number(job.done || 0)));
  const pendingFromRecords = statuses.filter((status) => status === "PENDING").length;
  const explicitPending = nonNegativeInteger(metrics.pending_pages, job.pending_pages);
  const pending = Math.max(
    explicitPending ?? 0,
    pendingFromRecords,
    Math.max(0, total - completed - active),
  );
  const retryPages = nonNegativeInteger(
    metrics.auto_retry_pages,
    metrics.retried_pages,
    job.auto_retry_pages,
    job.retry_pages,
    countFromArray(job.auto_retry_page_ids, job.retried_page_ids),
  ) ?? records.filter((page) => Number(page.retry_count || page.retries || 0) > 0 || page.retrying).length;
  const elapsedSeconds = durationSeconds(job, metrics);
  const averageRate = finiteNumber(
    metrics.average_pages_per_minute,
    metrics.pages_per_minute,
    job.average_pages_per_minute,
    elapsedSeconds > 0 ? completed * 60 / elapsedSeconds : null,
  );
  const recentRate = finiteNumber(
    metrics.recent_pages_per_minute,
    metrics.last_minute_pages_per_minute,
    job.recent_pages_per_minute,
  );
  const etaSeconds = finiteNumber(
    metrics.eta_seconds,
    metrics.estimated_remaining_seconds,
    job.eta_seconds,
    averageRate > 0 ? Math.max(0, total - completed) * 60 / averageRate : null,
  );
  const currentValues = metrics.current_pages || job.current_pages || job.active_page_numbers;
  const currentPages = (Array.isArray(currentValues) ? currentValues : [
    metrics.current_page,
    job.current_page,
    job.page,
  ]).map(Number).filter((value, index, values) => (
    Number.isInteger(value) && value > 0 && values.indexOf(value) === index
  ));
  const explicitProgress = finiteNumber(metrics.progress, job.progress);
  const computedProgress = total ? completed / total : 0;
  // A terminal HTTP/job status is not evidence that the immutable raw TEX was
  // frozen or that the two-pass baseline compile succeeded.  The host metrics
  // deliberately reserve 100% for COMPILED; never promote it from `done` here.
  const normalizedExplicit = explicitProgress == null
    ? null
    : Math.max(0, Math.min(1, explicitProgress > 1 ? explicitProgress / 100 : explicitProgress));
  // A persisted zero can be stale after restart while page records already
  // prove useful work.  Once the host has reported a non-zero milestone,
  // however, it is authoritative because page completion alone omits the
  // freeze/compile gates and must never promote a partial run to 100%.
  const progress = normalizedExplicit == null
    ? computedProgress
    : (normalizedExplicit === 0 && computedProgress > 0 ? computedProgress : normalizedExplicit);

  return {
    total,
    success,
    needsReview,
    failed,
    active,
    pending,
    retryPages,
    completed,
    currentPages,
    progress,
    elapsedSeconds,
    averageRate,
    recentRate,
    etaSeconds,
    concurrency: nonNegativeInteger(metrics.current_concurrency, job.current_concurrency, job.concurrency),
    dpi: nonNegativeInteger(metrics.current_dpi, job.current_dpi, job.dpi),
    rateLimited: Boolean(metrics.rate_limited || job.rate_limited),
  };
}

export function buildOcrRecoveryPresentation(job = {}) {
  const status = String(job.status || "").trim().toLowerCase();
  const records = pageRecords(job);
  const numbered = records.map((page, index) => ({
    page,
    state: statusOf(page),
    number: nonNegativeInteger(
      page.source_page_number,
      page.source_page,
      page.page_number,
      page.page,
      index + 1,
    ),
  })).filter((item) => item.number > 0);
  const pendingPageNumbers = numbered
    .filter((item) => item.state === "PENDING")
    .map((item) => item.number);
  const failedPageNumbers = numbered
    .filter((item) => FAILED_PAGE_STATES.has(item.state) || item.state === "CANCELLED")
    .map((item) => item.number);
  const activePageNumbers = numbered
    .filter((item) => ACTIVE_PAGE_STATES.has(item.state))
    .map((item) => item.number);
  const reviewPageNumbers = numbered
    .filter((item) => (
      REVIEW_PAGE_STATES.has(item.state)
      || item.page.needs_review === true
      || item.page.low_conf === true
    ))
    .map((item) => item.number);
  const incompletePageNumbers = Array.from(new Set([
    ...pendingPageNumbers,
    ...failedPageNumbers,
    ...activePageNumbers,
  ])).sort((left, right) => left - right);
  const progress = buildOcrProgress(job);
  const recordsCoverSelection = progress.total > 0 && numbered.length >= progress.total;
  const incompleteCount = recordsCoverSelection
    ? incompletePageNumbers.length
    : Math.max(
      incompletePageNumbers.length,
      progress.pending + progress.failed + progress.active,
    );
  const canResumeIncomplete = status === "partial"
    && job.can_resume === true
    && incompleteCount > 0;
  const needsReviewCount = Math.max(
    new Set(reviewPageNumbers).size,
    progress.needsReview,
  );
  const terminal = ["done", "partial", "error"].includes(status);
  const complete = status === "done" && incompleteCount === 0 && needsReviewCount === 0;
  const canRetryReview = terminal
    && job.raw_frozen !== true
    && needsReviewCount > 0;

  let statusLabel = "";
  let title = "";
  let detail = "";
  if (terminal && incompleteCount > 0) {
    statusLabel = canResumeIncomplete ? "未完成，可继续" : "尚未完成";
    title = `OCR 尚未完成：还有 ${incompleteCount} 页待处理`;
    detail = canResumeIncomplete
      ? "已完成页面和用量记录均已保留；点击“继续未完成页面”即可从不可变快照续跑。"
      : "已完成页面已经保留；请重试未完成页面，或检查识别服务设置。";
  } else if (status === "error") {
    statusLabel = "处理失败";
    title = "OCR 失败，已有结果已保留";
    detail = "没有把失败任务显示为完成；请检查识别服务设置后重试。";
  } else if (needsReviewCount > 0) {
    statusLabel = "已完成，待确认";
    title = `OCR 已完成，但有 ${needsReviewCount} 页待确认`;
    detail = canRetryReview
      ? "全部页面均已处理；可只重试待确认页，已经成功的页面不会重复识别。"
      : "全部页面均已处理；待确认表示质量复核项，不是未识别页面。";
  } else if (status === "done") {
    statusLabel = "已完成";
    title = "OCR 已完成";
    detail = "原稿已经冻结；基线产物只包含纯语法恢复，不会自动套定理、证明或模板。";
  }

  return {
    complete,
    canResumeIncomplete,
    canRetryReview,
    incompleteCount,
    pendingPageNumbers,
    failedPageNumbers,
    activePageNumbers,
    incompletePageNumbers,
    reviewPageNumbers: Array.from(new Set(reviewPageNumbers)).sort((left, right) => left - right),
    statusLabel,
    title,
    detail,
    actionLabel: `继续未完成页面（${incompleteCount}）`,
    reviewActionLabel: `重试待确认页（${needsReviewCount}）`,
  };
}

function artifactFrom(job, ...names) {
  const stores = [job.artifacts, job.outputs, job.result?.artifacts, job.snapshot?.artifacts].filter(Boolean);
  for (const store of stores) {
    for (const name of names) {
      const value = store?.[name];
      if (typeof value === "string" && value) return { available: true, url: value };
      if (value && typeof value === "object") {
        return {
          available: value.available !== false && value.exists !== false,
          url: value.download_url || value.url || value.href || "",
          status: value.status || value.preview_status || "",
          filename: value.filename || value.name || "",
        };
      }
      if (value === true) return { available: true, url: "" };
    }
  }
  return { available: false, url: "" };
}

export function buildOcrArtifacts(job = {}) {
  const terminal = ["done", "partial", "error", "paused"].includes(String(job.status || "").toLowerCase());
  const raw = artifactFrom(job, "raw_ocr_tex", "raw_tex", "ocr_source_tex");
  const source = artifactFrom(job, "source_pdf", "source", "input_pdf");
  const baselineTex = artifactFrom(job, "baseline_tex", "ocr_baseline_tex");
  const baselinePdf = artifactFrom(job, "baseline_pdf", "ocr_baseline_pdf");
  if (!raw.available && terminal && (job.raw_ready || job.raw_tex || Number(job.raw_revision || 0) > 0)) {
    raw.available = true;
    raw.url = job.id ? `/api/ocr/jobs/${job.id}/result` : "";
  }
  const compileStatus = String(
    job.compile_status
      || job.baseline_compile?.preview_status
      || job.baseline?.preview_status
      || baselinePdf.status
      || "",
  ).toUpperCase();
  return {
    source: { label: "原始 PDF / 图片", ...source },
    raw: { label: "不可变 OCR 原稿 TEX", ...raw },
    baselineTex: { label: "OCR 基线 TEX", ...baselineTex },
    baselinePdf: { label: "OCR 基线 PDF", ...baselinePdf },
    compileStatus: ["COMPILED", "PARTIAL_COMPILED", "SOURCE_PREVIEW"].includes(compileStatus)
      ? compileStatus : "",
  };
}

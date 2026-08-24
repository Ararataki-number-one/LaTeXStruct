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

function firstDefined(...values) {
  return values.find((value) => value !== undefined && value !== null && value !== "");
}

function rangeValue(value) {
  if (value == null || value === "") return null;
  if (Array.isArray(value)) {
    const low = finiteNumber(value[0]);
    const high = finiteNumber(value.length > 1 ? value[1] : value[0]);
    if (low == null || high == null || low < 0 || high < 0) return null;
    return { min: Math.min(low, high), max: Math.max(low, high) };
  }
  if (typeof value === "object") {
    const low = finiteNumber(value.min, value.low, value.lower, value.from, value.value);
    const high = finiteNumber(value.max, value.high, value.upper, value.to, value.value, low);
    if (low == null || high == null || low < 0 || high < 0) return null;
    return { min: Math.min(low, high), max: Math.max(low, high) };
  }
  const number = finiteNumber(value);
  return number == null || number < 0 ? null : { min: number, max: number };
}

function namedRange(source, names, minNames = [], maxNames = []) {
  for (const name of names) {
    const range = rangeValue(source?.[name]);
    if (range) return range;
  }
  const low = finiteNumber(...minNames.map((name) => source?.[name]));
  const high = finiteNumber(...maxNames.map((name) => source?.[name]));
  if (low == null && high == null) return null;
  const normalizedLow = low ?? high;
  const normalizedHigh = high ?? low;
  if (normalizedLow < 0 || normalizedHigh < 0) return null;
  return {
    min: Math.min(normalizedLow, normalizedHigh),
    max: Math.max(normalizedLow, normalizedHigh),
  };
}

function scaleRange(range, multiplier) {
  if (!range) return null;
  const scale = finiteNumber(multiplier);
  if (scale == null || scale < 0) return null;
  return { min: range.min * scale, max: range.max * scale };
}

function formatRange(range, formatter, separator = "–") {
  if (!range) return "";
  const low = formatter(range.min);
  const high = formatter(range.max);
  return range.min === range.max ? low : `${low}${separator}${high}`;
}

function tierEstimateSource(source, tier) {
  const normalizedTier = normalizeOcrQualityTier(tier);
  const containers = [source?.ocr_estimates, source?.estimates, source?.estimate_by_tier];
  for (const container of containers) {
    if (container?.[normalizedTier] && typeof container[normalizedTier] === "object") {
      return container[normalizedTier];
    }
  }
  const generic = source?.ocr_estimate || source?.estimate || source?.estimation;
  if (generic?.tiers?.[normalizedTier]) return generic.tiers[normalizedTier];
  return generic && typeof generic === "object" ? generic : {};
}

function nonNegativeInteger(...values) {
  const number = finiteNumber(...values);
  return number == null ? null : Math.max(0, Math.trunc(number));
}

function positiveInteger(...values) {
  const number = nonNegativeInteger(...values);
  return number != null && number > 0 ? number : null;
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

function estimateMetric(source, selectedPages, directConfig, perPageConfig) {
  const direct = namedRange(
    source,
    directConfig.names,
    directConfig.minNames,
    directConfig.maxNames,
  );
  const basisPages = nonNegativeInteger(
    source?.basis_pages,
    source?.selected_pages,
    source?.page_count,
  );
  if (direct && (basisPages == null || selectedPages == null || basisPages === selectedPages)) {
    return direct;
  }
  const perPageSources = [source?.per_page, source?.per_page_estimate];
  for (const perPageSource of perPageSources) {
    const perPage = namedRange(
      perPageSource,
      perPageConfig.names,
      perPageConfig.minNames,
      perPageConfig.maxNames,
    );
    if (perPage && selectedPages != null) return scaleRange(perPage, selectedPages);
  }
  const flatPerPage = namedRange(
    source,
    perPageConfig.flatNames || [],
    perPageConfig.flatMinNames || [],
    perPageConfig.flatMaxNames || [],
  );
  if (flatPerPage && selectedPages != null) return scaleRange(flatPerPage, selectedPages);
  return null;
}

export function buildOcrEstimate(source = {}, selectedPages = null, tier = "recommended") {
  const estimate = tierEstimateSource(source, tier);
  const selected = nonNegativeInteger(selectedPages);
  const calls = estimateMetric(estimate, selected, {
    names: ["calls", "requests", "request_count", "estimated_calls", "estimated_requests"],
    minNames: ["calls_min", "requests_min", "estimated_calls_min", "estimated_requests_min"],
    maxNames: ["calls_max", "requests_max", "estimated_calls_max", "estimated_requests_max"],
  }, {
    names: ["calls", "requests"],
    minNames: ["calls_min", "requests_min"],
    maxNames: ["calls_max", "requests_max"],
    flatNames: ["calls_per_page", "requests_per_page"],
    flatMinNames: ["calls_per_page_min", "requests_per_page_min"],
    flatMaxNames: ["calls_per_page_max", "requests_per_page_max"],
  });
  const durationSeconds = estimateMetric(estimate, selected, {
    names: ["duration_seconds", "elapsed_seconds", "estimated_duration_seconds", "time_seconds"],
    minNames: ["duration_seconds_min", "estimated_duration_seconds_min", "time_seconds_min"],
    maxNames: ["duration_seconds_max", "estimated_duration_seconds_max", "time_seconds_max"],
  }, {
    names: ["duration_seconds", "seconds"],
    minNames: ["duration_seconds_min", "seconds_min"],
    maxNames: ["duration_seconds_max", "seconds_max"],
    flatNames: ["seconds_per_page", "duration_seconds_per_page"],
    flatMinNames: ["seconds_per_page_min", "duration_seconds_per_page_min"],
    flatMaxNames: ["seconds_per_page_max", "duration_seconds_per_page_max"],
  });
  const cost = estimateMetric(estimate, selected, {
    names: ["cost", "estimated_cost", "cost_range"],
    minNames: ["cost_min", "estimated_cost_min"],
    maxNames: ["cost_max", "estimated_cost_max"],
  }, {
    names: ["cost"],
    minNames: ["cost_min"],
    maxNames: ["cost_max"],
    flatNames: ["cost_per_page"],
    flatMinNames: ["cost_per_page_min"],
    flatMaxNames: ["cost_per_page_max"],
  });
  const currency = String(
    firstDefined(
      estimate.currency,
      estimate.cost_currency,
      estimate.cost?.currency,
      estimate.cost_range?.currency,
      source.currency,
      source.cost_currency,
    ) || "",
  ).trim().toUpperCase();
  const formatCount = (value) => String(Math.max(0, Math.ceil(value)));
  const formatCostNumber = (value) => {
    const digits = value >= 100 ? 0 : value >= 1 ? 2 : 4;
    return Number(value.toFixed(digits)).toLocaleString("zh-CN", { maximumFractionDigits: digits });
  };
  const costPrefix = currency === "CNY" ? "¥" : currency === "USD" ? "$" : currency ? `${currency} ` : "";
  return {
    calls,
    durationSeconds,
    cost,
    currency,
    callsText: calls ? `${formatRange(calls, formatCount)} 次` : "待后端评估",
    durationText: durationSeconds
      ? formatRange(durationSeconds, (value) => formatOcrDuration(value))
      : "待后端评估",
    costText: cost
      ? `${costPrefix}${formatRange(cost, formatCostNumber)}${currency ? "" : "（币种未知）"}`
      : "无法估算",
    measured: Boolean(calls || durationSeconds || cost),
  };
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
  if (value == null) return "未知";
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
  if (number == null || number < 0) return "未知";
  return `${number < 10 ? number.toFixed(1) : number.toFixed(0)} 页/分钟`;
}

export function formatOcrInteger(value, suffix = "") {
  const number = finiteNumber(value);
  if (number == null || number < 0) return "未知";
  return `${Math.trunc(number).toLocaleString("zh-CN")}${suffix}`;
}

export function formatOcrCost(value, currency = "") {
  const number = finiteNumber(value);
  if (number == null || number < 0) return "未知";
  const normalized = String(currency || "").trim().toUpperCase();
  const prefix = normalized === "CNY" ? "¥" : normalized === "USD" ? "$" : normalized ? `${normalized} ` : "";
  const digits = number >= 100 ? 0 : number >= 1 ? 2 : 4;
  const amount = Number(number.toFixed(digits)).toLocaleString("zh-CN", { maximumFractionDigits: digits });
  return `${prefix}${amount}${normalized ? "" : "（币种未知）"}`;
}

export function ocrStrategyLabel(value) {
  const strategy = String(value || "").trim().toLowerCase();
  return ({
    object_layer_verified: "对象层验证",
    object_layer_verification: "对象层验证",
    born_digital_fast: "对象层验证",
    full_visual_ocr: "完整视觉 OCR",
    full_ocr: "完整视觉 OCR",
    visual_strict: "完整视觉 OCR",
    high_resolution_retry: "高分辨率重试",
    higher_dpi_retry: "高分辨率重试",
    crop_review: "局部裁片识别",
    crop_recognition: "局部裁片识别",
    local_crop_ocr: "局部裁片识别",
  })[strategy] || (strategy ? String(value) : "未知");
}

function firstMetric(sources, ...names) {
  for (const source of sources) {
    if (!source || typeof source !== "object") continue;
    for (const name of names) {
      if (source[name] !== undefined && source[name] !== null && source[name] !== "") {
        return source[name];
      }
    }
  }
  return null;
}

function explicitBoolean(sources, ...names) {
  const value = firstMetric(sources, ...names);
  if (value === true || value === false) return value;
  return null;
}

export function buildOcrProgress(job = {}) {
  const progressMetrics = job.progress_metrics || {};
  const performanceMetrics = job.performance_metrics || {};
  const genericMetrics = job.metrics || {};
  const metricSources = [progressMetrics, performanceMetrics, genericMetrics, job];
  const nestedPages = firstDefined(
    progressMetrics.pages,
    performanceMetrics.pages,
    genericMetrics.pages,
  ) || {};
  const throughput = firstDefined(
    progressMetrics.throughput,
    performanceMetrics.throughput,
    genericMetrics.throughput,
  ) || {};
  const scheduler = firstDefined(
    progressMetrics.scheduler,
    performanceMetrics.scheduler,
    genericMetrics.scheduler,
    job.scheduler,
  ) || {};
  const requestMetrics = firstDefined(
    progressMetrics.requests,
    performanceMetrics.requests,
    genericMetrics.requests,
  ) || {};
  const costActual = job.cost_report?.actual || {};
  const costCoverage = job.cost_report?.measurement_coverage || {};
  const usageSources = [
    progressMetrics.usage,
    performanceMetrics.usage,
    genericMetrics.usage,
    job.usage,
    costActual,
  ].filter(Boolean);
  const records = pageRecords(job);
  const statuses = records.map(statusOf);
  const total = nonNegativeInteger(
    firstMetric(metricSources, "total_pages", "selected_pages"),
    nestedPages.selected,
    job.total,
    job.selected_pages?.length,
    records.length,
  ) || 0;
  const statusCounts = nestedPages.by_final_status || nestedPages.final_status_counts || {};
  const success = nonNegativeInteger(
    firstMetric(metricSources, "success_pages", "success_count"),
    statusCounts.SUCCESS,
  ) ?? statuses.filter((status) => SUCCESS_PAGE_STATES.has(status)).length;
  const needsReview = nonNegativeInteger(
    firstMetric(metricSources, "needs_review_pages", "needs_review_count"),
    statusCounts.NEEDS_REVIEW,
    countFromArray(job.needs_review_page_ids, job.quality_report?.pages?.needs_review),
  ) ?? records.filter((page, index) => (
    REVIEW_PAGE_STATES.has(statuses[index]) || page.needs_review === true || page.low_conf === true
  )).length;
  const failed = nonNegativeInteger(
    firstMetric(metricSources, "failed_pages", "failed_count"),
    statusCounts.FAILED,
    countFromArray(job.failed_page_ids, job.quality_report?.pages?.failed_or_incomplete),
  ) ?? statuses.filter((status) => FAILED_PAGE_STATES.has(status)).length;
  const active = nonNegativeInteger(
    firstMetric(metricSources, "in_flight_pages", "active_pages", "running_pages"),
  ) ?? statuses.filter((status) => ACTIVE_PAGE_STATES.has(status)).length;
  const terminal = statuses.filter((status) => TERMINAL_PAGE_STATES.has(status)).length;
  const explicitCompleted = nonNegativeInteger(
    firstMetric(metricSources, "completed_pages", "coverage_completed"),
    nestedPages.coverage_completed,
    job.done,
  );
  const completed = Math.min(
    total,
    explicitCompleted ?? (statuses.length ? terminal : success + needsReview + failed),
  );
  const pendingFromRecords = statuses.filter((status) => status === "PENDING").length;
  const explicitPending = nonNegativeInteger(firstMetric(metricSources, "pending_pages"));
  const pending = Math.max(
    explicitPending ?? 0,
    pendingFromRecords,
    Math.max(0, total - completed - active),
  );
  const retryPages = nonNegativeInteger(
    firstMetric(metricSources, "retry_pages", "auto_retry_pages", "retried_pages"),
    countFromArray(job.auto_retry_page_ids, job.retried_page_ids),
  ) ?? records.filter((page) => Number(page.retry_count || page.retries || 0) > 0 || page.retrying).length;
  const elapsedMilliseconds = finiteNumber(
    firstMetric(metricSources, "elapsed_ms", "total_elapsed_ms"),
  );
  const elapsedSeconds = elapsedMilliseconds == null
    ? durationSeconds(job, progressMetrics)
    : elapsedMilliseconds / 1000;
  const averageRate = finiteNumber(
    firstMetric(metricSources, "average_pages_per_minute", "pages_per_minute"),
    throughput.average_pages_per_minute,
    elapsedSeconds > 0 ? completed * 60 / elapsedSeconds : null,
  );
  const recentRate = finiteNumber(
    firstMetric(metricSources, "recent_pages_per_minute", "last_minute_pages_per_minute"),
    throughput.recent_pages_per_minute,
  );
  const etaSeconds = finiteNumber(
    firstMetric(metricSources, "eta_seconds", "estimated_remaining_seconds"),
    throughput.eta_seconds,
    averageRate > 0 ? Math.max(0, total - completed) * 60 / averageRate : null,
  );
  const currentValues = firstMetric(metricSources, "current_pages", "active_page_numbers");
  const currentPages = (Array.isArray(currentValues) ? currentValues : [
    firstMetric(metricSources, "current_page", "page"),
  ]).map(Number).filter((value, index, values) => (
    Number.isInteger(value) && value > 0 && values.indexOf(value) === index
  ));
  const explicitProgress = finiteNumber(firstMetric(metricSources, "progress"));
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

  const inputTokens = nonNegativeInteger(firstMetric(usageSources, "input_tokens"));
  const outputTokens = nonNegativeInteger(firstMetric(usageSources, "output_tokens"));
  const explicitTotalTokens = nonNegativeInteger(firstMetric(usageSources, "total_tokens"));
  const observedInput = nonNegativeInteger(firstMetric(usageSources, "observed_input_tokens"));
  const observedOutput = nonNegativeInteger(firstMetric(usageSources, "observed_output_tokens"));
  const totalTokens = explicitTotalTokens
    ?? (inputTokens != null && outputTokens != null ? inputTokens + outputTokens : null)
    ?? (observedInput != null || observedOutput != null ? (observedInput || 0) + (observedOutput || 0) : null);
  const tokenCoverageComplete = explicitTotalTokens != null || (
    inputTokens != null && outputTokens != null
    && costCoverage.input_tokens?.complete !== false
    && costCoverage.output_tokens?.complete !== false
  );
  const actualCost = finiteNumber(firstMetric(usageSources, "cost"));
  const observedCost = finiteNumber(firstMetric(usageSources, "observed_cost"));
  const cost = actualCost ?? observedCost;
  const costCoverageComplete = actualCost != null
    && costCoverage.cost?.complete !== false
    && performanceMetrics.usage?.cost_coverage?.complete !== false;
  const currency = String(firstMetric(usageSources, "currency") || "").trim().toUpperCase();
  const rateLimited = explicitBoolean(metricSources, "rate_limited", "is_rate_limited");
  const explicitRateStatus = firstMetric(metricSources, "rate_limit_status", "limiter_status");
  const rateLimitStatus = explicitRateStatus != null
    ? String(explicitRateStatus)
    : rateLimited === true ? "限流中" : rateLimited === false ? "未限流" : "未知";
  const strategy = firstMetric(metricSources, "current_strategy", "strategy", "ocr_strategy");

  return {
    total,
    selectedPages: total,
    success,
    needsReview,
    failed,
    active,
    inFlight: active,
    pending,
    retryPages,
    completed,
    currentPages,
    progress,
    elapsedSeconds,
    averageRate,
    recentRate,
    etaSeconds,
    concurrency: nonNegativeInteger(
      firstMetric(metricSources, "current_concurrency", "concurrency"),
      scheduler.current_concurrency,
      scheduler.concurrency,
    ),
    batchSize: nonNegativeInteger(
      firstMetric(metricSources, "current_batch_size", "batch_size"),
      scheduler.current_batch_size,
      scheduler.batch_size,
    ),
    dpi: positiveInteger(firstMetric(metricSources, "current_dpi", "dpi")),
    rateLimited: rateLimited === true,
    rateLimitStatus,
    strategy: strategy == null ? "" : String(strategy),
    strategyLabel: ocrStrategyLabel(strategy),
    totalTokens,
    tokenCoverageComplete,
    cost,
    costCoverageComplete,
    currency,
    requestCount: nonNegativeInteger(requestMetrics.total),
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
  const terminal = ["done", "partial", "error", "cancelled"].includes(status);
  const complete = status === "done" && incompleteCount === 0 && needsReviewCount === 0;
  const canRetryReview = terminal
    && job.raw_frozen !== true
    && needsReviewCount > 0;

  let statusLabel = "";
  let title = "";
  let detail = "";
  if (status === "cancelled") {
    statusLabel = "已安全取消";
    title = incompleteCount > 0
      ? `OCR 已取消：还有 ${incompleteCount} 页未处理`
      : "OCR 已取消";
    detail = "取消前已完成的页面、不可变记录和实际用量均已保留；不会显示为成功完成。";
  } else if (terminal && incompleteCount > 0) {
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
        const available = value.available !== false && value.exists !== false;
        return {
          available,
          url: available ? (value.download_url || value.url || value.href || "") : "",
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
  const terminal = ["done", "partial", "error", "paused", "cancelled"].includes(String(job.status || "").toLowerCase());
  const raw = artifactFrom(job, "raw_ocr_tex", "raw_tex", "ocr_source_tex");
  const source = artifactFrom(job, "source_pdf", "source", "input_pdf");
  const baselineTex = artifactFrom(job, "baseline_tex", "ocr_baseline_tex");
  const evidenceCorrectedTex = artifactFrom(
    job,
    "evidence_corrected_tex",
    "ocr_evidence_corrected_tex",
    "corrected_tex",
    "evidence_revision_tex",
  );
  const baselinePdf = artifactFrom(job, "baseline_pdf", "ocr_baseline_pdf");
  const baselineProject = artifactFrom(
    job,
    "baseline_project",
    "baseline_project_zip",
    "ocr_baseline_project",
    "project_zip",
  );
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
  ).trim().toUpperCase().slice(0, 64);
  const projectId = String(
    job.baseline_project_id || job.project_id || job.imported_project_id || "",
  ).trim();
  return {
    source: { label: "原始 PDF / 图片", ...source },
    raw: { label: "不可变 OCR 原稿 TEX", ...raw },
    baselineTex: { label: "纯语法恢复 OCR 基线 TEX", ...baselineTex },
    evidenceCorrectedTex: { label: "图像证据修订版 TEX", ...evidenceCorrectedTex },
    baselinePdf: { label: "OCR 基线 PDF", ...baselinePdf },
    baselineProject: { label: "OCR 基线工程 ZIP", ...baselineProject },
    compileStatus,
    projectId,
  };
}

export async function openOcrProjectWithoutAnalysis({
  jobId,
  existingProjectId = "",
  request,
  navigate,
}) {
  if (typeof navigate !== "function") {
    throw new Error("打开项目所需的前端导航不可用");
  }
  const currentProjectId = String(existingProjectId || "").trim();
  if (currentProjectId) {
    navigate(currentProjectId);
    return { id: currentProjectId, reused: true };
  }
  const normalizedJobId = String(jobId || "").trim();
  if (!normalizedJobId) throw new Error("OCR 任务编号缺失");
  if (typeof request !== "function") throw new Error("打开项目所需的前端请求能力不可用");
  const response = await request(`/api/ocr/jobs/${normalizedJobId}/open`, { method: "POST" });
  const payload = await response.json();
  const projectId = String(payload?.id || payload?.project_id || "").trim();
  if (!projectId) throw new Error("服务未返回项目编号");
  navigate(projectId);
  return { ...payload, id: projectId, reused: Boolean(payload?.reused) };
}

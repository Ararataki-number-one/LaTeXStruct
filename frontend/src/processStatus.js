const ACTIVE_STATUSES = new Set(["running", "pausing", "paused", "cancelling", "committing"]);
const FAILED_STATUSES = new Set(["blocked", "error"]);
const TERMINAL_STATUSES = new Set(["done", "blocked", "error", "cancelled"]);

export const PROCESS_STAGE_DEFINITIONS = Object.freeze([
  {
    id: "preflight",
    label: "输入证据检查",
    phases: ["preflight"],
    help: "核对冻结源文件、哈希、页数和选择范围，旧版已知元数据缺陷会留下迁移记录。",
  },
  {
    id: "inventory",
    label: "全文结构清点",
    phases: ["parse", "scan"],
    help: "逐行识别裸 formal 标题和既有定理、证明环境。",
  },
  {
    id: "decision",
    label: "结构判断",
    phases: ["decide"],
    help: "对每个候选形成可追踪结论，不把漏答当作通过。",
  },
  {
    id: "full-review",
    label: "全文独立复核",
    phases: ["full-review"],
    help: "再次覆盖全文与既有环境，检查漏套、错套和范围过宽。",
  },
  {
    id: "ai-review",
    label: "AI 二次复查",
    phases: ["review"],
    help: "复查修改范围与结论，未解决项会进入人工清单。",
  },
  {
    id: "quality-compile",
    label: "全文真实编译",
    phases: ["quality-compile"],
    help: "生成完整 COMPILED PDF；部分编译不能算通过。",
  },
  {
    id: "quality-visual",
    label: "逐页视觉复核",
    phases: ["quality-visual"],
    help: "逐页对照源 PDF，并只允许宿主已有的可逆定点修复。",
  },
  {
    id: "final-inventory",
    label: "最终结构清单",
    phases: ["draft"],
    help: "对最终 TEX 重新清点；残余 formal 问题会阻止发布。",
  },
  {
    id: "gate",
    label: "最终门禁与报告",
    phases: ["report", "commit", "done", "verification_failed"],
    help: "汇总失败原因；只有全部证据通过才保存为已验证结果。",
  },
]);

const PHASE_COPY = Object.freeze({
  preflight: ["正在核对输入证据", "验证冻结源文件、哈希、页数和选择范围。"],
  parse: ["正在读取全文结构", "解析章节、环境和不可修改区域。"],
  scan: ["正在建立 formal 清单", "逐行清点标题与既有环境。"],
  decide: ["正在判断结构候选", "每个候选必须获得唯一结论。"],
  "full-review": ["正在全文独立复核", "检查初次扫描未发现的漏套、错套和多套。"],
  review: ["正在 AI 二次复查", "再次核对修改范围和置信度。"],
  "quality-compile": ["正在全文真实编译", "必须得到完整 COMPILED PDF 才会进入逐页复核。"],
  "quality-visual": ["正在逐页视觉复核", "左侧源 PDF 与右侧编译页正在逐页比对。"],
  draft: ["正在生成最终结构清单", "重新扫描最终 TEX 并执行静态安全门。"],
  report: ["正在汇总证据与失败原因", "生成用户可读报告和最终门禁结论。"],
  commit: ["正在保存已验证结果", "已通过全部门禁，正在原子保存。"],
  done: ["处理完成", "全部必需检查已经通过。"],
  verification_failed: ["最终安全门未通过", "失败草稿已保留，正式结果没有被覆盖。"],
  error: ["处理未完成", "请查看错误详情；正式结果没有被覆盖。"],
  cancelled: ["任务已取消", "取消前已有阶段可用于诊断。"],
});

function stageForPhase(phase) {
  return PROCESS_STAGE_DEFINITIONS.find((stage) => stage.phases.includes(phase));
}

export function describeProcessPhase(phase, fallback = "") {
  const key = String(phase || "");
  const copy = PHASE_COPY[key];
  if (copy) return { label: copy[0], help: copy[1] };
  return {
    label: String(fallback || "正在处理"),
    help: "等待当前安全步骤完成。",
  };
}

export function buildProcessStageTrail(job = {}) {
  const events = Array.isArray(job.events) ? job.events : [];
  const businessEvents = events.filter((event) => event?.scope !== "finalization");
  const reachedPhases = Array.isArray(job.reached_phases) ? job.reached_phases : [];
  const seen = new Set([
    ...reachedPhases.map((phase) => String(phase || "")),
    ...businessEvents.map((event) => String(event?.phase || "")),
  ]);
  const currentPhase = String(job.phase || "");
  const currentStage = stageForPhase(currentPhase);
  const status = String(job.status || "");
  let failedStage = null;
  if (FAILED_STATUSES.has(status) && !currentStage) {
    failedStage = stageForPhase(String(job.failure_phase || ""));
    if (!failedStage) {
      const prior = [...businessEvents]
        .reverse()
        .find((event) => stageForPhase(String(event?.phase || "")));
      failedStage = prior ? stageForPhase(String(prior.phase || "")) : null;
    }
  }

  return PROCESS_STAGE_DEFINITIONS.map((stage) => {
    const wasSeen = stage.phases.some((phase) => seen.has(phase));
    let state = "pending";
    if (currentStage?.id === stage.id && ACTIVE_STATUSES.has(status)) state = "current";
    else if (currentStage?.id === stage.id && FAILED_STATUSES.has(status)) state = "failed";
    else if (failedStage?.id === stage.id) state = "failed";
    else if (wasSeen) state = "completed";
    else if (TERMINAL_STATUSES.has(status)) state = "skipped";
    return { ...stage, state };
  });
}

export function verificationFailureTitle(failure = {}) {
  const label = String(failure?.label || "安全检查").trim() || "安全检查";
  const summary = String(failure?.summary || "检查未通过").trim() || "检查未通过";
  // Older reports sometimes stored "<label>未通过" (or repeated the label
  // after a colon) as the summary.  Rendering both fields verbatim makes one
  // failure look like two failures, which is particularly misleading in a
  // terminal safety gate.  The host still retains the unmodified failure in
  // the report; this is presentation-only de-duplication.
  const compact = (value) => String(value || "").replace(/[：:\s]/g, "");
  const compactLabel = compact(label);
  const compactSummary = compact(summary);
  if (
    compactSummary === compactLabel
    || compactSummary === `${compactLabel}未通过`
    || compactSummary === `${compactLabel}${compactLabel}未通过`
  ) return `${label}：未通过`;
  if (compactSummary.startsWith(compactLabel)) {
    const suffix = compactSummary.slice(compactLabel.length);
    if (!suffix || suffix === "未通过") return `${label}：未通过`;
  }
  return `${label}：${summary}`;
}

const STAGE_CHECK_IDS = Object.freeze({
  "full-review": ["full-document-review"],
  "ai-review": ["ai-second-review", "second-ai-review", "ai-review"],
  "quality-compile": ["compile-render-visual-repair"],
  "quality-visual": ["compile-render-visual-repair"],
  "final-inventory": ["final-formal-inventory"],
});

function skipReason(stage = {}, verification = {}, job = {}) {
  const matchingCheck = (STAGE_CHECK_IDS[stage?.id] || [])
    .map((id) => checkById(verification, id))
    .find(Boolean);
  const configuredReason = String(matchingCheck?.skip_reason || "").trim();
  if (configuredReason === "user-disabled") return "用户未启用（不计为失败）";
  if (configuredReason) return `配置跳过：${configuredReason}`;
  if (matchingCheck?.skipped === true) return "配置跳过（不计为失败）";

  // A terminal job has stopped advancing.  Never leave an unvisited stage
  // with the ambiguous label "未运行": explain whether it was intentionally
  // skipped, prevented by missing evidence, or cut off by the terminal state.
  const status = String(job?.status || "").toLowerCase();
  if (status === "blocked") return "因安全检查未通过而未执行";
  if (status === "error") return "因处理错误而中止";
  if (status === "cancelled") return "因用户取消而未执行";
  if (status === "done") return "本次流程不需要此步骤";
  return "等待前置步骤";
}

export function processStageStateLabel(stage = {}, verification = {}, job = {}) {
  const stateLabels = {
    completed: "已完成",
    current: "进行中",
    failed: "未通过",
    pending: "等待中",
  };
  const fullReviewCheck = checkById(verification, "full-document-review");
  const userDisabledSecondReview = (
    fullReviewCheck?.skipped === true
    && fullReviewCheck?.skip_reason === "user-disabled"
  );
  if (
    userDisabledSecondReview
    && stage?.state === "skipped"
    && ["full-review", "ai-review"].includes(stage?.id)
  ) {
    return "用户未启用（不计为失败）";
  }
  if (stage?.state === "skipped") return skipReason(stage, verification, job);
  return stateLabels[stage?.state] || String(stage?.state || "");
}

/**
 * `progress` is execution coverage only.  A blocked task legitimately reaches
 * 100% because its run has ended; it must never be presented as a verification
 * success.  Keeping this mapping pure makes the wording testable without a
 * React render and keeps the status API/UI contract explicit.
 */
export function describeExecutionProgress(job = {}) {
  const numeric = Number(job?.progress);
  const percent = Math.max(0, Math.min(100, Math.round((Number.isFinite(numeric) ? numeric : 0) * 100)));
  const status = String(job?.status || "").toLowerCase();
  const verificationStatus = String(job?.verification_status || "").toLowerCase();
  if (percent < 100) return { percent, label: "执行进度", detail: "正在执行，尚未形成验证结论" };
  if (verificationStatus === "passed" || status === "done") return { percent, label: "执行进度", detail: "执行完成；安全检查通过" };
  if (verificationStatus === "failed" || status === "blocked") return { percent, label: "执行进度", detail: "执行完成；安全检查未通过" };
  if (status === "cancelled") return { percent, label: "执行进度", detail: "执行结束：任务已取消，未形成验证结论" };
  if (status === "error") return { percent, label: "执行进度", detail: "执行结束：发生错误，未形成验证结论" };
  return { percent, label: "执行进度", detail: "执行完成，等待验证结论" };
}

export function verificationCheckDisplayLabel(check = {}) {
  const label = String(check?.label || check?.id || "安全检查");
  if (check?.skipped !== true) return `${check?.ok ? "✓" : "✗"}${label}`;
  const reason = String(check?.skip_reason || "").trim();
  if (reason === "user-disabled") return `·${label}（用户未启用）`;
  if (reason) return `·${label}（配置跳过：${reason}）`;
  return `·${label}（配置跳过；未形成通过结论）`;
}

function checkById(verification, id) {
  const checks = Array.isArray(verification?.checks) ? verification.checks : [];
  return checks.find((check) => check?.id === id) || null;
}

function stateFromCheck(check, fallbackOk = false) {
  if (check?.skipped === true) return "skipped";
  if (check?.ok === true || (!check && fallbackOk)) return "passed";
  return "failed";
}

function reasons(items) {
  return (Array.isArray(items) ? items : [])
    .map((item) => String(item?.reason || item?.summary || "").trim())
    .filter(Boolean);
}

export function summarizeVerificationStages(verification = {}) {
  const full = verification.full_document_review || {};
  const visual = verification.visual_quality_loop || {};
  const finalInventory = verification.final_formal_inventory || {};
  const rounds = Array.isArray(visual.rounds) ? visual.rounds : [];
  const completeCompiles = rounds.filter((round) => (
    round?.compile?.ok === true && round?.compile?.preview_status === "COMPILED"
  )).length;
  const lastAudit = [...rounds].reverse().find((round) => round?.ai_audit)?.ai_audit || {};
  const finalFindings = Array.isArray(finalInventory.findings) ? finalInventory.findings : [];
  const blockers = finalFindings.filter((finding) => (
    ["missing", "wrong-env", "overwide", "duplicate"].includes(finding?.kind)
  ));
  const counts = finalInventory.counts || {};
  const fullCheck = checkById(verification, "full-document-review");
  const visualCheck = checkById(verification, "compile-render-visual-repair");
  const finalCheck = checkById(verification, "final-formal-inventory");
  const fullRecorded = Boolean(fullCheck) || Object.keys(full).length > 0;
  const visualRecorded = Boolean(visualCheck) || Object.keys(visual).length > 0;
  const finalRecorded = Boolean(finalCheck) || Object.keys(finalInventory).length > 0;
  const compileState = !visualRecorded || visualCheck?.skipped === true
    ? "skipped"
    : visual.required === true && rounds.length > 0 && completeCompiles === rounds.length
      ? "passed"
      : visual.required === true ? "failed" : "skipped";

  return [
    {
      id: "full-review",
      label: "全文独立复核",
      state: !fullRecorded
        ? "skipped"
        : stateFromCheck(fullCheck, full.checked === true && full.ok === true),
      summary: !fullRecorded
        ? "该旧任务未记录此阶段（不是检查通过）"
        : fullCheck?.skipped === true
        ? fullCheck?.skip_reason === "user-disabled"
          ? "用户未启用第二遍复查（不计为失败）"
          : "本次未要求运行"
        : `复核 ${Array.isArray(full.chunks) ? full.chunks.length : 0} 个分段；`
          + `无效 ${Array.isArray(full.invalid) ? full.invalid.length : 0}；`
          + `待人工 ${Array.isArray(full.escalations) ? full.escalations.length : 0}`,
      details: [...reasons(full.invalid), ...reasons(full.escalations)],
    },
    {
      id: "quality-compile",
      label: "全文真实编译",
      state: compileState,
      summary: !visualRecorded
        ? "该旧任务未记录此阶段（不是检查通过）"
        : compileState === "skipped"
        ? "本次未要求运行"
        : `${completeCompiles}/${rounds.length} 轮得到完整 COMPILED PDF`,
      details: rounds
        .filter((round) => round?.compile?.ok !== true || round?.compile?.preview_status !== "COMPILED")
        .map((round) => `第 ${round?.round || "?"} 轮未得到完整编译 PDF`),
    },
    {
      id: "quality-visual",
      label: "逐页视觉复核",
      state: !visualRecorded
        ? "skipped"
        : stateFromCheck(visualCheck, visual.checked === true && visual.ok === true),
      summary: !visualRecorded
        ? "该旧任务未记录此阶段（不是检查通过）"
        : visualCheck?.skipped === true
        ? "本次未要求运行"
        : `回答 ${Number(lastAudit.page_count || 0)} 页；定点修复 ${Number(visual.repair_count || 0)} 项；`
          + `未解决 ${Array.isArray(visual.unresolved) ? visual.unresolved.length : 0}`,
      details: [...reasons(visual.invalid), ...reasons(visual.unresolved)],
    },
    {
      id: "final-inventory",
      label: "最终结构清单",
      state: !finalRecorded
        ? "skipped"
        : stateFromCheck(finalCheck, blockers.length === 0 && Boolean(finalInventory.schema)),
      summary: !finalRecorded
        ? "该旧任务未记录此阶段（不是检查通过）"
        : finalCheck?.skipped === true
        ? "本次未要求运行"
        : `formal 标题 ${Number(counts.anchors || 0)}；环境 ${Number(counts.environments || 0)}；阻断 ${blockers.length}`,
      details: reasons(blockers),
    },
  ];
}

function dashboardNumber(...values) {
  for (const value of values) {
    if (value === "" || value == null) continue;
    const number = Number(value);
    if (Number.isFinite(number)) return Math.max(0, Math.trunc(number));
  }
  return null;
}

function dashboardSeconds(job = {}, metrics = {}) {
  const explicit = dashboardNumber(
    metrics.elapsed_seconds,
    metrics.total_elapsed_seconds,
    job.elapsed_seconds,
    job.duration_seconds,
  );
  if (explicit != null) return explicit;
  const started = Date.parse(job.started_at || job.snapshot?.started_at || "");
  const ended = Date.parse(job.finished_at || job.completed_at || "");
  if (!Number.isFinite(started)) return null;
  return Math.max(0, Math.round(((Number.isFinite(ended) ? ended : Date.now()) - started) / 1000));
}

function dashboardArtifact(job, name, fallbackAvailable = false) {
  const stores = [
    job?.artifacts,
    job?.outputs,
    job?.result?.artifacts,
    job?.snapshot?.artifacts,
  ].filter(Boolean);
  for (const store of stores) {
    const value = store?.[name];
    if (typeof value === "string" && value) return { available: true, url: value };
    if (value && typeof value === "object") {
      return {
        available: value.available !== false && value.exists !== false,
        url: value.download_url || value.url || value.href || "",
        filename: value.filename || value.name || "",
      };
    }
    if (value === true) return { available: true, url: "" };
  }
  return { available: Boolean(fallbackAvailable), url: "" };
}

export function formatProcessDuration(seconds) {
  const value = Number(seconds);
  if (!Number.isFinite(value) || value < 0) return "暂无";
  const rounded = Math.round(value);
  if (rounded < 60) return `${rounded} 秒`;
  const hours = Math.floor(rounded / 3600);
  const minutes = Math.floor((rounded % 3600) / 60);
  if (hours) return `${hours} 小时 ${minutes} 分`;
  return `${minutes} 分钟`;
}

export function buildAnalysisDashboard(job = {}, verification = {}, decisions = [], info = {}) {
  const analysisPerformance = verification?.analysis_v2?.performance
    || job.result?.verification?.analysis_v2?.performance
    || verification?.v2_verification_evidence?.performance;
  const metrics = job.performance_metrics
    || job.progress_metrics
    || job.metrics
    || analysisPerformance
    || {};
  const benchmarkMetrics = analysisPerformance
    || job.performance_metrics
    || metrics;
  const issueCounts = job.issue_counts || job.issue_summary || job.result?.issue_counts || {};
  const ledger = Array.isArray(job.issue_ledger)
    ? job.issue_ledger
    : Array.isArray(job.result?.issue_ledger) ? job.result.issue_ledger : [];
  const decisionItems = Array.isArray(decisions) ? decisions : [];
  const statusCounts = ledger.reduce((counts, issue) => {
    const status = String(issue?.current_status || issue?.status || "OPEN").toUpperCase();
    counts[status] = (counts[status] || 0) + 1;
    return counts;
  }, {});
  const found = dashboardNumber(
    issueCounts.found,
    issueCounts.total,
    metrics.issues_found,
    job.issues_found,
    ledger.length || null,
    decisionItems.length || null,
  ) || 0;
  const fixed = dashboardNumber(
    issueCounts.fixed,
    issueCounts.verified_closed,
    metrics.issues_fixed,
    job.issues_fixed,
    statusCounts.VERIFIED_CLOSED,
    decisionItems.filter((item) => item?.status === "applied").length || null,
  ) || 0;
  const blocked = dashboardNumber(
    issueCounts.blocked,
    metrics.blocked_issues,
    job.blocked_issues,
    statusCounts.BLOCKED,
  ) || 0;
  const remaining = dashboardNumber(
    issueCounts.remaining,
    issueCounts.open,
    metrics.issues_remaining,
    job.issues_remaining,
    (statusCounts.OPEN || 0) + (statusCounts.FIXING || 0)
      + (statusCounts.FIXED_PENDING_REVIEW || 0) + (statusCounts.REGRESSION || 0),
  ) ?? Math.max(0, found - fixed);
  const totalPages = dashboardNumber(
    metrics.total_pages,
    benchmarkMetrics.total_pages,
    job.page_count,
    job.total_pages,
    info.page_count,
  );
  const benchmarkPageCount = 600;
  const reportedBenchmarkPageCount = dashboardNumber(
    benchmarkMetrics.benchmark_page_count,
  ) ?? benchmarkPageCount;
  const benchmarkElapsed = Number(benchmarkMetrics.elapsed_seconds);
  const benchmarkCheckedPages = dashboardNumber(benchmarkMetrics.checked_pages);
  const benchmarkFinalStatus = String(benchmarkMetrics.final_status || "").toUpperCase();
  const benchmarkTotalPages = dashboardNumber(
    benchmarkMetrics.total_pages,
    job.page_count,
    job.total_pages,
    info.page_count,
  );
  const benchmarkScopeEligible = benchmarkTotalPages === benchmarkPageCount
    && reportedBenchmarkPageCount === benchmarkPageCount
    && benchmarkMetrics.benchmark_eligible === true
    && Number(benchmarkMetrics.target_seconds) === 7200;
  const completeBenchmarkEvidence = benchmarkScopeEligible
    && benchmarkMetrics.available === true
    && benchmarkCheckedPages === benchmarkPageCount
    && Number.isFinite(benchmarkElapsed)
    && benchmarkElapsed > 0;
  const reportedTargetStatus = String(benchmarkMetrics.target_status || "").toUpperCase();
  let performanceTargetStatus = "NOT_EVALUATED";
  if (completeBenchmarkEvidence && benchmarkMetrics.target_evaluated === true) {
    const recomputedTargetMet = benchmarkElapsed <= 7200
      && ["VERIFIED", "COMPLETED_WITH_ISSUES"].includes(benchmarkFinalStatus);
    const recomputedTargetStatus = recomputedTargetMet ? "PASSED" : "FAILED";
    if (reportedTargetStatus === recomputedTargetStatus
      && benchmarkMetrics.target_met === recomputedTargetMet) {
      performanceTargetStatus = recomputedTargetStatus;
    }
  }
  const performanceTargetLabel = performanceTargetStatus === "PASSED"
    ? "已达到"
    : performanceTargetStatus === "FAILED"
      ? "未达到"
      : benchmarkScopeEligible
        ? "未评估（等待完整测量）"
        : "未评估（仅完整 600 页可评）";
  const checkedPages = dashboardNumber(
    metrics.checked_pages,
    metrics.pages_checked,
    job.checked_pages,
    job.pages_checked,
    job.result?.checked_pages,
  );
  const currentValues = metrics.current_pages || job.current_pages || job.current_page_ids;
  const currentPages = (Array.isArray(currentValues) ? currentValues : [
    metrics.current_page,
    job.current_page,
    job.source_page,
  ]).map(Number).filter((value, index, values) => (
    Number.isInteger(value) && value > 0 && values.indexOf(value) === index
  ));
  const currentPhase = describeProcessPhase(job.phase, job.phase_label || job.message);
  const rollbackCount = dashboardNumber(
    metrics.rollback_count,
    metrics.rollbacks,
    job.rollback_count,
    job.rollback_history?.length,
  ) || 0;
  const bestVersion = String(
    job.best_candidate_id
      || job.best_version
      || job.result?.best_candidate_id
      || job.result?.candidate_id
      || (info.has_result ? "已保存最佳版本" : ""),
  );
  const analysisArchive = job.analysis_archive || job.result?.analysis_archive || {};
  // v2 final status is a host-derived, hash-bound archive decision.  Legacy
  // safe_to_export remains useful for the unchanged export endpoints, but it
  // must never promote the analysis dashboard to VERIFIED.
  const rawFinalStatus = String(
    analysisArchive.final_status || job.final_status || job.result?.final_status || "",
  ).toUpperCase();
  let finalStatus = rawFinalStatus;
  if (!["VERIFIED", "COMPLETED_WITH_ISSUES", "FAILED_BEST_RETAINED"].includes(finalStatus)) {
    if (["done", "blocked", "cancelled"].includes(String(job.status || "").toLowerCase())) {
      finalStatus = "COMPLETED_WITH_ISSUES";
    } else if (String(job.status || "").toLowerCase() === "error") {
      finalStatus = "FAILED_BEST_RETAINED";
    } else finalStatus = "";
  }
  const terminal = TERMINAL_STATUSES.has(String(job.status || "").toLowerCase()) || Boolean(finalStatus);

  return {
    stage: String(job.stage_label || job.phase_label || currentPhase.label || "等待开始"),
    stageHelp: currentPhase.help,
    round: dashboardNumber(metrics.current_round, job.current_round, job.round, job.macro_round),
    totalPages,
    performanceTargetStatus,
    performanceTargetMet: performanceTargetStatus === "NOT_EVALUATED"
      ? null
      : performanceTargetStatus === "PASSED",
    performanceTargetLabel,
    checkedPages,
    currentPages,
    found,
    fixed,
    remaining,
    blocked,
    rollbackCount,
    rolledBack: Boolean(job.rolled_back || job.rollback_occurred || rollbackCount > 0),
    bestVersion,
    elapsedSeconds: dashboardSeconds(job, metrics),
    etaSeconds: dashboardNumber(metrics.eta_seconds, metrics.estimated_remaining_seconds, job.eta_seconds),
    finalStatus,
    terminal,
    canContinue: terminal && job.can_refine !== false && Boolean(bestVersion || info.has_result),
    artifacts: [
      { id: "raw-ocr", label: "OCR 原稿 TEX", ...dashboardArtifact(job, "raw_ocr_tex", Boolean(info.raw_ocr_available)) },
      { id: "baseline-tex", label: "OCR 基线 TEX", ...dashboardArtifact(job, "baseline_tex", Boolean(info.baseline_tex_available)) },
      { id: "baseline-pdf", label: "OCR 基线 PDF", ...dashboardArtifact(job, "baseline_pdf", Boolean(info.baseline_pdf_available)) },
      { id: "best-tex", label: "AI 最佳 TEX", ...dashboardArtifact(job, "best_tex", Boolean(info.has_result)) },
      { id: "best-pdf", label: "AI 最佳 PDF", ...dashboardArtifact(job, "best_pdf", Boolean(info.result_pdf_available || job.preview_state === "COMPILED")) },
      { id: "quality-report", label: "简洁质量报告", ...dashboardArtifact(job, "quality_report", Boolean(info.has_report || job.result)) },
    ],
  };
}

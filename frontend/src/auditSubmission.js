export const AUDIT_PROFILES = [
  { value: "quick", label: "快速诊断", hint: "优先保留关键结果、报告和机器检查。" },
  { value: "standard", label: "标准审计", hint: "适合大多数 ChatGPT/Codex 外部复核。" },
  { value: "full", label: "完整取证", hint: "尽可能包含页图、公式裁片和完整日志。" },
];

export const DEFAULT_AUDIT_FORM = Object.freeze({
  profile: "standard",
  audit_focus: "",
  include_source_files: true,
  include_compile_logs: true,
  include_verification_records: true,
  include_page_images: false,
  include_formula_crops: false,
  sanitize_sensitive: true,
});

const WORKFLOW_LABELS = {
  ANALYSIS_REVIEW_ONLY: "仅分析与审阅",
  OCR_ONLY: "仅 OCR",
  OCR_ANALYSIS_REVIEW: "OCR＋分析与审阅",
  TEMPLATE_CONVERSION: "模板转换",
  MULTIFILE_PROJECT: "多文件工程",
};

const RUN_STATUS_LABELS = {
  SUCCESS: "成功",
  UNVERIFIED: "未验证",
  FAILED: "失败",
  PARTIAL: "部分完成",
  CANCELLED: "已取消",
};

const VERIFICATION_STATUS_LABELS = {
  VERIFIED: "机器验证通过",
  UNVERIFIED: "未通过完整机器验证",
  NOT_AVAILABLE: "无机器验证结果",
  UNKNOWN: "验证状态未知",
};

const PROFILE_LABELS = Object.fromEntries(AUDIT_PROFILES.map((item) => [item.value, item.label]));
const CLIENT_STALE_PREFIX = "latexstruct-audit-client-stale-v1";

export function normalizeAuditForm(value = {}) {
  const combinedVerification = value.include_verification_decisions;
  const combinedEvidence = value.include_page_images_formula_crops;
  const profile = AUDIT_PROFILES.some((item) => item.value === value.profile)
    ? value.profile
    : DEFAULT_AUDIT_FORM.profile;
  return {
    profile,
    audit_focus: typeof value.audit_focus === "string" ? value.audit_focus : "",
    include_source_files: value.include_source_files ?? DEFAULT_AUDIT_FORM.include_source_files,
    include_compile_logs: value.include_compile_logs ?? DEFAULT_AUDIT_FORM.include_compile_logs,
    include_verification_records: value.include_verification_records
      ?? combinedVerification
      ?? DEFAULT_AUDIT_FORM.include_verification_records,
    include_page_images: value.include_page_images
      ?? combinedEvidence
      ?? DEFAULT_AUDIT_FORM.include_page_images,
    include_formula_crops: value.include_formula_crops
      ?? combinedEvidence
      ?? DEFAULT_AUDIT_FORM.include_formula_crops,
    sanitize_sensitive: value.sanitize_sensitive ?? DEFAULT_AUDIT_FORM.sanitize_sensitive,
  };
}

export function buildAuditSubmissionRequest(value = {}) {
  const normalized = normalizeAuditForm(value);
  const snapshotId = typeof value.snapshot_id === "string" ? value.snapshot_id.trim() : "";
  return {
    ...normalized,
    audit_focus: normalized.audit_focus.trim(),
    ...(snapshotId ? { snapshot_id: snapshotId } : {}),
  };
}

export function normalizeAuditHistory(value) {
  if (!Array.isArray(value)) return [];
  const seen = new Set();
  return value.flatMap((item) => {
    if (!item || typeof item !== "object") return [];
    const snapshotId = typeof item.snapshot_id === "string" ? item.snapshot_id.trim() : "";
    if (!snapshotId || seen.has(snapshotId)) return [];
    seen.add(snapshotId);
    return [{
      ...item,
      snapshot_id: snapshotId,
      canGenerate: item.can_generate === true || item.can_generate_snapshot === true,
      isLatest: item.is_latest === true,
      historical: item.historical === true || item.is_latest === false,
    }];
  });
}

export function selectableAuditHistory(value) {
  return normalizeAuditHistory(value).filter((item) => {
    const workflow = String(item.workflow || "").toUpperCase();
    const status = String(
      item.terminal_status || item.status || item.run_terminal_status || "",
    ).toUpperCase();
    return item.canGenerate && item.historical && !item.isLatest
      && workflow === "OCR_ONLY" && status === "PARTIAL";
  });
}

export function canOpenAuditSubmissionDialog(currentCanGenerate, history) {
  return currentCanGenerate === true || selectableAuditHistory(history).length > 0;
}

export function isHistoricalAuditSubmission(submission) {
  return Boolean(submission?.historical === true || submission?.is_latest === false);
}

export function reviewAcceptanceRoute(status) {
  const normalized = String(status || "").toLowerCase();
  if (normalized === "rejected") return "unreject";
  if (normalized === "applied") return "accept";
  return "ignore";
}

export function normalizeLatestAuditResponse(payload) {
  const body = payload && typeof payload === "object" ? payload : {};
  return {
    available: body.available === true,
    canGenerate: body.can_generate === true,
    reason: typeof body.reason === "string" ? body.reason : "",
    latest: body.latest && typeof body.latest === "object" ? body.latest : null,
    history: normalizeAuditHistory(body.history),
  };
}

export function blockAuditForPendingTask(value = {}) {
  return {
    available: value?.available === true,
    canGenerate: false,
    reason: "TASK_RUNNING",
  };
}

export function isAuditSubmissionStale(submission) {
  return Boolean(submission?.stale === true || submission?.client_stale === true);
}

export function auditSubmissionActionState(submission, busy = false) {
  const stale = isAuditSubmissionStale(submission);
  const zipReady = String(submission?.bundle_state || "").toUpperCase() === "ZIP_READY"
    || Boolean(submission?.filename && submission?.submission_id);
  return {
    stale,
    zipReady,
    canCopy: !busy && !stale && Boolean(submission?.short_prompt),
    canOpenFolder: !busy && !stale && zipReady,
    canDownload: !busy && !stale && zipReady,
    canRegenerate: !busy,
  };
}

export function forceAuditSubmissionStale(submission, reason = "审阅状态已改变") {
  if (!submission || typeof submission !== "object") return submission;
  const reasons = Array.isArray(submission.stale_reasons)
    ? submission.stale_reasons.filter((item) => typeof item === "string" && item.trim())
    : [];
  if (reason && !reasons.includes(reason)) reasons.unshift(reason);
  return {
    ...submission,
    client_stale: true,
    stale_reasons: reasons,
  };
}

export function reconcileAuditMutationFailure(
  storage,
  pid,
  submission,
  reason = "审阅操作失败，正在重新核对宿主状态",
) {
  clearAuditClientStale(storage, pid, submission);
  return forceAuditSubmissionStale(submission, reason);
}

export function auditClientStaleKey(pid, submissionId) {
  return `${CLIENT_STALE_PREFIX}:${String(pid || "")}:${String(submissionId || "")}`;
}

export function readAuditClientStale(storage, pid, submission) {
  if (!storage || !submission?.submission_id) return submission;
  try {
    const reason = storage.getItem(auditClientStaleKey(pid, submission.submission_id));
    return reason ? forceAuditSubmissionStale(submission, reason) : submission;
  } catch {
    return submission;
  }
}

export function rememberAuditClientStale(storage, pid, submission, reason) {
  if (!storage || !submission?.submission_id) return;
  try {
    storage.setItem(auditClientStaleKey(pid, submission.submission_id), reason || "审阅状态已改变");
  } catch {}
}

export function clearAuditClientStale(storage, pid, submission) {
  if (!storage || !submission?.submission_id) return;
  try {
    storage.removeItem(auditClientStaleKey(pid, submission.submission_id));
  } catch {}
}

export function auditWorkflowLabel(value) {
  return WORKFLOW_LABELS[value] || value || "工作流未知";
}

export function auditRunStatusLabel(value) {
  return RUN_STATUS_LABELS[value] || value || "状态未知";
}

export function auditVerificationStatusLabel(value) {
  return VERIFICATION_STATUS_LABELS[value] || value || "验证状态未知";
}

export function auditProfileLabel(value) {
  return PROFILE_LABELS[value] || value || PROFILE_LABELS.standard;
}

export function auditUnavailableReason(reason) {
  const labels = {
    NO_TERMINAL_RUN: "任务进入终态后即可生成",
    TASK_RUNNING: "任务仍在运行，请等待终态快照冻结",
    AUDIT_STATUS_UNAVAILABLE: "暂时无法读取审计提交包状态，请稍后重试",
    SNAPSHOT_UNAVAILABLE: "本次运行尚未形成可用快照",
    PROJECT_NOT_READY: "项目材料尚未准备完成",
  };
  return labels[reason] || reason || "当前尚不能生成审计提交包";
}

export function formatAuditCreatedAt(value) {
  if (!value) return "时间未知";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return String(value);
  return new Intl.DateTimeFormat("zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(parsed);
}

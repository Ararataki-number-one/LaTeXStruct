import assert from "node:assert/strict";
import test from "node:test";

import {
  DEFAULT_AUDIT_FORM,
  auditClientStaleKey,
  auditRunStatusLabel,
  auditSubmissionActionState,
  auditWorkflowLabel,
  blockAuditForPendingTask,
  buildAuditSubmissionRequest,
  canOpenAuditSubmissionDialog,
  clearAuditClientStale,
  forceAuditSubmissionStale,
  isHistoricalAuditSubmission,
  isAuditSubmissionStale,
  normalizeAuditForm,
  normalizeAuditHistory,
  normalizeLatestAuditResponse,
  readAuditClientStale,
  reconcileAuditMutationFailure,
  rememberAuditClientStale,
  reviewAcceptanceRoute,
  selectableAuditHistory,
} from "../src/auditSubmission.js";

function memoryStorage() {
  const values = new Map();
  return {
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, String(value)),
    removeItem: (key) => values.delete(key),
  };
}

test("standard 是默认审计档位且默认清理敏感信息", () => {
  assert.equal(DEFAULT_AUDIT_FORM.profile, "standard");
  assert.equal(DEFAULT_AUDIT_FORM.sanitize_sensitive, true);
  assert.equal(DEFAULT_AUDIT_FORM.include_source_files, true);
  assert.equal(DEFAULT_AUDIT_FORM.include_page_images, false);
  assert.equal(DEFAULT_AUDIT_FORM.include_formula_crops, false);
});

test("请求只包含策略字段，不允许客户端提交文件角色或路径", () => {
  const request = buildAuditSubmissionRequest({
    ...DEFAULT_AUDIT_FORM,
    audit_focus: "  检查定理边界  ",
    artifact_roles: ["source"],
    files: ["C:/secret/source.tex"],
  });
  assert.deepEqual(Object.keys(request).sort(), [
    "audit_focus",
    "include_compile_logs",
    "include_formula_crops",
    "include_page_images",
    "include_source_files",
    "include_verification_records",
    "profile",
    "sanitize_sensitive",
  ].sort());
  assert.equal(request.audit_focus, "检查定理边界");
  assert.equal("artifact_roles" in request, false);
  assert.equal("files" in request, false);
});

test("兼容旧的合并验证和证据选项", () => {
  const normalized = normalizeAuditForm({
    include_verification_decisions: false,
    include_page_images_formula_crops: false,
  });
  assert.equal(normalized.include_verification_records, false);
  assert.equal(normalized.include_page_images, false);
  assert.equal(normalized.include_formula_crops, false);
});

test("latest 契约只接受显式 available 和 can_generate", () => {
  const latest = { submission_id: "sub-1", stale: false };
  assert.deepEqual(normalizeLatestAuditResponse({
    available: true,
    can_generate: true,
    reason: null,
    latest,
  }), {
    available: true,
    canGenerate: true,
    reason: "",
    latest,
    history: [],
  });
  assert.equal(normalizeLatestAuditResponse({ available: 1, can_generate: "yes" }).canGenerate, false);
});

test("历史运行选择只接受宿主给出的不可变 OCR_ONLY/PARTIAL 快照", () => {
  const history = selectableAuditHistory([
    {
      snapshot_id: "snap-ocr",
      workflow: "OCR_ONLY",
      run_terminal_status: "PARTIAL",
      is_latest: false,
      can_generate_snapshot: true,
    },
    {
      snapshot_id: "snap-current",
      workflow: "OCR_ONLY",
      run_terminal_status: "PARTIAL",
      is_latest: true,
      can_generate_snapshot: true,
    },
    {
      snapshot_id: "snap-analysis",
      workflow: "ANALYSIS_REVIEW_ONLY",
      run_terminal_status: "PARTIAL",
      is_latest: false,
      can_generate_snapshot: true,
    },
    {
      snapshot_id: "snap-ocr-success",
      workflow: "OCR_ONLY",
      run_terminal_status: "SUCCESS",
      is_latest: false,
      can_generate_snapshot: true,
    },
    {
      snapshot_id: "snap-no-host-permission",
      workflow: "OCR_ONLY",
      run_terminal_status: "PARTIAL",
      is_latest: false,
    },
    { snapshot_id: "snap-ocr", workflow: "OCR_ONLY", can_generate: true },
  ]);
  assert.deepEqual(history.map((item) => item.snapshot_id), ["snap-ocr"]);
  assert.equal(normalizeAuditHistory(null).length, 0);
});

test("历史选择读取后端真实 terminal_status 字段", () => {
  const selected = selectableAuditHistory([{
    snapshot_id: "snapshot-contract",
    workflow: "OCR_ONLY",
    terminal_status: "PARTIAL",
    historical: true,
    is_latest: false,
    can_generate_snapshot: true,
  }]);
  assert.equal(selected.length, 1);
  assert.equal(selected[0].snapshot_id, "snapshot-contract");
});

test("显式历史请求只携带宿主 snapshot_id，历史结果保持独立标识", () => {
  const request = buildAuditSubmissionRequest({
    ...DEFAULT_AUDIT_FORM,
    snapshot_id: "  snap-history-1  ",
  });
  assert.equal(request.snapshot_id, "snap-history-1");
  assert.equal(isHistoricalAuditSubmission({ historical: true }), true);
  assert.equal(isHistoricalAuditSubmission({ is_latest: false }), true);
  assert.equal(isHistoricalAuditSubmission({ is_latest: true }), false);
});

test("普通任务一启动就关闭组包入口，不能沿用旧的 can_generate", () => {
  assert.deepEqual(blockAuditForPendingTask({
    available: true,
    canGenerate: true,
    reason: "",
  }), {
    available: true,
    canGenerate: false,
    reason: "TASK_RUNNING",
  });
  assert.equal(canOpenAuditSubmissionDialog(false, []), false);
});

test("运行中 OCR_ONLY/PARTIAL 也只能由后端显式 can_generate 重新开放", () => {
  const blocked = blockAuditForPendingTask({ available: true, canGenerate: true });
  assert.equal(blocked.canGenerate, false);

  const explicitOcr = normalizeLatestAuditResponse({
    available: true,
    can_generate: true,
    reason: "",
    latest: {
      submission_id: "sub-ocr-partial",
      workflow: "OCR_ONLY",
      terminal_status: "PARTIAL",
      stale: false,
    },
  });
  assert.equal(explicitOcr.canGenerate, true);
  assert.equal(canOpenAuditSubmissionDialog(false, [{
    snapshot_id: "snap-explicit-history",
    workflow: "OCR_ONLY",
    run_terminal_status: "PARTIAL",
    is_latest: false,
    can_generate: true,
  }]), true);

  const implicitOcr = normalizeLatestAuditResponse({
    available: true,
    latest: { workflow: "OCR_ONLY", terminal_status: "PARTIAL" },
  });
  assert.equal(implicitOcr.canGenerate, false);
});

test("客户端 freshness guard 只能把提交包降为 stale，不能提升状态", () => {
  const original = {
    submission_id: "sub-2",
    verification_status: "UNVERIFIED",
    stale: false,
    stale_reasons: [],
  };
  const guarded = forceAuditSubmissionStale(original, "审阅确认已改变");
  assert.equal(isAuditSubmissionStale(guarded), true);
  assert.equal(guarded.verification_status, "UNVERIFIED");
  assert.deepEqual(guarded.stale_reasons, ["审阅确认已改变"]);
});

test("stale 提交包不能复制、打开或下载，只能重新生成", () => {
  const actions = auditSubmissionActionState({
    submission_id: "sub-stale",
    bundle_state: "ZIP_READY",
    filename: "audit.zip",
    short_prompt: "请审计",
    stale: true,
  });
  assert.deepEqual(actions, {
    stale: true,
    zipReady: true,
    canCopy: false,
    canOpenFolder: false,
    canDownload: false,
    canRegenerate: true,
  });
});

test("审阅操作发起时可立即把旧包降为 stale 并禁用全部使用动作", () => {
  const prior = {
    submission_id: "sub-before-review",
    bundle_state: "ZIP_READY",
    filename: "audit.zip",
    short_prompt: "请审计",
    stale: false,
  };
  assert.equal(auditSubmissionActionState(prior).canDownload, true);
  const pendingMutation = forceAuditSubmissionStale(prior, "审阅确认状态正在改变");
  const actions = auditSubmissionActionState(pendingMutation);
  assert.equal(actions.canCopy, false);
  assert.equal(actions.canOpenFolder, false);
  assert.equal(actions.canDownload, false);
});

test("rejected 项的接受动作必须先走 unreject，不能直接写 accepted metadata", () => {
  assert.equal(reviewAcceptanceRoute("rejected"), "unreject");
  assert.equal(reviewAcceptanceRoute("applied"), "accept");
  assert.equal(reviewAcceptanceRoute("ambiguous"), "ignore");
  assert.equal(reviewAcceptanceRoute(null), "ignore");
});

test("审阅 API 失败时保留内存 fail-closed，但清除本次持久 stale 供宿主 latest 纠正", () => {
  const storage = memoryStorage();
  const original = {
    submission_id: "sub-review-api-failed",
    bundle_state: "ZIP_READY",
    filename: "audit.zip",
    short_prompt: "请审计",
    stale: false,
  };
  rememberAuditClientStale(storage, "pid-review-failed", original, "审阅确认状态正在改变");
  const pendingReconciliation = reconcileAuditMutationFailure(
    storage,
    "pid-review-failed",
    original,
  );

  assert.equal(isAuditSubmissionStale(pendingReconciliation), true);
  assert.equal(auditSubmissionActionState(pendingReconciliation).canDownload, false);
  assert.equal(
    isAuditSubmissionStale(readAuditClientStale(storage, "pid-review-failed", original)),
    false,
  );
});

test("接受审阅后的 stale guard 可跨页面重新加载并可由新包清除", () => {
  const storage = memoryStorage();
  const submission = { submission_id: "sub-3", stale: false };
  rememberAuditClientStale(storage, "pid-1", submission, "审阅确认已改变");
  assert.equal(isAuditSubmissionStale(readAuditClientStale(storage, "pid-1", submission)), true);
  clearAuditClientStale(storage, "pid-1", submission);
  assert.equal(isAuditSubmissionStale(readAuditClientStale(storage, "pid-1", submission)), false);
  assert.match(auditClientStaleKey("pid-1", "sub-3"), /pid-1:sub-3$/);
});

test("工作流和终态标签不根据 verified 状态自行推断", () => {
  const workflows = {
    ANALYSIS_REVIEW_ONLY: "仅分析与审阅",
    OCR_ONLY: "仅 OCR",
    OCR_ANALYSIS_REVIEW: "OCR＋分析与审阅",
    TEMPLATE_CONVERSION: "模板转换",
    MULTIFILE_PROJECT: "多文件工程",
  };
  const statuses = {
    SUCCESS: "成功",
    UNVERIFIED: "未验证",
    FAILED: "失败",
    PARTIAL: "部分完成",
    CANCELLED: "已取消",
  };
  for (const [value, label] of Object.entries(workflows)) {
    assert.equal(auditWorkflowLabel(value), label);
  }
  for (const [value, label] of Object.entries(statuses)) {
    assert.equal(auditRunStatusLabel(value), label);
  }
  assert.equal(auditRunStatusLabel("CUSTOM_STATE"), "CUSTOM_STATE");
});

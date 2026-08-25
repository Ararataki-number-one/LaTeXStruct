import assert from "node:assert/strict";
import test from "node:test";

import {
  buildAnalysisDashboard,
  buildProcessStageTrail,
  describeExecutionProgress,
  describeProcessPhase,
  processStageStateLabel,
  summarizeVerificationStages,
  verificationCheckDisplayLabel,
  verificationFailureTitle,
} from "../src/processStatus.js";


test("quality stages use plain-language labels and expose the current stage", () => {
  assert.deepEqual(describeProcessPhase("preflight"), {
    label: "正在核对输入证据",
    help: "验证冻结源文件、哈希、页数和选择范围。",
  });
  assert.deepEqual(describeProcessPhase("full-review"), {
    label: "正在全文独立复核",
    help: "检查初次扫描未发现的漏套、错套和多套。",
  });
  assert.equal(describeProcessPhase("quality-compile").label, "正在全文真实编译");
  assert.equal(describeProcessPhase("quality-visual").label, "正在逐页视觉复核");

  const trail = buildProcessStageTrail({
    status: "running",
    phase: "quality-visual",
    events: [
      { phase: "scan" },
      { phase: "decide" },
      { phase: "full-review" },
      { phase: "review" },
      { phase: "quality-compile" },
      { phase: "quality-visual" },
    ],
  });
  assert.equal(trail.find((stage) => stage.id === "quality-visual").state, "current");
  assert.equal(trail.find((stage) => stage.id === "quality-compile").state, "completed");
  assert.equal(trail.find((stage) => stage.id === "final-inventory").state, "pending");
});


test("a preflight exception marks the input gate failed instead of every core stage unrun", () => {
  const trail = buildProcessStageTrail({
    status: "error",
    phase: "error",
    failure_phase: "preflight",
    failure_progress: 0.01,
    events: [
      { phase: "queued" },
      { phase: "preflight" },
      { phase: "audit_submission", scope: "finalization" },
      { phase: "error" },
    ],
  });

  assert.equal(trail.find((stage) => stage.id === "preflight").state, "failed");
  assert.equal(trail.find((stage) => stage.id === "inventory").state, "skipped");
  assert.equal(trail.find((stage) => stage.id === "gate").state, "skipped");
});


test("bounded event history cannot erase an early completed stage", () => {
  const trail = buildProcessStageTrail({
    status: "error",
    phase: "error",
    failure_phase: "quality-compile",
    reached_phases: ["queued", "preflight", "parse", "scan", "decide", "quality-compile"],
    events: Array.from({ length: 40 }, (_, index) => ({
      phase: "quality-compile",
      message: `compile ${index}`,
    })),
  });

  assert.equal(trail.find((stage) => stage.id === "preflight").state, "completed");
  assert.equal(trail.find((stage) => stage.id === "inventory").state, "completed");
  assert.equal(trail.find((stage) => stage.id === "quality-compile").state, "failed");
});


test("terminal jobs distinguish completed, failed and genuinely skipped stages", () => {
  const trail = buildProcessStageTrail({
    status: "blocked",
    phase: "verification_failed",
    events: [
      { phase: "scan" },
      { phase: "decide" },
      { phase: "draft" },
      { phase: "report" },
      { phase: "verification_failed" },
    ],
  });
  assert.equal(trail.find((stage) => stage.id === "inventory").state, "completed");
  assert.equal(trail.find((stage) => stage.id === "full-review").state, "skipped");
  assert.equal(trail.find((stage) => stage.id === "quality-visual").state, "skipped");
  assert.equal(trail.find((stage) => stage.id === "final-inventory").state, "completed");
  assert.equal(trail.find((stage) => stage.id === "gate").state, "failed");
});


test("verification summary explains compile, visual and final inventory failures", () => {
  const rows = summarizeVerificationStages({
    checks: [
      { id: "full-document-review", ok: true, skipped: false },
      { id: "compile-render-visual-repair", ok: false, skipped: false },
      { id: "final-formal-inventory", ok: false, skipped: false },
    ],
    full_document_review: {
      checked: true,
      ok: true,
      chunks: [{}, {}],
      invalid: [],
      escalations: [],
    },
    visual_quality_loop: {
      required: true,
      checked: false,
      ok: false,
      repair_count: 1,
      invalid: [],
      unresolved: [{ reason: "源 PDF 第 7 页没有对应编译页" }],
      rounds: [{
        round: 1,
        compile: { ok: true, preview_status: "COMPILED" },
        ai_audit: { page_count: 16 },
      }, {
        round: 2,
        compile: { ok: false, preview_status: "PARTIAL_COMPILED" },
      }],
    },
    final_formal_inventory: {
      schema: "latexstruct-formal-inventory-v1",
      counts: { anchors: 9, environments: 8 },
      findings: [{ kind: "wrong-env", reason: "Theorem 3.4 被套成 lemma" }],
    },
  });

  assert.deepEqual(rows.map((row) => [row.id, row.state]), [
    ["full-review", "passed"],
    ["quality-compile", "failed"],
    ["quality-visual", "failed"],
    ["final-inventory", "failed"],
  ]);
  assert.match(rows[0].summary, /复核 2 个分段/);
  assert.match(rows[1].summary, /1\/2 轮/);
  assert.match(rows[2].summary, /回答 16 页/);
  assert.deepEqual(rows[2].details, ["源 PDF 第 7 页没有对应编译页"]);
  assert.match(rows[3].summary, /阻断 1/);
  assert.deepEqual(rows[3].details, ["Theorem 3.4 被套成 lemma"]);
});


test("skipped quality checks are called not run, never passed", () => {
  const rows = summarizeVerificationStages({
    checks: [
      { id: "full-document-review", ok: true, skipped: true },
      { id: "compile-render-visual-repair", ok: true, skipped: true },
      { id: "final-formal-inventory", ok: true, skipped: true },
    ],
    visual_quality_loop: { required: false, rounds: [] },
    final_formal_inventory: { counts: {}, findings: [] },
  });
  assert.ok(rows.every((row) => row.state === "skipped"));
  assert.equal(rows[0].summary, "本次未要求运行");
  assert.equal(rows[1].summary, "本次未要求运行");
  assert.equal(rows[2].summary, "本次未要求运行");
});


test("user-disabled second review is explicitly neutral in stage and quality copy", () => {
  const verification = {
    checks: [
      {
        id: "full-document-review",
        ok: null,
        skipped: true,
        skip_reason: "user-disabled",
      },
    ],
    full_document_review: {
      checked: false,
      ok: false,
      status: "USER_DISABLED",
      skip_reason: "user-disabled",
    },
  };
  const rows = summarizeVerificationStages(verification);
  assert.equal(rows[0].state, "skipped");
  assert.equal(rows[0].summary, "用户未启用第二遍复查（不计为失败）");
  assert.equal(processStageStateLabel({ id: "full-review", state: "skipped" }, verification),
    "用户未启用（不计为失败）");
  assert.equal(processStageStateLabel({ id: "ai-review", state: "skipped" }, verification),
    "用户未启用（不计为失败）");
});


test("failure titles collapse legacy repeated label summaries", () => {
  const label = "最终 TEX 已重新盘点且无漏套、错套、多套或重复 formal 环境";
  assert.equal(
    verificationFailureTitle({ label, summary: `${label}未通过` }),
    `${label}：未通过`,
  );
  assert.equal(
    verificationFailureTitle({ label, summary: "最终清点仍有 3 个 formal 阻断项" }),
    `${label}：最终清点仍有 3 个 formal 阻断项`,
  );
  assert.equal(
    verificationFailureTitle({ label, summary: `${label}：${label}未通过` }),
    `${label}：未通过`,
  );
});


test("terminal skipped stages say why they did not run", () => {
  const blocked = { status: "blocked" };
  assert.equal(
    processStageStateLabel({ id: "ai-review", state: "skipped" }, {}, blocked),
    "因安全检查未通过而未执行",
  );
  assert.equal(
    processStageStateLabel({ id: "quality-visual", state: "skipped" }, {}, { status: "error" }),
    "因处理错误而中止",
  );
  assert.equal(
    processStageStateLabel({ id: "full-review", state: "skipped" }, {
      checks: [{ id: "full-document-review", skipped: true, skip_reason: "user-disabled" }],
    }, blocked),
    "用户未启用（不计为失败）",
  );
});


test("100 percent represents execution completion, never an implied verification pass", () => {
  assert.deepEqual(describeExecutionProgress({ status: "blocked", progress: 1 }), {
    percent: 100,
    label: "执行进度",
    detail: "执行完成；安全检查未通过",
  });
  assert.match(describeExecutionProgress({ status: "running", progress: 0.5 }).detail, /尚未形成验证结论/);
  assert.equal(
    verificationCheckDisplayLabel({ label: "全文独立复核", ok: true, skipped: true, skip_reason: "user-disabled" }),
    "·全文独立复核（用户未启用）",
  );
  assert.match(
    verificationCheckDisplayLabel({ label: "逐页视觉复核", ok: true, skipped: true }),
    /配置跳过；未形成通过结论/,
  );
});


test("legacy verification without quality evidence is not displayed as passed or failed", () => {
  const rows = summarizeVerificationStages({ safe_to_export: false, checks: [] });
  assert.ok(rows.every((row) => row.state === "skipped"));
  assert.ok(rows.every((row) => row.summary.includes("旧任务未记录")));
  assert.ok(rows.every((row) => row.summary.includes("不是检查通过")));
});


test("analysis dashboard exposes rounds, pages, issue ledger, rollback and best version", () => {
  const dashboard = buildAnalysisDashboard({
    status: "running",
    phase: "quality-visual",
    current_round: 3,
    checked_pages: 15,
    page_count: 17,
    current_pages: [8, 9],
    issue_counts: { total: 9, verified_closed: 5, remaining: 3, blocked: 1 },
    rollback_history: [{ candidate_id: "round-2" }],
    best_candidate_id: "round-1",
    progress_metrics: { elapsed_seconds: 420, eta_seconds: 180 },
  }, {}, [], {});
  assert.equal(dashboard.round, 3);
  assert.equal(dashboard.checkedPages, 15);
  assert.deepEqual(dashboard.currentPages, [8, 9]);
  assert.deepEqual([dashboard.found, dashboard.fixed, dashboard.remaining, dashboard.blocked], [9, 5, 3, 1]);
  assert.equal(dashboard.rolledBack, true);
  assert.equal(dashboard.bestVersion, "round-1");
  assert.equal(dashboard.etaSeconds, 180);
  assert.equal(dashboard.performanceTargetStatus, "NOT_EVALUATED");
  assert.equal(dashboard.performanceTargetMet, null);
  assert.match(dashboard.performanceTargetLabel, /仅完整 600 页可评/);
});


test("analysis dashboard keeps the 600-page target tri-state and rejects short-run promotion", () => {
  const short = buildAnalysisDashboard({
    page_count: 37,
    performance_metrics: {
      total_pages: 37,
      target_seconds: 7200,
      target_status: "PASSED",
      target_met: true,
    },
  }, {}, [], {});
  assert.equal(short.performanceTargetStatus, "NOT_EVALUATED");
  assert.equal(short.performanceTargetMet, null);

  const complete = buildAnalysisDashboard({ page_count: 600 }, {
    analysis_v2: {
      performance: {
        available: true,
        total_pages: 600,
        checked_pages: 600,
        elapsed_seconds: 7000,
        final_status: "VERIFIED",
        benchmark_page_count: 600,
        benchmark_eligible: true,
        target_seconds: 7200,
        target_status: "PASSED",
        target_evaluated: true,
        target_met: true,
      },
    },
  }, [], {});
  assert.equal(complete.performanceTargetStatus, "PASSED");
  assert.equal(complete.performanceTargetMet, true);
  assert.equal(complete.performanceTargetLabel, "已达到");

  const legacy = buildAnalysisDashboard({
    page_count: 600,
    performance_metrics: { total_pages: 600, target_met: true },
  }, {}, [], {});
  assert.equal(legacy.performanceTargetStatus, "NOT_EVALUATED");
  assert.equal(legacy.performanceTargetMet, null);
});


test("analysis benchmark evidence is not shadowed by coexisting OCR performance metrics", () => {
  const dashboard = buildAnalysisDashboard({
    page_count: 600,
    performance_metrics: {
      schema_version: "latexstruct-ocr-performance-metrics-v2",
      pages: {
        selected: 600,
        coverage_completed: 600,
        remaining: 0,
      },
      throughput: { average_pages_per_minute: 25 },
    },
  }, {
    analysis_v2: {
      performance: {
        available: true,
        total_pages: 600,
        checked_pages: 600,
        elapsed_seconds: 7000,
        final_status: "VERIFIED",
        benchmark_page_count: 600,
        benchmark_eligible: true,
        target_seconds: 7200,
        target_status: "PASSED",
        target_evaluated: true,
        target_met: true,
      },
    },
  }, [], {});

  assert.equal(dashboard.performanceTargetStatus, "PASSED");
  assert.equal(dashboard.performanceTargetMet, true);
  assert.equal(dashboard.performanceTargetLabel, "已达到");
});


test("analysis dashboard maps terminal states without upgrading unverified work", () => {
  const issues = buildAnalysisDashboard({
    status: "blocked",
    result: { final_status: "COMPLETED_WITH_ISSUES", best_candidate_id: "best-7" },
  }, { safe_to_export: false }, [], { has_result: true });
  assert.equal(issues.finalStatus, "COMPLETED_WITH_ISSUES");
  assert.equal(issues.canContinue, true);
  assert.equal(issues.artifacts.find((item) => item.id === "best-tex").available, true);

  const verified = buildAnalysisDashboard({
    status: "done",
    result: { analysis_archive: { final_status: "VERIFIED", verified: true } },
  }, { safe_to_export: true }, [], { has_result: true });
  assert.equal(verified.finalStatus, "VERIFIED");

  const legacy = buildAnalysisDashboard(
    { status: "done" },
    { safe_to_export: true },
    [],
    { has_result: true },
  );
  assert.equal(legacy.finalStatus, "COMPLETED_WITH_ISSUES");

  const v2Issues = buildAnalysisDashboard({
    status: "done",
    result: {
      analysis_archive: {
        final_status: "COMPLETED_WITH_ISSUES",
        verified: false,
      },
    },
  }, { safe_to_export: true }, [], { has_result: true });
  assert.equal(v2Issues.finalStatus, "COMPLETED_WITH_ISSUES");

  const failed = buildAnalysisDashboard({ status: "error" }, { safe_to_export: false }, [], { has_result: true });
  assert.equal(failed.finalStatus, "FAILED_BEST_RETAINED");
});

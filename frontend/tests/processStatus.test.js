import assert from "node:assert/strict";
import test from "node:test";

import {
  buildProcessStageTrail,
  describeProcessPhase,
  summarizeVerificationStages,
} from "../src/processStatus.js";


test("quality stages use plain-language labels and expose the current stage", () => {
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


test("legacy verification without quality evidence is not displayed as passed or failed", () => {
  const rows = summarizeVerificationStages({ safe_to_export: false, checks: [] });
  assert.ok(rows.every((row) => row.state === "skipped"));
  assert.ok(rows.every((row) => row.summary.includes("旧任务未记录")));
  assert.ok(rows.every((row) => row.summary.includes("不是检查通过")));
});

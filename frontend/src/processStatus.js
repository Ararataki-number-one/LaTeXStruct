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
        ? "本次未要求运行"
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

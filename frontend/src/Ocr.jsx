import { useEffect, useRef, useState } from "react";
import Editor from "@monaco-editor/react";
import { api } from "./api";
import { apiAuthority, sameApiAuthority } from "./providerUrl";
import {
  buildOcrArtifacts,
  buildOcrProgress,
  buildOcrRecoveryPresentation,
  formatOcrDuration,
  formatPagesPerMinute,
  legacyOcrQualityProfile,
  normalizeOcrQualityTier,
  ocrPagePresentation,
  OCR_QUALITY_TIERS,
  qualityTierLabel,
} from "./ocrPresentation";

const OCR_SESSION_JOB_KEY = "latexstruct-current-ocr-job-v1";
const CODEX_BACKEND = "codex_cli";
// 兼容 v1.1.2 的 10 位旧任务号；新任务使用完整 UUID4 hex（128-bit）。
const OCR_JOB_ID_RE = /^(?:[0-9a-f]{10}|[0-9a-f]{32})$/;
const OCR_ACTIVE_STATUSES = new Set(["starting", "running", "pausing", "paused"]);

function rememberedOcrJobId() {
  try {
    const value = String(window.sessionStorage.getItem(OCR_SESSION_JOB_KEY) || "");
    if (!OCR_JOB_ID_RE.test(value)) {
      if (value) window.sessionStorage.removeItem(OCR_SESSION_JOB_KEY);
      return "";
    }
    return value;
  } catch {
    return "";
  }
}

function rememberOcrJobId(jobId) {
  const value = String(jobId || "");
  if (!OCR_JOB_ID_RE.test(value)) return false;
  try {
    window.sessionStorage.setItem(OCR_SESSION_JOB_KEY, value);
    return true;
  } catch {
    return false;
  }
}

function forgetOcrJobId(jobId = "") {
  try {
    const current = window.sessionStorage.getItem(OCR_SESSION_JOB_KEY);
    if (!jobId || current === jobId) {
      window.sessionStorage.removeItem(OCR_SESSION_JOB_KEY);
    }
  } catch {
    // sessionStorage 不可用不影响服务端的显式保全与删除门禁。
  }
}

function ocrStatusLabel(status) {
  return ({
    ready: "已读取页数",
    starting: "正在启动",
    running: "正在处理",
    pausing: "正在安全暂停",
    done: "已完成",
    partial: "部分完成",
    error: "处理失败",
    paused: "已暂停",
  })[status] || "等待处理";
}

function qualityPageNumbers(report) {
  const pages = report?.pages || {};
  return new Set([
    ...(pages.failed_or_incomplete || []),
    ...(pages.low_confidence || []),
    ...(pages.needs_review || []),
    ...(pages.missing_provenance || []),
  ].map(Number).filter(Number.isInteger));
}

function QualityGateCard({ job, onSelectPage }) {
  const report = job?.quality_report;
  if (!report) return null;
  const running = report.status === "running";
  const passed = report.page_gate_passed === true;
  const findings = running ? [] : [
    ...(Array.isArray(report.blockers) ? report.blockers : []),
    ...(Array.isArray(report.warnings) ? report.warnings : []),
  ];
  const counts = report.counts || {};
  const statusLabel = running ? "检查中" : passed ? "检查完成" : "有待确认页面";

  return (
    <section
      className={`ocr-quality-gate ${running ? "running" : passed ? "passed" : "blocked"}`}
      role={passed || running ? "status" : "alert"}
      aria-label="OCR 页面检查"
    >
      <div className="quality-gate-heading">
        <div>
          <b>问题页检查</b>
          <span>已完成页面会保留；只需重试下方列出的页面。</span>
        </div>
        <strong>{statusLabel}</strong>
      </div>
      <div className="quality-gate-metrics">
        <span>完成 {counts.completed_pages || 0}/{counts.selected_pages || 0} 页</span>
        <span>低置信 {counts.low_confidence_pages || 0}</span>
        <span>待复核 {counts.needs_review_pages || 0}</span>
        <span>来源缺失 {counts.missing_provenance_pages || 0}</span>
        <span>局部证据 {counts.local_evidence_pages || 0} 页</span>
      </div>
      {findings.length > 0 && (
        <div className="quality-gate-findings">
          {findings.map((finding, index) => (
            <div key={`${finding.code || "finding"}-${index}`}>
              <span>{finding.message || "发现页级质量问题"}</span>
              {Array.isArray(finding.pages) && finding.pages.length > 0 && (
                <span className="quality-page-links">
                  {finding.pages.slice(0, 12).map((page) => (
                    <button type="button" key={page} onClick={() => onSelectPage(Number(page))}>
                      P{page}
                    </button>
                  ))}
                  {finding.pages.length > 12 && <small>另有 {finding.pages.length - 12} 页</small>}
                </span>
              )}
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

function ocrSnapshotPreserved(job) {
  const rawRevision = Number(job?.raw_revision || 0);
  const usageRevision = Number(job?.usage_revision || 0);
  const pageRevision = Number(job?.page_revision || 0);
  return rawRevision > 0 && ["downloaded", "imported"].some((kind) => (
    Number(job?.[`${kind}_revision`] || 0) === rawRevision
    && Number(job?.[`${kind}_usage_revision`] || 0) === usageRevision
    && Number(job?.[`${kind}_page_revision`] || 0) === pageRevision
  ));
}

function sameApiHost(left, right) {
  return sameApiAuthority(left, right);
}

function hasConfiguredKey(value) {
  return String(value || "").startsWith("已配置");
}

function matchingPreset(baseUrl, model, providers) {
  const authority = apiAuthority(baseUrl);
  if (!authority.startsWith("https://")) return null;
  return providers.find((item) => {
    const presetAuthority = apiAuthority(item.base_url);
    return presetAuthority.startsWith("https://")
      && presetAuthority === authority
      && item.model === model;
  }) || null;
}

function ocrReadiness(setup, overrideModel, customVisionConfirmed) {
  if (setup.status === "loading") {
    return { blocked: true, reason: "正在检查 OCR 引擎……" };
  }
  if (setup.status === "error") {
    return {
      blocked: true,
      reason: "无法确认 OCR 配置，已阻止启动。请前往设置页检查后重试。",
    };
  }

  const cfg = setup.config || {};
  if (cfg.analysis_backend === CODEX_BACKEND) {
    if (!setup.codexStatus?.ready) {
      return {
        blocked: true,
        codex: true,
        reason: setup.codexStatusError
          || setup.codexStatus?.message
          || "本机 Codex 尚未就绪。请在设置中完成 ChatGPT 登录并刷新状态。",
      };
    }
    return {
      blocked: false,
      codex: true,
      reason: "OCR 已就绪：图片/PDF 将由 Codex 视觉能力处理，使用 ChatGPT/Codex 订阅额度。需要联网，并非离线识别。",
    };
  }
  const baseUrl = cfg.ocr_base_url || cfg.decide_base_url || "";
  const effectiveModel = overrideModel.trim() || cfg.ocr_model || cfg.decide_model || "";
  const authority = apiAuthority(baseUrl);
  const preset = matchingPreset(baseUrl, effectiveModel, setup.providers || []);
  const isDeepSeek = authority === "https://api.deepseek.com:443"
    || String(effectiveModel).toLowerCase().startsWith("deepseek")
    || preset?.provider === "deepseek";
  const hasKey = hasConfiguredKey(cfg.ocr_api_key)
    || (sameApiHost(baseUrl, cfg.decide_base_url) && hasConfiguredKey(cfg.decide_api_key))
    || (sameApiHost(baseUrl, cfg.review_base_url) && hasConfiguredKey(cfg.review_api_key));

  if (!baseUrl) {
    return { blocked: true, reason: "尚未配置 OCR API Host。请先前往设置选择视觉服务商。" };
  }
  if (!authority) {
    return { blocked: true, reason: "OCR API Host 格式不安全或无效。请前往设置检查协议、端口和地址。" };
  }
  if (!effectiveModel) {
    return { blocked: true, reason: "尚未选择视觉模型。请先前往设置选择 Qwen 视觉模型。" };
  }
  if (isDeepSeek) {
    return {
      blocked: true,
      reason: "当前 OCR 指向 DeepSeek。DeepSeek 不支持图片输入，不能用于视觉 OCR；请在设置中改用 Qwen 视觉模型。",
    };
  }
  if (!hasKey) {
    return { blocked: true, reason: "视觉模型尚未配置 API Key。请先前往设置安全保存 Key。" };
  }
  if (preset && !preset.vision) {
    return { blocked: true, reason: "当前模型不支持图片输入。请在设置中选择视觉模型。" };
  }
  if (!preset?.vision && !customVisionConfirmed) {
    return {
      blocked: true,
      needsConfirmation: true,
      reason: `无法自动确认“${effectiveModel}”支持图片输入。请改用内置视觉模型，或仅在确认其具备视觉能力后继续。`,
    };
  }
  return {
    blocked: false,
    custom: !preset?.vision,
    reason: preset?.vision
      ? `OCR 已就绪：${preset.label}`
      : `OCR 已就绪：已确认自定义视觉模型 ${effectiveModel}`,
  };
}

export default function Ocr({ onImport, onOpenSettings }) {
  const [files, setFiles] = useState([]);
  const file = files[0] || null;
  const [startPage, setStartPage] = useState("1");
  const [endPage, setEndPage] = useState("");
  const [pdfInfo, setPdfInfo] = useState({ status: "idle", total: 0, maxPages: 500, jobId: null });
  const [dpi, setDpi] = useState(200);
  const [qualityTier, setQualityTier] = useState("recommended");
  const [model, setModel] = useState("");
  const [setup, setSetup] = useState({ status: "loading", config: null, providers: [] });
  const [customVisionConfirmed, setCustomVisionConfirmed] = useState(false);
  const [job, setJob] = useState(null);
  const [current, setCurrent] = useState(null);
  const [currentTex, setCurrentTex] = useState("");
  const [previewMode, setPreviewMode] = useState("live");
  const [focusLivePreview, setFocusLivePreview] = useState(false);
  const [liveTex, setLiveTex] = useState("");
  const [liveRevision, setLiveRevision] = useState(0);
  const [rawSaved, setRawSaved] = useState(null);
  const [importingProject, setImportingProject] = useState(false);
  const [msg, setMsg] = useState("");
  const [starting, setStarting] = useState(false);
  const [restoringJob, setRestoringJob] = useState(() => Boolean(rememberedOcrJobId()));
  const [restoreFailed, setRestoreFailed] = useState(false);
  const [restoreNonce, setRestoreNonce] = useState(0);
  const [retryingPage, setRetryingPage] = useState(null);
  const [retryingFailed, setRetryingFailed] = useState(false);
  const [controlAction, setControlAction] = useState("");
  const [rawSaving, setRawSaving] = useState(false);
  const [pollingStopped, setPollingStopped] = useState(false);
  const [pollNonce, setPollNonce] = useState(0);
  const inspectSequence = useRef(0);
  const inspectedJobId = useRef(null);
  const liveEditorRef = useRef(null);
  const activeJobId = useRef(null);
  const pageSelectionSequence = useRef(0);
  const retryLockRef = useRef(false);
  const controlLockRef = useRef(false);
  const snapshotEpochRef = useRef(0);
  const snapshotRevisionRef = useRef({ jobId: "", revision: -1 });

  const applyJobSnapshot = (next) => {
    if (!next?.id || (activeJobId.current && activeJobId.current !== next.id)) return false;
    const revision = Number(next.state_revision);
    const previous = snapshotRevisionRef.current;
    if (
      previous.jobId === next.id
      && Number.isFinite(revision)
      && revision < previous.revision
    ) {
      return false;
    }
    snapshotRevisionRef.current = {
      jobId: next.id,
      revision: Number.isFinite(revision) ? revision : previous.jobId === next.id ? previous.revision : -1,
    };
    setQualityTier(normalizeOcrQualityTier(next.quality_tier, next.quality_profile));
    if (Number.isFinite(Number(next.dpi)) && Number(next.dpi) >= 72) {
      setDpi(Number(next.dpi));
    }
    setJob(next);
    return true;
  };

  const snapshotFromPayload = (payload) => {
    if (payload?.job?.id && payload.job.pages) return payload.job;
    if (payload?.id && payload.pages) return payload;
    return null;
  };

  const refreshJob = async (jid) => {
    const next = await (await api(`/api/ocr/jobs/${jid}`)).json();
    applyJobSnapshot(next);
    return next;
  };

  const inspectFile = async (selected, sequence = inspectSequence.current) => {
    const selectedFiles = Array.isArray(selected) ? selected.filter(Boolean) : (selected ? [selected] : []);
    const selectedIsPdf = selectedFiles.length === 1 && /\.pdf$/i.test(selectedFiles[0]?.name || "");
    const selectedIsCollection = selectedFiles.length > 1;
    const expectedSourceType = selectedIsPdf ? "pdf" : (selectedIsCollection ? "images" : "image");
    setPdfInfo({ status: "loading", total: 0, maxPages: 500, jobId: null });
    setMsg(selectedIsPdf
      ? "正在上传 PDF 并读取总页数……"
      : (selectedIsCollection ? `正在按选择顺序上传 ${selectedFiles.length} 张图片……` : "正在上传图片并准备转写……"));
    const form = new FormData();
    selectedFiles.forEach((item) => form.append("file", item));
    try {
      const info = await (await api("/api/ocr/inspect", { method: "POST", body: form })).json();
      if (sequence !== inspectSequence.current) {
        api(`/api/ocr/jobs/${info.id}`, { method: "DELETE" }).catch(() => {});
        return;
      }
      if (info.source_type !== expectedSourceType) {
        await api(`/api/ocr/jobs/${info.id}`, { method: "DELETE" }).catch(() => {});
        throw new Error("服务识别的文件类型与所选文件不一致");
      }
      if (!rememberOcrJobId(info.id)) {
        await api(`/api/ocr/jobs/${info.id}`, { method: "DELETE" }).catch(() => {});
        throw new Error("OCR 任务编号无效或浏览器无法保存恢复信息，请重试");
      }
      inspectedJobId.current = info.id;
      const defaultEnd = Math.min(info.total_pages, info.max_pages_per_job);
      setStartPage("1");
      setEndPage(String(defaultEnd));
      setPdfInfo({
        status: "ready",
        total: info.total_pages,
        maxPages: info.max_pages_per_job,
        jobId: info.id,
      });
      if (selectedIsPdf) {
        setMsg(info.total_pages > info.max_pages_per_job
          ? `已读取 PDF：共 ${info.total_pages} 页；为控制耗时与费用，默认选择前 ${defaultEnd} 页`
          : `已读取 PDF：共 ${info.total_pages} 页，默认处理全部`);
      } else if (selectedIsCollection) {
        setMsg(`已按选择顺序保存 ${info.total_pages} 张原始图片；本地生成的视觉 PDF 仅用于逐页识别`);
      } else {
        setMsg("图片已安全上传，可开始单页转写");
      }
    } catch (error) {
      if (sequence !== inspectSequence.current) return;
      inspectedJobId.current = null;
      setPdfInfo({ status: "error", total: 0, maxPages: 500, jobId: null });
      setMsg((selectedIsPdf ? "无法读取 PDF 页数：" : "无法准备图片：") + error.message);
    }
  };

  const chooseFile = async (selected) => {
    const selectedFiles = Array.isArray(selected) ? selected.filter(Boolean) : (selected ? [selected] : []);
    const pdfCount = selectedFiles.filter((item) => /\.pdf$/i.test(item?.name || "")).length;
    if (pdfCount && (pdfCount !== 1 || selectedFiles.length !== 1)) {
      setMsg("PDF 必须单独选择；多文件模式仅支持按顺序选择 PNG/JPG 图片");
      return false;
    }
    if (restoringJob || restoreFailed) {
      setMsg("正在恢复上一份 OCR 任务，请稍候再选择新文件");
      return false;
    }
    if (retryLockRef.current || retryingPage !== null || retryingFailed || rawSaving) {
      setMsg(retryLockRef.current || retryingPage !== null || retryingFailed
        ? "OCR 失败页正在重试，请等待完成后再选择新文件"
        : "原始 OCR 正在保存，请等待完成后再选择新文件");
      return false;
    }
    if (job?.importing) {
      setMsg("OCR 结果正在导入项目，请等待完成后再选择新文件");
      return false;
    }
    const recovery = buildOcrRecoveryPresentation(job || {});
    if (recovery.canResumeIncomplete) {
      setMsg(`上一份 OCR 还有 ${recovery.incompleteCount} 页未完成；请先继续任务或明确放弃。`);
      return false;
    }

    let latestJob = job;
    if (job?.id && ["done", "partial", "error"].includes(job.status)) {
      try {
        latestJob = await refreshJob(job.id);
      } catch {
        // 无法刷新时沿用页面上最后一次状态，并按未保全处理，避免静默丢失结果。
      }
      const preserved = ocrSnapshotPreserved(latestJob);
      const usage = latestJob?.usage || {};
      const hasValuableResult = Boolean(
        latestJob?.raw_ready || Number(usage.calls || 0) > 0 || Number(usage.total_tokens || 0) > 0,
      );
      if (hasValuableResult && !preserved && !window.confirm(
        "当前 OCR 已产生结果或费用，但最新结果还没有下载或导入项目。切换文件会永久放弃这些内容，是否继续？",
      )) {
        setMsg("已保留当前 OCR 结果；请先下载原稿或打开项目");
        return false;
      }
    }
    if (
      latestJob?.importing || latestJob?.saving
      || OCR_ACTIVE_STATUSES.has(latestJob?.status)
    ) {
      setMsg("上一份 OCR 仍在处理或已暂停；请先继续完成任务，再选择新文件");
      return false;
    }

    const previous = inspectedJobId.current;
    const disposableJobs = new Set();
    if (previous) disposableJobs.add(previous);
    if (latestJob?.id && !OCR_ACTIVE_STATUSES.has(latestJob.status)) {
      disposableJobs.add(latestJob.id);
    }
    try {
      await Promise.all(Array.from(disposableJobs).map(
        (jid) => api(`/api/ocr/jobs/${jid}`, { method: "DELETE" }),
      ));
    } catch (error) {
      setMsg("暂时无法安全清理上一份 OCR 文件：" + error.message);
      return false;
    }
    forgetOcrJobId();
    const sequence = inspectSequence.current + 1;
    inspectSequence.current = sequence;
    inspectedJobId.current = null;
    activeJobId.current = null;
    snapshotEpochRef.current += 1;
    snapshotRevisionRef.current = { jobId: "", revision: -1 };
    pageSelectionSequence.current += 1;
    setFiles(selectedFiles);
    setJob(null);
    setCurrent(null);
    setCurrentTex("");
    setPreviewMode("live");
    setLiveTex("");
    setLiveRevision(0);
    setRestoreFailed(false);
    setPollingStopped(false);
    if (!selectedFiles.length) {
      setPdfInfo({ status: "idle", total: 0, maxPages: 500, jobId: null });
      setMsg("");
      return true;
    }
    inspectFile(selectedFiles, sequence);
    return true;
  };

  const isPdf = Boolean(file && /\.pdf$/i.test(file.name || ""));
  const isImageCollection = files.length > 1;
  const isPagedSource = isPdf || isImageCollection;
  const startNumber = Number(startPage);
  const endNumber = Number(endPage);
  let pageRangeError = "";
  let selectedPageCount = 0;
  if (isPagedSource && pdfInfo.status === "ready") {
    if (!/^\d+$/.test(startPage) || !/^\d+$/.test(endPage)) {
      pageRangeError = "起始页和结束页必须填写整数";
    } else if (startNumber < 1 || endNumber > pdfInfo.total) {
      pageRangeError = `页码必须位于 1-${pdfInfo.total} 页内`;
    } else if (startNumber > endNumber) {
      pageRangeError = "起始页不能大于结束页";
    } else {
      selectedPageCount = endNumber - startNumber + 1;
      if (selectedPageCount > pdfInfo.maxPages) {
        pageRangeError = `单次最多处理 ${pdfInfo.maxPages} 页，请缩小范围`;
      }
    }
  }

  const start = async () => {
    if (restoringJob || restoreFailed) {
      setMsg("上一份 OCR 状态尚未恢复，请先点击“重试恢复”");
      return;
    }
    if (job?.id) {
      setMsg("已有当前 OCR 任务；请先保存或导入结果，或明确放弃本次任务后再重新开始");
      return;
    }
    const readiness = ocrReadiness(setup, model, customVisionConfirmed);
    if (readiness.blocked) {
      setMsg(readiness.reason);
      return;
    }
    if (!file) return alert("请选择 PDF 或图片");
    if (pdfInfo.status !== "ready" || !pdfInfo.jobId || (isPagedSource && pageRangeError)) {
      setMsg(pageRangeError || "请等待文件上传与页数读取完成后再开始");
      return;
    }
    const fd = new FormData();
    fd.append("dpi", String(dpi));
    fd.append("model", model);
    fd.append("quality_tier", qualityTier);
    fd.append("quality_profile", legacyOcrQualityProfile(qualityTier));
    // OCR 阶段只做忠实转写与基线恢复，不冻结任何出版模板。
    fd.append("output_template", "");
    const endpoint = `/api/ocr/jobs/${pdfInfo.jobId}/start`;
    if (isPagedSource) {
      fd.append("start_page", startPage);
      fd.append("end_page", endPage);
      setMsg(isPdf
        ? `正在启动原 PDF 第 ${startPage}-${endPage} 页转写……`
        : `正在启动所选图片序列第 ${startPage}-${endPage} 张转写……`);
    } else {
      setMsg("正在启动图片转写……");
    }
    setCurrent(null);
    pageSelectionSequence.current += 1;
    setCurrentTex("");
    setPreviewMode("live");
    setLiveTex("");
    setLiveRevision(0);
    setStarting(true);
    setPollingStopped(false);
    try {
      const r = await api(endpoint, { method: "POST", body: fd });
      const { id } = await r.json();
      if (id !== pdfInfo.jobId) throw new Error("服务返回了不一致的 OCR 任务编号");
      const recoverable = rememberOcrJobId(id);
      activeJobId.current = id;
      snapshotRevisionRef.current = { jobId: id, revision: -1 };
      inspectedJobId.current = null;
      setRestoreFailed(false);
      setJob({
        id,
        status: "running",
        source_type: isPdf ? "pdf" : (isImageCollection ? "images" : "image"),
        source_total: isPagedSource ? pdfInfo.total : 1,
        total: isPagedSource ? selectedPageCount : 1,
        done: 0,
        raw_revision: 0,
        raw_chars: 0,
        usage_revision: 0,
        page_revision: 0,
        quality_tier: qualityTier,
        quality_profile: legacyOcrQualityProfile(qualityTier),
        output_template: "",
        dpi,
        pages: {},
      });
      setMsg((isPagedSource ? "正在逐页处理所选范围……" : "正在处理图片……")
        + (recoverable ? "" : " 浏览器无法记录恢复信息，本次处理完成前请勿离开 OCR 页面。"));
    } catch (e) {
      try {
        const recovered = await (await api(`/api/ocr/jobs/${pdfInfo.jobId}`)).json();
        if (recovered.id !== pdfInfo.jobId) throw new Error("恢复到的任务编号不一致");
        if (recovered.status === "ready") {
          setMsg("启动尚未生效，可再次点击“开始 OCR”：" + e.message);
        } else {
          activeJobId.current = recovered.id;
          snapshotRevisionRef.current = {
            jobId: recovered.id,
            revision: Number.isFinite(Number(recovered.state_revision))
              ? Number(recovered.state_revision) : -1,
          };
          inspectedJobId.current = null;
          setQualityTier(normalizeOcrQualityTier(recovered.quality_tier, recovered.quality_profile));
          setJob(recovered);
          setRestoreFailed(false);
          setMsg("启动响应曾中断，已通过原任务编号恢复，未重复创建 OCR 任务");
        }
      } catch (recoveryError) {
        if (recoveryError?.status === 404) {
          forgetOcrJobId(pdfInfo.jobId);
          inspectedJobId.current = null;
          setPdfInfo({ status: "error", total: 0, maxPages: 500, jobId: null });
          setMsg("启动失败且上传任务已失效，请重新选择文件：" + e.message);
        } else {
          setRestoreFailed(true);
          setMsg("启动响应中断，暂时无法确认后台状态；任务编号已保留，请点击“重试恢复”，不要重新上传");
        }
      }
    } finally {
      setStarting(false);
    }
  };

  const selectPage = async (n) => {
    const page = job?.pages?.[n];
    if (ocrPagePresentation(page).pending) return;
    const selectedJobId = job?.id;
    if (!selectedJobId) return;
    const selection = pageSelectionSequence.current + 1;
    pageSelectionSequence.current = selection;
    setCurrent(n);
    liveEditorRef.current = null;
    setPreviewMode("page");
    try {
      const text = await (await api(`/api/ocr/jobs/${selectedJobId}/pages/${n}/tex`)).text();
      if (
        selection !== pageSelectionSequence.current
        || activeJobId.current !== selectedJobId
      ) return;
      setCurrentTex(text);
    } catch (error) {
      if (
        selection !== pageSelectionSequence.current
        || activeJobId.current !== selectedJobId
      ) return;
      setCurrentTex("");
      setMsg("暂时无法读取本页结果：" + error.message);
    }
  };

  const retry = async (n) => {
    if (retryLockRef.current || retryingPage !== null || retryingFailed || rawSaving) return;
    const retryJobId = job?.id;
    const retrySequence = inspectSequence.current;
    if (!retryJobId) return;
    retryLockRef.current = true;
    snapshotEpochRef.current += 1;
    setRetryingPage(n);
    const label = job?.source_type === "pdf" ? `原第 ${n} 页` : "图片";
    setMsg(`${label}重试中……`);
    const stillCurrent = () => (
      retrySequence === inspectSequence.current
      && activeJobId.current === retryJobId
    );
    const refreshRetrySnapshot = async () => {
      try {
        const latest = await (await api(`/api/ocr/jobs/${retryJobId}`)).json();
        if (!stillCurrent()) return null;
        applyJobSnapshot(latest);
        return latest;
      } catch {
        return null;
      }
    };
    try {
      await api(`/api/ocr/jobs/${retryJobId}/pages/${n}/retry`, { method: "POST" });
      const updated = await refreshRetrySnapshot();
      if (!updated || !stillCurrent()) return;
      await selectPage(n);
      if (updated?.status === "done") {
        setMsg("原始 OCR 已保留，可逐页检查或开始 AI 自动整理");
      } else if (updated?.status === "partial") {
        setMsg("本页重试后仍有失败页面；请查看错误后再次重试");
      } else {
        setMsg("重试已提交，请查看页面状态");
      }
    } catch (e) {
      const latest = await refreshRetrySnapshot();
      if (!stillCurrent()) return;
      if (latest?.status === "running") {
        setMsg(`${label}重试连接中断，但后台仍在处理；已恢复自动轮询`);
      } else if (latest?.status === "done") {
        await selectPage(n);
        setMsg("重试已在后台完成，原始 OCR 已更新并保留");
      } else if (latest?.status === "partial") {
        await selectPage(n);
        setMsg(ocrPagePresentation(latest.pages?.[n]).success
          ? "本页已在后台重试成功；仍有其他失败页面需要处理"
          : "本页后台重试后仍失败，请查看错误并再次重试");
      } else if (!latest && !e?.status) {
        // POST 的响应断开时无法判断服务端是否已接收。保守恢复轮询，避免把
        // 仍在扣费/运行的任务误显示成终态。
        setJob((previous) => previous?.id === retryJobId
          ? { ...previous, status: "running", phase: "正在确认单页重试状态" }
          : previous);
        setMsg(`${label}重试连接中断，正在重新确认后台状态……`);
      } else {
        setMsg(`${label}重试失败：${e.message}`);
      }
    } finally {
      try {
        const latest = await refreshRetrySnapshot();
        if (stillCurrent()) {
          if (latest?.status === "running") {
            setMsg(`${label}仍在后台重试，已继续自动接收进度`);
          }
          setRetryingPage(null);
          setPollNonce((value) => value + 1);
        }
      } finally {
        retryLockRef.current = false;
      }
    }
  };

  const controlOcr = async (action) => {
    const controlJobId = job?.id;
    if (
      !controlJobId
      || !["pause", "resume"].includes(action)
      || controlLockRef.current
      || retryLockRef.current
      || rawSaving
      || job?.saving
      || job?.importing
    ) return;
    controlLockRef.current = true;
    snapshotEpochRef.current += 1;
    setControlAction(action);
    setMsg(action === "pause"
      ? "已请求安全暂停；当前正在渲染或识别的页面会先完成并保留。"
      : "正在继续 OCR，不会重复识别已完成页……");
    try {
      const payload = await (await api(`/api/ocr/jobs/${controlJobId}/${action}`, {
        method: "POST",
      })).json();
      if (activeJobId.current !== controlJobId) return;
      const next = snapshotFromPayload(payload)
        || await (await api(`/api/ocr/jobs/${controlJobId}`)).json();
      if (activeJobId.current !== controlJobId) return;
      applyJobSnapshot(next);
      if (action === "pause") {
        setMsg(next.status === "paused"
          ? "OCR 已安全暂停；已完成页、图片与 Token 记录均已保留。"
          : "正在完成当前页，随后安全暂停……");
      } else {
        setMsg("OCR 已继续，将从下一个未完成页开始。");
      }
      setPollingStopped(false);
      setPollNonce((value) => value + 1);
    } catch (error) {
      if (activeJobId.current !== controlJobId) return;
      try {
        const latest = await (await api(`/api/ocr/jobs/${controlJobId}`)).json();
        if (activeJobId.current === controlJobId) applyJobSnapshot(latest);
      } catch {
        // 控制请求的响应可能丢失；保留任务号与当前快照，由轮询继续确认。
      }
      setMsg(`${action === "pause" ? "暂停" : "继续"} OCR 失败：${error.message}`);
      setPollingStopped(false);
      setPollNonce((value) => value + 1);
    } finally {
      controlLockRef.current = false;
      if (activeJobId.current === controlJobId) setControlAction("");
    }
  };

  const retryFailedPages = async () => {
    if (retryLockRef.current || rawSaving || job?.saving || job?.importing) return;
    const retryJobId = job?.id;
    if (!retryJobId) return;
    retryLockRef.current = true;
    snapshotEpochRef.current += 1;
    setRetryingFailed(true);
    setPollingStopped(false);
    setMsg("正在重新排队所有失败页；已成功页不会重复识别……");
    try {
      const payload = await (await api(`/api/ocr/jobs/${retryJobId}/retry-failed`, {
        method: "POST",
      })).json();
      if (activeJobId.current !== retryJobId) return;
      const next = snapshotFromPayload(payload)
        || await (await api(`/api/ocr/jobs/${retryJobId}`)).json();
      if (activeJobId.current !== retryJobId) return;
      applyJobSnapshot(next);
      setMsg(next.status === "running"
        ? "失败页已重新排队，正在后台顺序识别；可在页边界安全暂停。"
        : "失败页重试请求已提交。");
      setPollNonce((value) => value + 1);
    } catch (error) {
      if (activeJobId.current !== retryJobId) return;
      try {
        const latest = await (await api(`/api/ocr/jobs/${retryJobId}`)).json();
        if (activeJobId.current === retryJobId) applyJobSnapshot(latest);
      } catch {
        // 任务编号仍保留，不根据一次断连假定后台未接收请求。
      }
      setMsg("重试所有失败页失败：" + error.message);
      setPollNonce((value) => value + 1);
    } finally {
      retryLockRef.current = false;
      if (activeJobId.current === retryJobId) setRetryingFailed(false);
    }
  };

  const importProject = async () => {
    setImportingProject(true);
    setMsg("正在创建项目；随后会进入工作台实时显示整理进度……");
    try {
      const sourceStem = String(file?.name || "OCR")
        .replace(/\.[^.]+$/, "")
        .replace(/\s+/g, " ")
        .trim()
        .slice(0, 60) || "OCR";
      const pageRange = job.source_type === "pdf"
        ? `-P${job.selected_start || 1}-${job.selected_end || job.source_total || 1}`
        : "";
      const projectName = `${sourceStem}-OCR${pageRange}`;
      const params = new URLSearchParams({
        name: projectName,
        title: sourceStem,
        mode: "ai",
        template: "",
      });
      const r = await api(`/api/ocr/jobs/${job.id}/import?${params.toString()}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      const { id } = await r.json();
      forgetOcrJobId(job.id);
      onImport(id);
    } catch (e) {
      setMsg("无法进入审阅：" + e.message);
    } finally {
      setImportingProject(false);
    }
  };

  const copyRawResult = async () => {
    try {
      const text = await (await api(`/api/ocr/jobs/${job.id}/result`)).text();
      let copied = false;
      if (navigator.clipboard?.writeText) {
        try {
          await navigator.clipboard.writeText(text);
          copied = true;
        } catch {
          // WebView 可能暴露接口但拒绝权限，继续使用 textarea 兜底。
        }
      }
      if (!copied) {
        const area = document.createElement("textarea");
        area.value = text;
        area.setAttribute("readonly", "");
        area.style.position = "fixed";
        area.style.opacity = "0";
        document.body.appendChild(area);
        try {
          area.select();
          copied = document.execCommand("copy");
        } finally {
          area.remove();
        }
      }
      if (!copied) throw new Error("系统未允许访问剪贴板");
      setMsg("已复制当前原始 OCR LaTeX");
    } catch (error) {
      setMsg("复制原始 OCR 失败：" + error.message);
    }
  };

  const saveRawResult = async () => {
    if (rawSaving || retryLockRef.current || retryBusy) return;
    setRawSaving(true);
    setMsg("正在把 OCR 工程 ZIP（TEX+图片）保存到下载文件夹……");
    try {
      const saved = await (await api(`/api/ocr/jobs/${job.id}/save`, { method: "POST" })).json();
      setRawSaved({ ...saved, jobId: job.id });
      setMsg(`已保存 ${saved.filename} 到 ${saved.folder}`);
    } catch (error) {
      setMsg("保存 OCR 工程 ZIP 失败：" + error.message);
    } finally {
      setRawSaving(false);
    }
  };

  const openDownloadFolder = async () => {
    try {
      await api("/api/exports/open-folder", { method: "POST" });
      setMsg(`已打开 ${rawSaved?.folder || "下载/LaTeXStruct"}`);
    } catch (error) {
      setMsg("无法打开保存位置：" + error.message);
    }
  };

  const browserDownloadRaw = async () => {
    try {
      const response = await api(`/api/ocr/jobs/${job.id}/package`);
      const blob = await response.blob();
      if (!blob.size) throw new Error("服务返回了空文件");
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = "ocr-project.zip";
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      setMsg("已请求浏览器下载 OCR 工程 ZIP；桌面版若没有保存，请使用主保存按钮。");
    } catch (error) {
      setMsg("浏览器下载失败：" + error.message);
    }
  };

  const discardJob = async () => {
    if (!job?.id || !window.confirm("确定放弃本次 OCR 结果和费用记录吗？此操作无法撤销。")) return;
    try {
      await api(`/api/ocr/jobs/${job.id}`, { method: "DELETE" });
      forgetOcrJobId(job.id);
      activeJobId.current = null;
      snapshotEpochRef.current += 1;
      snapshotRevisionRef.current = { jobId: "", revision: -1 };
      pageSelectionSequence.current += 1;
      setJob(null);
      setFiles([]);
      setCurrent(null);
      setCurrentTex("");
      setPreviewMode("live");
      setLiveTex("");
      setLiveRevision(0);
      setQualityTier("recommended");
      setDpi(200);
      setPdfInfo({ status: "idle", total: 0, maxPages: 500, jobId: null });
      setMsg("本次 OCR 临时结果已清除");
    } catch (error) {
      setMsg("无法清除 OCR 结果：" + error.message);
    }
  };

  useEffect(() => {
    let active = true;
    Promise.all([
      api("/api/config").then((r) => r.json()),
      api("/api/providers").then((r) => r.json()),
    ]).then(async ([config, data]) => {
      let codexStatus = null;
      let codexStatusError = "";
      if (config.analysis_backend === CODEX_BACKEND) {
        try {
          codexStatus = await api("/api/codex/status").then((response) => response.json());
        } catch (error) {
          codexStatusError = error.message;
        }
      }
      if (!active) return;
      setSetup({
        status: "ready",
        config,
        providers: data.providers || [],
        codexStatus,
        codexStatusError,
      });
    }).catch(() => {
      if (active) setSetup({ status: "error", config: null, providers: [] });
    });
    return () => { active = false; };
  }, []);

  useEffect(() => {
    const remembered = rememberedOcrJobId();
    if (!remembered) {
      setRestoringJob(false);
      setRestoreFailed(false);
      return undefined;
    }
    const restoreSequence = inspectSequence.current;
    let active = true;
    setMsg("正在恢复上一份 OCR 任务……");
    api(`/api/ocr/jobs/${remembered}`)
      .then((response) => response.json())
      .then((restored) => {
        if (!active) return;
        if (
          inspectSequence.current !== restoreSequence
          || rememberedOcrJobId() !== remembered
        ) {
          setRestoringJob(false);
          return;
        }
        if (!OCR_JOB_ID_RE.test(String(restored?.id || "")) || restored.id !== remembered) {
          forgetOcrJobId(remembered);
          setRestoringJob(false);
          setRestoreFailed(false);
          setMsg("上一份 OCR 恢复信息无效，已安全清除；请重新选择文件");
          return;
        }
        activeJobId.current = remembered;
        snapshotRevisionRef.current = {
          jobId: remembered,
          revision: Number.isFinite(Number(restored.state_revision))
            ? Number(restored.state_revision) : -1,
        };
        inspectedJobId.current = restored.status === "ready" ? remembered : null;
        setQualityTier(normalizeOcrQualityTier(restored.quality_tier, restored.quality_profile));
        setJob(restored.status === "ready" ? null : restored);
        setCurrent(null);
        setCurrentTex("");
        setPreviewMode("live");
        setLiveTex("");
        setLiveRevision(0);
        setPollingStopped(false);
        setRestoringJob(false);
        setRestoreFailed(false);
        if (restored.source_type === "pdf") {
          const first = Number(restored.selected_start || 1);
          const last = Number(restored.selected_end || restored.source_total || first);
          setStartPage(String(first));
          setEndPage(String(last));
          setPdfInfo({
            status: restored.status === "ready" ? "ready" : "restored",
            total: Number(restored.source_total || last),
            maxPages: 500,
            jobId: restored.status === "ready" ? remembered : null,
          });
        } else {
          setStartPage("1");
          setEndPage("1");
          setPdfInfo({
            status: restored.status === "ready" ? "ready" : "restored",
            total: 1,
            maxPages: 1,
            jobId: restored.status === "ready" ? remembered : null,
          });
        }
        const recovery = buildOcrRecoveryPresentation(restored);
        setMsg(["running", "pausing"].includes(restored.status)
          ? (restored.status === "pausing"
            ? "已恢复上一份 OCR，正在完成当前页后安全暂停……"
            : "已恢复上一份 OCR，正在继续接收逐页进度……")
          : restored.status === "paused"
            ? "已恢复上一份 OCR 的暂停状态；可点击“继续识别”。"
          : recovery.canResumeIncomplete
            ? `已从不可变快照恢复；还有 ${recovery.incompleteCount} 页未完成，可点击“继续未完成页面”。`
          : restored.status === "ready"
            ? `已恢复上一份${restored.source_type === "pdf" ? " PDF 页数记录" : "图片上传记录"}；若文件选择已清空，请重新选择原文件`
            : "已恢复上一份 OCR 结果，可继续检查、保存或导入项目");
      })
      .catch((error) => {
        if (!active) return;
        setRestoringJob(false);
        if (error?.status === 404) {
          forgetOcrJobId(remembered);
          setRestoreFailed(false);
          setMsg("上一份 OCR 已过期或应用曾重启，请重新选择文件");
        } else {
          setRestoreFailed(true);
          setMsg("暂时无法恢复上一份 OCR，任务编号已保留；请稍后返回重试：" + error.message);
        }
      });
    return () => { active = false; };
  }, [restoreNonce]);

  useEffect(() => {
    const localRetryBusy = retryingPage !== null || retryingFailed;
    const busy = OCR_ACTIVE_STATUSES.has(job?.status)
      || Boolean(job?.saving || job?.importing || localRetryBusy);
    if (!job?.id || !busy) return undefined;
    let active = true;
    let timer = null;
    let failures = 0;
    const tick = async () => {
      const requestEpoch = snapshotEpochRef.current;
      try {
        const next = await (await api(`/api/ocr/jobs/${job.id}`)).json();
        if (
          !active
          || requestEpoch !== snapshotEpochRef.current
          || activeJobId.current !== job.id
        ) return;
        if (failures > 0) setMsg("进度连接已恢复，继续接收 OCR 状态");
        failures = 0;
        setPollingStopped(false);
        applyJobSnapshot(next);
        if (OCR_ACTIVE_STATUSES.has(next.status) || next.saving || next.importing || localRetryBusy) {
          timer = setTimeout(tick, next.status === "paused" ? 2500 : 1200);
        }
      } catch (error) {
        if (
          !active
          || requestEpoch !== snapshotEpochRef.current
          || activeJobId.current !== job.id
        ) return;
        failures += 1;
        if (failures <= 5) {
          const delay = Math.min(10000, 800 * (2 ** (failures - 1)));
          setMsg(`进度连接暂时中断，正在自动重试（${failures}/5）……`);
          timer = setTimeout(tick, delay);
        } else {
          setPollingStopped(true);
          setMsg(`无法继续获取进度：${error.message}。OCR 任务可能仍在后台运行。`);
        }
      }
    };
    timer = setTimeout(tick, 300);
    return () => {
      active = false;
      if (timer) clearTimeout(timer);
    };
  }, [job?.id, job?.status, job?.saving, job?.importing, retryingPage, retryingFailed, pollNonce]);

  useEffect(() => {
    if (!job?.status) return;
    const recovery = buildOcrRecoveryPresentation(job);
    if (job.saving) {
      setMsg("正在把 OCR 工程 ZIP（TEX+图片）保存到下载文件夹……");
    } else if (job.importing) {
      setMsg("正在把原始 OCR 导入项目并执行安全检查……");
    } else if (job.status === "done") {
      setMsg("原始 OCR 已保留，可下载原稿或开始 AI 自动整理");
    } else if (job.status === "partial") {
      setMsg(recovery.canResumeIncomplete
        ? `任务从不可变快照恢复，尚有 ${recovery.incompleteCount} 页未完成；请点击“继续未完成页面”。`
        : "部分页面识别失败；成功页已保留，请只重试问题页");
    } else if (job.status === "error") {
      setMsg("OCR 未完成；请检查文件与识别服务设置后重试");
    } else if (job.status === "pausing") {
      setMsg("正在完成当前页，随后安全暂停；已完成结果不会丢失。");
    } else if (job.status === "paused") {
      setMsg("OCR 已安全暂停；可点击“继续识别”从未完成页恢复。");
    } else if (job.status === "running") {
      setMsg("已上传，正在逐页处理……");
    }
  }, [job?.status, job?.saving, job?.importing]);

  useEffect(() => {
    const observedRevision = Number(job?.raw_revision || 0);
    if (!job?.id || observedRevision <= 0 || observedRevision === liveRevision) {
      return undefined;
    }
    let active = true;
    let timer = null;
    let attempts = 0;
    const loadPreview = async () => {
      attempts += 1;
      try {
        const response = await api(`/api/ocr/jobs/${job.id}/preview`);
        const text = await response.text();
        const responseRevision = Number(
          response.headers.get("X-LaTeXStruct-OCR-Revision") || observedRevision,
        );
        if (!active || responseRevision <= liveRevision) return;
        const editor = liveEditorRef.current;
        const shouldFollow = previewMode === "live" && (!editor || (
          editor.getScrollHeight() - editor.getScrollTop() - editor.getLayoutInfo().height < 96
        ));
        setLiveTex(text);
        setLiveRevision(responseRevision);
        if (shouldFollow) {
          window.requestAnimationFrame(() => {
            const currentEditor = liveEditorRef.current;
            const model = currentEditor?.getModel();
            if (active && previewMode === "live" && model) {
              currentEditor.revealLine(model.getLineCount());
            }
          });
        }
      } catch (error) {
        if (!active) return;
        if (attempts < 3) {
          timer = setTimeout(loadPreview, 1000 * attempts);
        } else if (previewMode === "live") {
          setMsg("实时 OCR 草稿暂时无法刷新：" + error.message);
        }
      }
    };
    loadPreview();
    return () => {
      active = false;
      if (timer) clearTimeout(timer);
    };
  }, [job?.id, job?.raw_revision, liveRevision, previewMode]);

  useEffect(() => {
    activeJobId.current = job?.id || null;
  }, [job?.id]);

  useEffect(() => {
    if (rawSaved && (
      rawSaved.jobId !== job?.id || Number(rawSaved.revision) !== Number(job?.raw_revision || 0)
      || Number(rawSaved.usage_revision || 0) !== Number(job?.usage_revision || 0)
      || Number(rawSaved.page_revision || 0) !== Number(job?.page_revision || 0)
    )) {
      setRawSaved(null);
    }
  }, [job?.id, job?.raw_revision, job?.usage_revision, job?.page_revision, rawSaved]);

  useEffect(() => {
    if (current && job?.id) selectPage(current);
  }, [job?.id, current, job?.pages?.[current]?.status]);

  const pageNums = job ? Object.keys(job.pages || {}).map(Number).sort((a, b) => a - b) : [];
  const successfulPages = job
    ? Object.values(job.pages || {}).filter((page) => ocrPagePresentation(page).success).length : 0;
  const failedPageNums = job ? pageNums.filter((n) => {
    const page = job.pages?.[n];
    const presentation = ocrPagePresentation(page);
    return !presentation.success && (
      page?.can_retry === true || (page?.can_retry == null && presentation.failed)
    );
  }) : [];
  const retryBusy = retryingPage !== null || retryingFailed;
  const totalPages = job ? (job.total || pageNums.length || successfulPages) : 0;
  const readiness = ocrReadiness(setup, model, customVisionConfirmed);
  const currentTaskIndex = current == null ? 0 : (job?.pages?.[current]?.task_index || 0);
  const activeQualityTier = job
    ? normalizeOcrQualityTier(job.quality_tier, job.quality_profile)
    : qualityTier;
  const qualityReport = job?.quality_report || null;
  const qualityRetryPageSet = qualityPageNumbers(qualityReport);
  const ocrProgress = buildOcrProgress(job || {});
  const ocrRecovery = buildOcrRecoveryPresentation(job || {});
  const ocrArtifacts = buildOcrArtifacts(job || {});
  const issuePages = Array.from(new Set([
    ...failedPageNums,
    ...ocrRecovery.incompletePageNumbers,
    ...qualityRetryPageSet,
    ...pageNums.filter((n) => job?.pages?.[n]?.needs_review || job?.pages?.[n]?.low_conf),
  ])).sort((a, b) => a - b);
  const terminalOcr = ["done", "partial", "error"].includes(job?.status);

  return (
    <div className="ocr">
      <section className="card">
        <div className="ocr-page-heading">
          <div>
            <h2>OCR 识别</h2>
            <p>把 PDF 或图片忠实转成可编辑 LaTeX，并生成真实编译的 OCR 基线。</p>
          </div>
          {!readiness.blocked && <span className="ocr-ready-badge">识别服务已就绪</span>}
        </div>
        <div
          className={`ocr-config-status ${readiness.blocked ? "blocked" : "ready"}`}
          role={readiness.blocked ? "alert" : "status"}
        >
          <div>
            <b>{readiness.blocked
              ? "OCR 尚未就绪"
              : "可以开始识别"}</b>
            {readiness.blocked && <p>{readiness.reason}</p>}
            {readiness.needsConfirmation && (
              <label className="toggle-line">
                <input
                  type="checkbox"
                  checked={customVisionConfirmed}
                  onChange={(event) => setCustomVisionConfirmed(event.target.checked)}
                />
                我确认该自定义模型支持图片输入
              </label>
            )}
          </div>
          {readiness.blocked && setup.status !== "loading" && (
            <button type="button" onClick={onOpenSettings}>前往设置</button>
          )}
        </div>
        <div className="ocr-start-grid">
          <label className="ocr-file-picker">
            <span>1　选择 PDF 或一组图片</span>
            <input
              type="file"
              accept=".pdf,.png,.jpg,.jpeg"
              multiple
              disabled={restoringJob || restoreFailed || starting || OCR_ACTIVE_STATUSES.has(job?.status)
                || ocrRecovery.canResumeIncomplete || job?.importing || controlAction || retryBusy || rawSaving}
              onChange={async (event) => {
                const accepted = await chooseFile(Array.from(event.target.files || []));
                if (!accepted) event.target.value = "";
              }}
            />
            <small>{isImageCollection
              ? `${files.length} 张图片（按选择顺序）：${files.map((item) => item.name).join("、")}`
              : (file?.name || "支持单个 PDF，或按顺序选择多张 PNG/JPG")}</small>
          </label>
          <fieldset className="ocr-quality-picker" disabled={Boolean(job?.id) || starting || restoringJob || restoreFailed}>
            <legend>2　识别质量</legend>
            <div className="ocr-quality-options">
              {OCR_QUALITY_TIERS.map((tier) => (
                <label key={tier.id} className={activeQualityTier === tier.id ? "active" : ""}>
                  <input
                    type="radio"
                    name="ocr-quality-tier"
                    value={tier.id}
                    checked={activeQualityTier === tier.id}
                    onChange={() => {
                      setQualityTier(tier.id);
                      setDpi(200);
                    }}
                  />
                  <span><b>{tier.label}{tier.recommended ? "（推荐）" : ""}</b><small>{tier.description}</small></span>
                </label>
              ))}
            </div>
          </fieldset>
        </div>
        {file && pdfInfo.status === "loading" && (
          <div className="pdf-range-card loading" role="status">
            {isPdf
              ? "正在上传 PDF 并读取总页数……"
              : (isImageCollection ? `正在按顺序安全上传 ${files.length} 张图片……` : "正在安全上传图片……")}
          </div>
        )}
        {file && pdfInfo.status === "error" && (
          <div className="pdf-range-card error" role="alert">
            <span>{isPdf ? "未能读取 PDF 页数" : "未能准备图片"}，尚未产生 OCR 费用。</span>
            <button type="button" onClick={() => inspectFile(files)}>重新读取</button>
          </div>
        )}
        {isPagedSource && pdfInfo.status === "ready" && (
          <div className="pdf-range-card">
            <div className="pdf-page-total">
              <b>{isPdf ? `PDF 共 ${pdfInfo.total} 页` : `图片序列共 ${pdfInfo.total} 张`}</b>
              <span>{pdfInfo.total > pdfInfo.maxPages
                ? `单次上限 ${pdfInfo.maxPages} 页，默认选择前 ${pdfInfo.maxPages} 页`
                : "默认处理全部，可在开始前缩小范围"}</span>
            </div>
            <label>
              起始页
              <input
                type="number"
                min="1"
                max={pdfInfo.total}
                step="1"
                value={startPage}
                onChange={(event) => setStartPage(event.target.value)}
              />
            </label>
            <span className="range-separator">至</span>
            <label>
              结束页
              <input
                type="number"
                min="1"
                max={pdfInfo.total}
                step="1"
                value={endPage}
                onChange={(event) => setEndPage(event.target.value)}
              />
            </label>
            <div className={`pdf-selection-summary ${pageRangeError ? "invalid" : ""}`}>
              {pageRangeError || (isPdf
                ? `本次处理 ${selectedPageCount} 页（原第 ${startNumber}-${endNumber} 页）`
                : `本次处理 ${selectedPageCount} 张（选择顺序第 ${startNumber}-${endNumber} 张）`)}
              <small>单次最多 {pdfInfo.maxPages} 页；Token 与费用只累计所选页面</small>
            </div>
          </div>
        )}
        {!isPagedSource && file && <p className="hint">单张图片按一页处理，无需填写页码。</p>}
        {restoreFailed && (
          <div className="pdf-range-card error" role="alert">
            <span>上一份 OCR 的任务编号仍安全保留；恢复前不会允许新建任务。</span>
            <button
              type="button"
              onClick={() => {
                setRestoreFailed(false);
                setRestoringJob(true);
                setRestoreNonce((value) => value + 1);
              }}
            >
              重试恢复
            </button>
          </div>
        )}
        {!job && (
          <div className="ocr-start-action">
            <button
              className="primary"
              disabled={restoringJob || restoreFailed || starting || readiness.blocked || controlAction
                || retryBusy || rawSaving || !file || pdfInfo.status !== "ready"
                || (isPagedSource && Boolean(pageRangeError))}
              onClick={start}
            >
              {starting ? "正在启动……" : "开始 OCR"}
            </button>
            <span>{file
              ? `将按“${qualityTierLabel(activeQualityTier)}”档识别${isPagedSource && selectedPageCount ? ` ${selectedPageCount} 页` : "此图片"}`
              : "选择文件后即可开始"}</span>
          </div>
        )}
        {job && (
          <div className={`process-card process-${job.status}`}>
            <div className="process-summary">
              <div>
                <b>{ocrRecovery.statusLabel || ocrStatusLabel(job.status)}</b>
                <span>{job.phase || `正在按“${qualityTierLabel(activeQualityTier)}”档处理`}</span>
              </div>
              <strong>{Math.round(ocrProgress.progress * 100)}%</strong>
            </div>
            <div className="process-track" role="progressbar" aria-label="OCR 进度"
              aria-valuemin="0" aria-valuemax="100" aria-valuenow={Math.round(ocrProgress.progress * 100)}>
              <span style={{ width: `${Math.round(ocrProgress.progress * 100)}%` }} />
            </div>
            <div className="ocr-progress-grid" aria-label="OCR 实时统计">
              <span><small>当前页</small><b>{ocrProgress.currentPages.length
                ? ocrProgress.currentPages.map((page) => `P${page}`).join("、") : "等待中"}</b></span>
              <span><small>成功</small><b>{ocrProgress.success}/{ocrProgress.total}</b></span>
              <span><small>自动重试</small><b>{ocrProgress.retryPages}</b></span>
              <span><small>待确认</small><b>{ocrProgress.needsReview}</b></span>
              <span><small>处理中</small><b>{ocrProgress.active}</b></span>
              <span><small>待处理</small><b>{ocrProgress.pending}</b></span>
            </div>
            <div className="ocr-speed-line">
              <span>平均速度：<b>{formatPagesPerMinute(ocrProgress.averageRate)}</b></span>
              <span>最近一分钟：<b>{formatPagesPerMinute(ocrProgress.recentRate)}</b></span>
              <span>预计剩余：<b>{formatOcrDuration(ocrProgress.etaSeconds)}</b></span>
              {ocrProgress.concurrency != null && <span>并行：<b>{ocrProgress.concurrency}</b></span>}
              {ocrProgress.dpi != null && <span>当前清晰度：<b>{ocrProgress.dpi} DPI</b></span>}
              {ocrProgress.rateLimited && <span className="warning">服务限流，已自动降速</span>}
            </div>
            {job.error && <p className="process-error-message">{job.error}</p>}
            <div className="ocr-control-row">
              {job.status === "running" && job.can_pause !== false && (
                <button
                  type="button"
                  disabled={Boolean(controlAction) || retryBusy || rawSaving || job.saving || job.importing}
                  onClick={() => controlOcr("pause")}
                >
                  {controlAction === "pause" ? "正在请求暂停……" : "Ⅱ 安全暂停"}
                </button>
              )}
              {["pausing", "paused"].includes(job.status) && job.can_resume !== false && (
                <button
                  className="primary"
                  type="button"
                  disabled={Boolean(controlAction) || retryBusy || rawSaving || job.saving || job.importing}
                  onClick={() => controlOcr("resume")}
                >
                  {controlAction === "resume" ? "正在继续……" : "▶ 继续识别"}
                </button>
              )}
              {ocrRecovery.canResumeIncomplete && (
                <button
                  className="primary"
                  type="button"
                  disabled={Boolean(controlAction) || retryBusy || rawSaving || job.saving || job.importing}
                  onClick={() => controlOcr("resume")}
                >
                  {controlAction === "resume" ? "正在继续未完成页面……" : `▶ ${ocrRecovery.actionLabel}`}
                </button>
              )}
              {["partial", "error"].includes(job.status) && failedPageNums.length > 0 && (
                <button
                  className="primary"
                  type="button"
                  disabled={retryBusy || rawSaving || Boolean(controlAction) || job.saving || job.importing}
                  onClick={retryFailedPages}
                >
                  {retryingFailed ? "正在重新排队……" : `重试全部失败页（${failedPageNums.length}）`}
                </button>
              )}
            </div>
            {pollingStopped && OCR_ACTIVE_STATUSES.has(job.status) && (
              <button
                type="button"
                onClick={() => {
                  setPollingStopped(false);
                  setPollNonce((value) => value + 1);
                }}
              >
                重新连接进度
              </button>
            )}
          </div>
        )}
        {job && <QualityGateCard job={job} onSelectPage={selectPage} />}
        <div className="status">{msg}</div>
        {terminalOcr && (
          <section className={`ocr-completion ${ocrRecovery.complete ? "complete" : "issues"}`}>
            <div className="ocr-completion-heading">
              <div>
                <h3>{ocrRecovery.title || "OCR 状态待确认"}</h3>
                <p>{ocrRecovery.detail || "已有页面记录均已保留。"}</p>
              </div>
              <span>{ocrArtifacts.compileStatus || "等待编译状态"}</span>
            </div>
            <div className="ocr-result-metrics">
              <span><small>总耗时</small><b>{formatOcrDuration(ocrProgress.elapsedSeconds)}</b></span>
              <span><small>平均速度</small><b>{formatPagesPerMinute(ocrProgress.averageRate)}</b></span>
              <span><small>自动重试页</small><b>{ocrProgress.retryPages}</b></span>
              <span><small>待确认页</small><b>{ocrProgress.needsReview}</b></span>
              <span><small>未完成页</small><b>{ocrRecovery.incompleteCount}</b></span>
              <span><small>编译状态</small><b>{ocrArtifacts.compileStatus || "暂无记录"}</b></span>
            </div>
            <div className="ocr-artifact-grid" aria-label="OCR 最终产物">
              {[ocrArtifacts.source, ocrArtifacts.raw, ocrArtifacts.baselineTex, ocrArtifacts.baselinePdf].map((artifact) => (
                <div key={artifact.label} className={artifact.available ? "available" : "pending"}>
                  <span>{artifact.available ? "✓" : "·"}</span>
                  <b>{artifact.label}</b>
                  {artifact.url
                    ? <a href={artifact.url} target="_blank" rel="noreferrer">打开 / 下载</a>
                    : <small>{artifact.available ? "已保存" : "本任务暂无此产物"}</small>}
                </div>
              ))}
            </div>
            {issuePages.length > 0 && (
              <div className="ocr-issue-pages">
                <b>问题页：</b>
                {issuePages.slice(0, 20).map((page) => {
                  const pending = ocrPagePresentation(job.pages?.[page]).pending;
                  return (
                    <button
                      type="button"
                      key={page}
                      disabled={pending}
                      title={pending ? "此页尚未处理；请使用“继续未完成页面”" : "查看本页"}
                      onClick={() => selectPage(page)}
                    >
                      P{page}{pending ? "（待继续）" : ""}
                    </button>
                  );
                })}
                {issuePages.length > 20 && <span>另有 {issuePages.length - 20} 页</span>}
              </div>
            )}
            <div className="ocr-result-actions">
              {ocrRecovery.canResumeIncomplete && (
                <button
                  className="primary"
                  disabled={retryBusy || rawSaving || Boolean(controlAction) || job.saving || job.importing}
                  onClick={() => controlOcr("resume")}
                >
                  {controlAction === "resume" ? "正在继续未完成页面……" : ocrRecovery.actionLabel}
                </button>
              )}
              {job.status === "done" && (
                <button className="primary" disabled={importingProject || rawSaving || retryBusy || Boolean(controlAction)} onClick={importProject}>
                  {importingProject ? "正在打开项目……" : "AI 全自动整理"}
                </button>
              )}
              {failedPageNums.length > 0 && (
                <button className="primary" disabled={retryBusy || rawSaving || Boolean(controlAction)} onClick={retryFailedPages}>
                  {retryingFailed ? "正在重新排队……" : `重试问题页（${failedPageNums.length}）`}
                </button>
              )}
              {ocrArtifacts.raw.available && (
                <>
                  <a className="button-link" href={`/api/ocr/jobs/${job.id}/result`} download>下载原稿 TEX</a>
                  <button type="button" disabled={rawSaving || retryBusy || Boolean(controlAction)} onClick={saveRawResult}>
                    {rawSaving ? "正在保存……" : "保存 OCR 工程 ZIP"}
                  </button>
                  <button type="button" disabled={retryBusy || Boolean(controlAction)} onClick={copyRawResult}>复制原稿 TEX</button>
                  <button type="button" disabled={retryBusy || Boolean(controlAction)} onClick={browserDownloadRaw}>备用下载 ZIP</button>
                </>
              )}
              {rawSaved && <button type="button" onClick={openDownloadFolder}>打开所在文件夹</button>}
            </div>
          </section>
        )}
        {job && ["done", "partial", "error"].includes(job.status) && (
          <div className="row">
            <button type="button" disabled={rawSaving || retryBusy || Boolean(controlAction)} onClick={discardJob}>放弃本次 OCR</button>
          </div>
        )}
      </section>
      <div className={`ocr-cols ${previewMode === "live" ? "ocr-live-layout" : "ocr-page-layout"} ${focusLivePreview ? "ocr-live-focus" : ""}`}>
        {(previewMode === "page" || !focusLivePreview) && (
          <aside className="col tree" aria-label="OCR 页面列表">
            {pageNums.map((n) => {
              const p = job.pages[n];
              const pageView = ocrPagePresentation(p);
              return (
                <button
                  type="button"
                  key={n}
                  className={`tree-item d-${String(pageView.state).toLowerCase()} ${current === n ? "active" : ""} ${pageView.pending ? "disabled" : ""}`}
                  disabled={pageView.pending}
                  aria-pressed={previewMode === "page" && current === n}
                  aria-label={`${job.source_type === "pdf" ? `原 PDF 第 ${n} 页` : "OCR 图片"}，任务 ${p.task_index || 1}/${totalPages}`}
                  onClick={() => selectPage(n)}
                >
                  <span className="badge">{job.source_type === "pdf" ? `原 P${n}` : `P${n}`}</span>
                  <span className="page-task-index">{p.task_index || 1}/{totalPages}</span>
                  <span className="m">
                    {qualityRetryPageSet.has(n) && pageView.success ? "待确认" : pageView.label}
                  </span>
                </button>
              );
            })}
          </aside>
        )}
        {previewMode === "page" && current != null && (
          <main className="col preview">
            <img
              src={`/api/ocr/jobs/${job.id}/pages/${current}`}
              alt={job.source_type === "pdf" ? `原 PDF 第 ${current} 页` : "OCR 图片"}
              style={{ maxWidth: "100%", border: "1px solid #e2e5ea" }}
            />
          </main>
        )}
        <aside className={`col tex ${previewMode === "live" ? "live-tex" : "page-tex"}`}>
          {previewMode === "live" && job && (
            <>
              <div className="live-preview-summary" aria-live="polite">
                <b>实时累积结果</b>
                <span>已完成 {successfulPages}/{totalPages} 页；新页面完成后会持续追加到下方草稿。</span>
                {!focusLivePreview && <span>点击左侧页面可检查原图与单页 LaTeX。</span>}
              </div>
              <div className="row live-preview-toolbar">
                <b>实时 OCR LaTeX 草稿（已完成页持续追加）</b>
                <span className="status">
                  版本 {liveRevision}/{Number(job.raw_revision || 0)} · {liveTex.length.toLocaleString()} 字符
                </span>
                <button
                  type="button"
                  aria-pressed={focusLivePreview}
                  onClick={() => setFocusLivePreview((focused) => !focused)}
                >
                  {focusLivePreview ? "显示页列表" : "专注预览"}
                </button>
                {current != null && !ocrPagePresentation(job.pages?.[current]).pending && (
                  <button type="button" onClick={() => selectPage(current)}>
                    检查{job.source_type === "pdf" ? `原第 ${current} 页` : "图片"}
                  </button>
                )}
              </div>
              {!liveTex && (
                <p className="status" aria-live="polite">等待第一页完成，草稿会自动出现在这里……</p>
              )}
              <Editor
                height="clamp(560px, 68vh, 900px)"
                language="latex"
                value={liveTex}
                onMount={(editor) => {
                  liveEditorRef.current = editor;
                  const lineCount = editor.getModel()?.getLineCount();
                  if (lineCount) editor.revealLine(lineCount);
                }}
                options={{ readOnly: true, minimap: { enabled: false }, scrollBeyondLastLine: false }}
              />
            </>
          )}
          {previewMode === "page" && current != null && (
            <>
              <div className="row">
                <b>{job.source_type === "pdf" ? `原第 ${current} 页` : "图片"} LaTeX
                  {currentTaskIndex > 0 && ` · ${currentTaskIndex}/${totalPages}`}</b>
                <button type="button" onClick={() => setPreviewMode("live")}>回到实时结果</button>
                {(ocrPagePresentation(job.pages[current]).failed
                  || job.pages[current]?.low_conf
                  || job.pages[current]?.needs_review
                  || qualityRetryPageSet.has(current)) && (
                  <button
                    disabled={retryBusy || rawSaving || Boolean(controlAction) || job.pages[current]?.retrying}
                    onClick={() => retry(current)}
                  >
                    {retryingPage === current || job.pages[current]?.retrying ? "正在重试……" : "重试此页"}
                  </button>
                )}
              </div>
              {job.pages[current]?.error && (
                <p className="warning">{job.pages[current].error}</p>
              )}
              <Editor
                height="70vh"
                language="latex"
                value={currentTex}
                options={{ readOnly: true, minimap: { enabled: false } }}
              />
            </>
          )}
        </aside>
      </div>
    </div>
  );
}

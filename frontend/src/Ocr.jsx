import { useEffect, useRef, useState } from "react";
import Editor from "@monaco-editor/react";
import { api } from "./api";
import { apiAuthority, sameApiAuthority } from "./providerUrl";

const OCR_SESSION_JOB_KEY = "latexstruct-current-ocr-job-v1";
// 兼容 v1.1.2 的 10 位旧任务号；新任务使用完整 UUID4 hex（128-bit）。
const OCR_JOB_ID_RE = /^(?:[0-9a-f]{10}|[0-9a-f]{32})$/;

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
    done: "已完成",
    partial: "部分完成",
    error: "处理失败",
    paused: "已暂停",
  })[status] || "等待处理";
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
    return { blocked: true, reason: "正在检查视觉模型与 API Key……" };
  }
  if (setup.status === "error") {
    return {
      blocked: true,
      reason: "无法确认 OCR 配置，已阻止启动。请前往设置页检查后重试。",
    };
  }

  const cfg = setup.config || {};
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
  const [file, setFile] = useState(null);
  const [startPage, setStartPage] = useState("1");
  const [endPage, setEndPage] = useState("");
  const [pdfInfo, setPdfInfo] = useState({ status: "idle", total: 0, maxPages: 500, jobId: null });
  const [dpi, setDpi] = useState(150);
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
  const [importMode, setImportMode] = useState("ai");
  const importTemplate = "elegantbook";
  const [importingProject, setImportingProject] = useState(false);
  const [msg, setMsg] = useState("");
  const [starting, setStarting] = useState(false);
  const [restoringJob, setRestoringJob] = useState(() => Boolean(rememberedOcrJobId()));
  const [restoreFailed, setRestoreFailed] = useState(false);
  const [restoreNonce, setRestoreNonce] = useState(0);
  const [retryingPage, setRetryingPage] = useState(null);
  const [rawSaving, setRawSaving] = useState(false);
  const [pollingStopped, setPollingStopped] = useState(false);
  const [pollNonce, setPollNonce] = useState(0);
  const inspectSequence = useRef(0);
  const inspectedJobId = useRef(null);
  const liveEditorRef = useRef(null);
  const activeJobId = useRef(null);

  const refreshJob = async (jid) => {
    const next = await (await api(`/api/ocr/jobs/${jid}`)).json();
    setJob(next);
    return next;
  };

  const inspectFile = async (selected, sequence = inspectSequence.current) => {
    const selectedIsPdf = /\.pdf$/i.test(selected?.name || "");
    setPdfInfo({ status: "loading", total: 0, maxPages: 500, jobId: null });
    setMsg(selectedIsPdf ? "正在上传 PDF 并读取总页数……" : "正在上传图片并准备转写……");
    const form = new FormData();
    form.append("file", selected);
    try {
      const info = await (await api("/api/ocr/inspect", { method: "POST", body: form })).json();
      if (sequence !== inspectSequence.current) {
        api(`/api/ocr/jobs/${info.id}`, { method: "DELETE" }).catch(() => {});
        return;
      }
      if (info.source_type !== (selectedIsPdf ? "pdf" : "image")) {
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
      setMsg(selectedIsPdf
        ? (info.total_pages > info.max_pages_per_job
          ? `已读取 PDF：共 ${info.total_pages} 页；为控制耗时与费用，默认选择前 ${defaultEnd} 页`
          : `已读取 PDF：共 ${info.total_pages} 页，默认处理全部`)
        : "图片已安全上传，可开始单页转写");
    } catch (error) {
      if (sequence !== inspectSequence.current) return;
      inspectedJobId.current = null;
      setPdfInfo({ status: "error", total: 0, maxPages: 500, jobId: null });
      setMsg((selectedIsPdf ? "无法读取 PDF 页数：" : "无法准备图片：") + error.message);
    }
  };

  const chooseFile = async (selected) => {
    if (restoringJob || restoreFailed) {
      setMsg("正在恢复上一份 OCR 任务，请稍候再选择新文件");
      return false;
    }
    if (retryingPage !== null || rawSaving) {
      setMsg(retryingPage !== null
        ? "当前页面正在重试，请等待完成后再选择新文件"
        : "原始 OCR 正在保存，请等待完成后再选择新文件");
      return false;
    }
    if (job?.importing) {
      setMsg("OCR 结果正在导入项目，请等待完成后再选择新文件");
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
        setMsg("已保留当前 OCR 结果；请先下载原始 OCR 或进入结构化审阅");
        return false;
      }
    }
    if (
      latestJob?.importing || latestJob?.saving
      || ["starting", "running"].includes(latestJob?.status)
    ) {
      setMsg("上一份 OCR 仍在处理、重试、保存或导入，请等待完成后再选择新文件");
      return false;
    }

    const previous = inspectedJobId.current;
    const disposableJobs = new Set();
    if (previous) disposableJobs.add(previous);
    if (latestJob?.id && !["starting", "running"].includes(latestJob.status)) {
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
    setFile(selected || null);
    setJob(null);
    setCurrent(null);
    setCurrentTex("");
    setPreviewMode("live");
    setLiveTex("");
    setLiveRevision(0);
    setRestoreFailed(false);
    setPollingStopped(false);
    if (!selected) {
      setPdfInfo({ status: "idle", total: 0, maxPages: 500, jobId: null });
      setMsg("");
      return true;
    }
    inspectFile(selected, sequence);
    return true;
  };

  const isPdf = Boolean(file && /\.pdf$/i.test(file.name || ""));
  const startNumber = Number(startPage);
  const endNumber = Number(endPage);
  let pageRangeError = "";
  let selectedPageCount = 0;
  if (isPdf && pdfInfo.status === "ready") {
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
    if (pdfInfo.status !== "ready" || !pdfInfo.jobId || (isPdf && pageRangeError)) {
      setMsg(pageRangeError || "请等待文件上传与页数读取完成后再开始");
      return;
    }
    const fd = new FormData();
    fd.append("dpi", String(dpi));
    fd.append("model", model);
    const endpoint = `/api/ocr/jobs/${pdfInfo.jobId}/start`;
    if (isPdf) {
      fd.append("start_page", startPage);
      fd.append("end_page", endPage);
      setMsg(`正在启动原 PDF 第 ${startPage}-${endPage} 页转写……`);
    } else {
      setMsg("正在启动图片转写……");
    }
    setCurrent(null);
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
      inspectedJobId.current = null;
      setRestoreFailed(false);
      setJob({
        id,
        status: "running",
        source_type: isPdf ? "pdf" : "image",
        source_total: isPdf ? pdfInfo.total : 1,
        total: isPdf ? selectedPageCount : 1,
        done: 0,
        raw_revision: 0,
        raw_chars: 0,
        usage_revision: 0,
        page_revision: 0,
        pages: {},
      });
      setMsg((isPdf ? "正在逐页处理所选范围……" : "正在处理图片……")
        + (recoverable ? "" : " 浏览器无法记录恢复信息，本次处理完成前请勿离开 OCR 页面。"));
    } catch (e) {
      try {
        const recovered = await (await api(`/api/ocr/jobs/${pdfInfo.jobId}`)).json();
        if (recovered.id !== pdfInfo.jobId) throw new Error("恢复到的任务编号不一致");
        if (recovered.status === "ready") {
          setMsg("启动尚未生效，可再次点击“开始转写”：" + e.message);
        } else {
          activeJobId.current = recovered.id;
          inspectedJobId.current = null;
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
    if (page?.status === "pending") return;
    setCurrent(n);
    liveEditorRef.current = null;
    setPreviewMode("page");
    try {
      setCurrentTex(await (await api(`/api/ocr/jobs/${job.id}/pages/${n}/tex`)).text());
    } catch (error) {
      setCurrentTex("");
      setMsg("暂时无法读取本页结果：" + error.message);
    }
  };

  const retry = async (n) => {
    if (retryingPage !== null || rawSaving) return;
    const retryJobId = job?.id;
    const retrySequence = inspectSequence.current;
    if (!retryJobId) return;
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
        setJob(latest);
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
        setMsg("原始 OCR 已保留，可逐页检查或进入结构化审阅");
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
        setMsg(latest.pages?.[n]?.status === "done"
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
      const latest = await refreshRetrySnapshot();
      if (stillCurrent()) {
        if (latest?.status === "running") {
          setMsg(`${label}仍在后台重试，已继续自动接收进度`);
        }
        setRetryingPage(null);
      }
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
        mode: importMode,
        template: importTemplate,
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
    if (rawSaving || retryingPage !== null) return;
    setRawSaving(true);
    setMsg("正在把原始 OCR 安全保存到下载文件夹……");
    try {
      const saved = await (await api(`/api/ocr/jobs/${job.id}/save`, { method: "POST" })).json();
      setRawSaved({ ...saved, jobId: job.id });
      setMsg(`已保存 ${saved.filename} 到 ${saved.folder}`);
    } catch (error) {
      setMsg("保存原始 OCR 失败：" + error.message);
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
      const response = await api(`/api/ocr/jobs/${job.id}/result`);
      const blob = await response.blob();
      if (!blob.size) throw new Error("服务返回了空文件");
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = "ocr-raw.tex";
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      setMsg("已请求浏览器下载；桌面版若没有保存，请使用“修复下载原始 OCR”");
    } catch (error) {
      setMsg("浏览器下载失败：" + error.message);
    }
  };

  const discardJob = async () => {
    if (!job?.id || !window.confirm("确定放弃本次 OCR 结果和费用记录吗？此操作无法撤销。")) return;
    try {
      await api(`/api/ocr/jobs/${job.id}`, { method: "DELETE" });
      forgetOcrJobId(job.id);
      setJob(null);
      setFile(null);
      setCurrent(null);
      setCurrentTex("");
      setPreviewMode("live");
      setLiveTex("");
      setLiveRevision(0);
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
    ]).then(([config, data]) => {
      if (active) {
        setSetup({ status: "ready", config, providers: data.providers || [] });
      }
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
        inspectedJobId.current = restored.status === "ready" ? remembered : null;
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
        setMsg(restored.status === "running"
          ? "已恢复上一份 OCR，正在继续接收逐页进度……"
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
    const busy = ["starting", "running"].includes(job?.status)
      || Boolean(job?.saving || job?.importing);
    if (!job?.id || !busy) return undefined;
    let active = true;
    let timer = null;
    let failures = 0;
    const tick = async () => {
      try {
        const next = await (await api(`/api/ocr/jobs/${job.id}`)).json();
        if (!active) return;
        if (failures > 0) setMsg("进度连接已恢复，继续接收 OCR 状态");
        failures = 0;
        setPollingStopped(false);
        setJob(next);
        if (["starting", "running"].includes(next.status) || next.saving || next.importing) {
          timer = setTimeout(tick, 1200);
        }
      } catch (error) {
        if (!active) return;
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
  }, [job?.id, job?.status, job?.saving, job?.importing, pollNonce]);

  useEffect(() => {
    if (!job?.status) return;
    if (job.saving) {
      setMsg("正在把原始 OCR 安全保存到下载文件夹……");
    } else if (job.importing) {
      setMsg("正在把原始 OCR 导入项目并执行安全检查……");
    } else if (job.status === "done") {
      setMsg("原始 OCR 已保留，可逐页检查或进入结构化审阅");
    } else if (job.status === "partial") {
      setMsg("部分页面转写失败；请在左侧选择失败页并重试，全部成功后再进入结构化审阅");
    } else if (job.status === "error") {
      setMsg("OCR 未完成；请检查文件与视觉模型设置后重新开始转写");
    } else if (job.status === "paused") {
      setMsg("OCR 已暂停；可点击“开始转写”重新开始");
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
    ? Object.values(job.pages || {}).filter((page) => page.status === "done").length : 0;
  const totalPages = job ? (job.total || pageNums.length || successfulPages) : 0;
  const processedPages = job ? Math.min(totalPages, Math.max(job.done || 0, successfulPages)) : 0;
  const progressCount = job && ["partial", "error"].includes(job.status)
    ? `成功 ${successfulPages}/${totalPages} 页`
    : job?.status === "done"
      ? `完成 ${totalPages}/${totalPages} 页`
      : `已处理 ${processedPages}/${totalPages} 页`;
  const readiness = ocrReadiness(setup, model, customVisionConfirmed);
  const currentTaskIndex = current == null ? 0 : (job?.pages?.[current]?.task_index || 0);

  return (
    <div className="ocr">
      <section className="card">
        <h2>OCR 转写（PDF / 图片 → 原始 LaTeX → 结构化审阅）</h2>
        <div
          className={`ocr-config-status ${readiness.blocked ? "blocked" : "ready"}`}
          role={readiness.blocked ? "alert" : "status"}
        >
          <div>
            <b>{readiness.blocked ? "OCR 尚未就绪" : "视觉模型与 Key 已就绪"}</b>
            <p>{readiness.reason}</p>
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
        <div className="row">
          <input
            type="file"
            accept=".pdf,.png,.jpg,.jpeg"
            disabled={restoringJob || restoreFailed || starting || job?.status === "running" || job?.importing
              || retryingPage !== null || rawSaving}
            onChange={async (event) => {
              const accepted = await chooseFile(event.target.files?.[0] || null);
              if (!accepted) event.target.value = "";
            }}
          />
          <select aria-label="PDF 渲染清晰度" value={dpi} onChange={(e) => setDpi(Number(e.target.value))}>
            <option value={150}>150 DPI</option>
            <option value={200}>200 DPI</option>
            <option value={300}>300 DPI</option>
          </select>
          <button
            className="primary"
            disabled={restoringJob || restoreFailed || starting || Boolean(job?.id) || job?.saving || job?.importing
              || readiness.blocked || retryingPage !== null || rawSaving
              || (Boolean(file) && pdfInfo.status !== "ready") || (isPdf && Boolean(pageRangeError))}
            onClick={start}
          >
            {starting ? "正在启动……" : "开始转写"}
          </button>
        </div>
        {file && pdfInfo.status === "loading" && (
          <div className="pdf-range-card loading" role="status">
            {isPdf ? "正在上传 PDF 并读取总页数……" : "正在安全上传图片……"}
          </div>
        )}
        {file && pdfInfo.status === "error" && (
          <div className="pdf-range-card error" role="alert">
            <span>{isPdf ? "未能读取 PDF 页数" : "未能准备图片"}，尚未产生 OCR 费用。</span>
            <button type="button" onClick={() => inspectFile(file)}>重新读取</button>
          </div>
        )}
        {isPdf && pdfInfo.status === "ready" && (
          <div className="pdf-range-card">
            <div className="pdf-page-total">
              <b>PDF 共 {pdfInfo.total} 页</b>
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
              {pageRangeError || `本次处理 ${selectedPageCount} 页（原第 ${startNumber}-${endNumber} 页）`}
              <small>单次最多 {pdfInfo.maxPages} 页；Token 与费用只累计所选页面</small>
            </div>
          </div>
        )}
        {!isPdf && file && <p className="hint">图片按单页处理，无需填写页码。</p>}
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
        <details className="advanced">
          <summary>临时指定其他视觉模型（一般无需填写）</summary>
          <div className="row">
            <input
              placeholder="视觉模型 ID；留空使用设置页选择的模型"
              value={model}
              onChange={(e) => {
                setModel(e.target.value);
                setCustomVisionConfirmed(false);
              }}
            />
          </div>
        </details>
        {job && (
          <div className={`process-card process-${job.status}`}>
            <div className="process-summary">
              <div><b>{job.phase || ocrStatusLabel(job.status)}</b><span>{progressCount}</span></div>
              <strong>{Math.round((job.progress || 0) * 100)}%</strong>
            </div>
            <div className="process-track" role="progressbar" aria-label="OCR 进度"
              aria-valuemin="0" aria-valuemax="100" aria-valuenow={Math.round((job.progress || 0) * 100)}>
              <span style={{ width: `${Math.round((job.progress || 0) * 100)}%` }} />
            </div>
            <div className="process-metrics">
              {job.source_type === "pdf" && job.source_total > 0 && (
                <span>源 PDF：共 {job.source_total} 页，本次 {totalPages} 页</span>
              )}
              <span>Token：{(job.cost?.total_tokens || job.usage?.total_tokens || 0).toLocaleString()}</span>
              <span>费用：{job.cost?.estimated_cost_cny == null ? "暂无估价" :
                `约 ¥${job.cost.estimated_cost_cny < 0.01 ? job.cost.estimated_cost_cny.toFixed(4) : job.cost.estimated_cost_cny.toFixed(2)}`}</span>
              {job.status === "done" && <span>本次 {totalPages}/{totalPages} 页全部完成</span>}
              {job.status === "partial" && (
                <span>已成功 {successfulPages}/{totalPages} 页，请重试失败页</span>
              )}
              {job.status === "error" && (
                <span>{job.page > 0
                  ? `${job.source_type === "pdf" ? `处理停止于原第 ${job.page} 页` : "图片处理已停止"} · ${job.current_index || processedPages}/${totalPages}`
                  : "处理已停止，可重新开始"}</span>
              )}
              {job.status === "paused" && (
                <span>{job.page > 0
                  ? `${job.source_type === "pdf" ? `已暂停在原第 ${job.page} 页` : "图片任务已暂停"} · ${job.current_index || processedPages}/${totalPages}`
                  : "任务已暂停"}</span>
              )}
              {job.status === "running" && job.page > 0 && (
                <span>{job.source_type === "pdf"
                  ? `原第 ${job.page} 页 · ${job.current_index || 1}/${totalPages}`
                  : "正在处理图片 · 1/1"}</span>
              )}
            </div>
            {job.error && <p className="process-error-message">{job.error}</p>}
            {pollingStopped && job.status === "running" && (
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
        <div className="status">{msg}</div>
        {job?.status === "done" && (
          <div className="ocr-import-options">
            <label>
              <span>结构化整理方式</span>
              <select
                value={importMode}
                disabled={importingProject}
                onChange={(event) => setImportMode(event.target.value)}
              >
                <option value="ai">AI 深度整理（默认，重点维护）</option>
                <option value="rule">旧规则兼容模式（不再主动优化）</option>
              </select>
            </label>
            <div className="template-choice fixed-template" aria-label="固定排版方案">
              <span>结构化后的成品</span>
              <b>ElegantBook 专业讲义（固定）</b>
            </div>
            <small>
              {importMode === "ai"
                ? "AI 会判断章节层级、删除 OCR 粘贴的目录页并插入真正的 \\tableofcontents，同时校正定理与证明边界。AI 不可用时会明确停止，不会悄悄换成规则结果。"
                : "旧规则模式仅为已有项目保留，不使用额外 AI 调用，也不再作为主要整理流程。"}
              {" "}结构校正通过后才套用固定 ElegantBook；任何安全检查失败都会保留原文并阻止导出。
            </small>
          </div>
        )}
        {(job?.status === "done" || job?.status === "partial") && (
          <div className="row">
            {job.status === "done" && (
              <button
                className="primary"
                disabled={importingProject || rawSaving || retryingPage !== null}
                onClick={importProject}
              >
                {importingProject
                  ? "正在创建项目……"
                  : `进入${importMode === "ai" ? " AI 深度" : "规则"}整理（保留原始 OCR）`}
              </button>
            )}
            <button className="primary" type="button" disabled={rawSaving || retryingPage !== null} onClick={saveRawResult}>
              {rawSaving ? "正在保存……" : "修复下载原始 OCR"}{job.status === "partial" ? "（不完整）" : ""}
            </button>
            <button type="button" disabled={retryingPage !== null} onClick={copyRawResult}>一键复制原始 OCR</button>
            <button type="button" disabled={retryingPage !== null} onClick={browserDownloadRaw}>浏览器下载（备用）</button>
            {rawSaved && <button type="button" onClick={openDownloadFolder}>打开保存位置</button>}
            {job.status === "partial" && <span className="warning">请重试失败页后再进入结构化审阅。</span>}
          </div>
        )}
        {job && ["done", "partial", "error"].includes(job.status) && (
          <div className="row">
            <button type="button" disabled={rawSaving || retryingPage !== null} onClick={discardJob}>放弃本次 OCR</button>
          </div>
        )}
      </section>
      <div className={`ocr-cols ${previewMode === "live" ? "ocr-live-layout" : "ocr-page-layout"} ${focusLivePreview ? "ocr-live-focus" : ""}`}>
        {(previewMode === "page" || !focusLivePreview) && (
          <aside className="col tree" aria-label="OCR 页面列表">
            {pageNums.map((n) => {
              const p = job.pages[n];
              return (
                <button
                  type="button"
                  key={n}
                  className={`tree-item d-${p.status} ${current === n ? "active" : ""} ${p.status === "pending" ? "disabled" : ""}`}
                  disabled={p.status === "pending"}
                  aria-pressed={previewMode === "page" && current === n}
                  aria-label={`${job.source_type === "pdf" ? `原 PDF 第 ${n} 页` : "OCR 图片"}，任务 ${p.task_index || 1}/${totalPages}`}
                  onClick={() => selectPage(n)}
                >
                  <span className="badge">{job.source_type === "pdf" ? `原 P${n}` : `P${n}`}</span>
                  <span className="page-task-index">{p.task_index || 1}/{totalPages}</span>
                  <span className="m">
                    {p.retrying ? "重试中" : p.status === "done" ? (p.low_conf ? "⚠ 低置信" : "OK") :
                      p.status === "error" ? "失败，可重试" :
                        p.status === "pending" ? "等待处理" : "处理中"}
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
                {current != null && job.pages?.[current]?.status !== "pending" && (
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
                {(job.pages[current]?.status === "error" || job.pages[current]?.low_conf) && (
                  <button
                    disabled={retryingPage !== null || rawSaving || job.pages[current]?.retrying}
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

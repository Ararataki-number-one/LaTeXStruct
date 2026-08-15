import { useEffect, useRef, useState } from "react";
import Editor from "@monaco-editor/react";
import { api } from "./api";
import { apiAuthority, sameApiAuthority } from "./providerUrl";

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
  const [msg, setMsg] = useState("");
  const [starting, setStarting] = useState(false);
  const [retryingPage, setRetryingPage] = useState(null);
  const [pollingStopped, setPollingStopped] = useState(false);
  const [pollNonce, setPollNonce] = useState(0);
  const inspectSequence = useRef(0);
  const inspectedJobId = useRef(null);

  const refreshJob = async (jid) => {
    const next = await (await api(`/api/ocr/jobs/${jid}`)).json();
    setJob(next);
    return next;
  };

  const inspectPdf = async (selected, sequence = inspectSequence.current) => {
    setPdfInfo({ status: "loading", total: 0, maxPages: 500, jobId: null });
    setMsg("正在上传 PDF 并读取总页数……");
    const form = new FormData();
    form.append("file", selected);
    try {
      const info = await (await api("/api/ocr/inspect", { method: "POST", body: form })).json();
      if (sequence !== inspectSequence.current) {
        api(`/api/ocr/jobs/${info.id}`, { method: "DELETE" }).catch(() => {});
        return;
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
      setMsg(info.total_pages > info.max_pages_per_job
        ? `已读取 PDF：共 ${info.total_pages} 页；为控制耗时与费用，默认选择前 ${defaultEnd} 页`
        : `已读取 PDF：共 ${info.total_pages} 页，默认处理全部`);
    } catch (error) {
      if (sequence !== inspectSequence.current) return;
      setPdfInfo({ status: "error", total: 0, maxPages: 500, jobId: null });
      setMsg("无法读取 PDF 页数：" + error.message);
    }
  };

  const chooseFile = async (selected) => {
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
      const revision = Number(latestJob?.raw_revision || 0);
      const preserved = revision > 0 && [
        Number(latestJob?.downloaded_revision || 0),
        Number(latestJob?.imported_revision || 0),
      ].includes(revision);
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
    const sequence = inspectSequence.current + 1;
    inspectSequence.current = sequence;
    inspectedJobId.current = null;
    setFile(selected || null);
    setJob(null);
    setCurrent(null);
    setCurrentTex("");
    setPollingStopped(false);
    if (!selected) {
      setPdfInfo({ status: "idle", total: 0, maxPages: 500, jobId: null });
      setMsg("");
      return true;
    }
    if (/\.pdf$/i.test(selected.name || "")) {
      inspectPdf(selected, sequence);
    } else {
      setStartPage("1");
      setEndPage("1");
      setPdfInfo({ status: "image", total: 1, maxPages: 1, jobId: null });
      setMsg("图片将按单页转写");
    }
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
    const readiness = ocrReadiness(setup, model, customVisionConfirmed);
    if (readiness.blocked) {
      setMsg(readiness.reason);
      return;
    }
    if (!file) return alert("请选择 PDF 或图片");
    if (isPdf && (pdfInfo.status !== "ready" || pageRangeError)) {
      setMsg(pageRangeError || "请等待 PDF 总页数读取完成后再开始");
      return;
    }
    const fd = new FormData();
    fd.append("dpi", String(dpi));
    fd.append("model", model);
    let endpoint = "/api/ocr/jobs";
    if (isPdf) {
      fd.append("start_page", startPage);
      fd.append("end_page", endPage);
      endpoint = `/api/ocr/jobs/${pdfInfo.jobId}/start`;
      setMsg(`正在启动原 PDF 第 ${startPage}-${endPage} 页转写……`);
    } else {
      fd.append("file", file);
      setMsg("上传图片中……");
    }
    setCurrent(null);
    setCurrentTex("");
    setStarting(true);
    setPollingStopped(false);
    try {
      const r = await api(endpoint, { method: "POST", body: fd });
      const { id } = await r.json();
      if (isPdf) inspectedJobId.current = null;
      setJob({
        id,
        status: "running",
        source_type: isPdf ? "pdf" : "image",
        source_total: isPdf ? pdfInfo.total : 1,
        total: isPdf ? selectedPageCount : 1,
        done: 0,
        pages: {},
      });
      setMsg(isPdf ? "正在逐页处理所选范围……" : "正在处理图片……");
    } catch (e) {
      setMsg("启动失败：" + e.message);
    } finally {
      setStarting(false);
    }
  };

  const selectPage = async (n) => {
    const page = job?.pages?.[n];
    if (page?.status === "pending") return;
    setCurrent(n);
    try {
      setCurrentTex(await (await api(`/api/ocr/jobs/${job.id}/pages/${n}/tex`)).text());
    } catch (error) {
      setCurrentTex("");
      setMsg("暂时无法读取本页结果：" + error.message);
    }
  };

  const retry = async (n) => {
    if (retryingPage !== null) return;
    setRetryingPage(n);
    const label = job?.source_type === "pdf" ? `原第 ${n} 页` : "图片";
    setMsg(`${label}重试中……`);
    try {
      await api(`/api/ocr/jobs/${job.id}/pages/${n}/retry`, { method: "POST" });
      const updated = await refreshJob(job.id);
      await selectPage(n);
      if (updated?.status === "done") {
        setMsg("原始 OCR 已保留，可逐页检查或进入结构化审阅");
      } else if (updated?.status === "partial") {
        setMsg("本页重试后仍有失败页面；请查看错误后再次重试");
      } else {
        setMsg("重试已提交，请查看页面状态");
      }
    } catch (e) {
      setMsg(`${label}重试失败：${e.message}`);
    } finally {
      setRetryingPage(null);
    }
  };

  const importProject = async () => {
    setMsg("正在运行结构化与安全检查……");
    try {
      const r = await api(`/api/ocr/jobs/${job.id}/import`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      const { id } = await r.json();
      onImport(id);
    } catch (e) {
      setMsg("无法进入审阅：" + e.message);
    }
  };

  const discardJob = async () => {
    if (!job?.id || !window.confirm("确定放弃本次 OCR 结果和费用记录吗？此操作无法撤销。")) return;
    try {
      await api(`/api/ocr/jobs/${job.id}`, { method: "DELETE" });
      setJob(null);
      setFile(null);
      setCurrent(null);
      setCurrentTex("");
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
    if (!job?.id || job.status !== "running") return undefined;
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
        if (next.status === "running") timer = setTimeout(tick, 1200);
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
  }, [job?.id, job?.status, pollNonce]);

  useEffect(() => {
    if (!job?.status) return;
    if (job.status === "done") {
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
  }, [job?.status]);

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
        <h2>OCR 转写（PDF / 图片 → ElegantBook LaTeX，两阶段）</h2>
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
            disabled={starting || job?.status === "running" || job?.importing}
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
            disabled={starting || job?.status === "running" || readiness.blocked
              || (isPdf && (pdfInfo.status !== "ready" || Boolean(pageRangeError)))}
            onClick={start}
          >
            {starting ? "正在启动……" : "开始转写"}
          </button>
        </div>
        {isPdf && pdfInfo.status === "loading" && (
          <div className="pdf-range-card loading" role="status">正在上传 PDF 并读取总页数……</div>
        )}
        {isPdf && pdfInfo.status === "error" && (
          <div className="pdf-range-card error" role="alert">
            <span>未能读取 PDF 页数，尚未产生 OCR 费用。</span>
            <button type="button" onClick={() => inspectPdf(file)}>重新读取</button>
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
              <div><b>{job.phase || job.status}</b><span>{progressCount}</span></div>
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
        {(job?.status === "done" || job?.status === "partial") && (
          <div className="row">
            {job.status === "done" && (
              <button className="primary" onClick={importProject}>进入结构化审阅（保留原始 OCR）</button>
            )}
            <a className="button-link" href={`/api/ocr/jobs/${job.id}/result`} download="ocr-raw.tex">
              下载原始 OCR{job.status === "partial" ? "（不完整）" : ""}
            </a>
            {job.status === "partial" && <span className="warning">请重试失败页后再进入结构化审阅。</span>}
          </div>
        )}
        {job && ["done", "partial", "error"].includes(job.status) && (
          <div className="row">
            <button type="button" onClick={discardJob}>放弃本次 OCR</button>
          </div>
        )}
      </section>
      <div className="ocr-cols">
        <aside className="col tree">
          {pageNums.map((n) => {
            const p = job.pages[n];
            return (
              <button
                type="button"
                key={n}
                className={`tree-item d-${p.status} ${current === n ? "active" : ""} ${p.status === "pending" ? "disabled" : ""}`}
                disabled={p.status === "pending"}
                aria-pressed={current === n}
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
        <main className="col preview">
          {current != null && (
            <img
              src={`/api/ocr/jobs/${job.id}/pages/${current}`}
              alt={job.source_type === "pdf" ? `原 PDF 第 ${current} 页` : "OCR 图片"}
              style={{ maxWidth: "100%", border: "1px solid #e2e5ea" }}
            />
          )}
        </main>
        <aside className="col tex">
          {current != null && (
            <>
              <div className="row">
                <b>{job.source_type === "pdf" ? `原第 ${current} 页` : "图片"} LaTeX
                  {currentTaskIndex > 0 && ` · ${currentTaskIndex}/${totalPages}`}</b>
                {(job.pages[current]?.status === "error" || job.pages[current]?.low_conf) && (
                  <button
                    disabled={retryingPage !== null || job.pages[current]?.retrying}
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

import { useEffect, useState } from "react";
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
  const [pages, setPages] = useState("");
  const [dpi, setDpi] = useState(150);
  const [model, setModel] = useState("");
  const [setup, setSetup] = useState({ status: "loading", config: null, providers: [] });
  const [customVisionConfirmed, setCustomVisionConfirmed] = useState(false);
  const [job, setJob] = useState(null);
  const [current, setCurrent] = useState(null);
  const [currentTex, setCurrentTex] = useState("");
  const [msg, setMsg] = useState("");

  const poll = async (jid) => {
    try {
      const j = await (await api(`/api/ocr/jobs/${jid}`)).json();
      setJob(j);
      return j;
    } catch (e) {
      setMsg("轮询失败：" + e.message);
      return null;
    }
  };

  const start = async () => {
    const readiness = ocrReadiness(setup, model, customVisionConfirmed);
    if (readiness.blocked) {
      setMsg(readiness.reason);
      return;
    }
    if (!file) return alert("请选择 PDF 或图片");
    const fd = new FormData();
    fd.append("file", file);
    fd.append("pages", pages);
    fd.append("dpi", String(dpi));
    fd.append("model", model);
    setMsg("上传中……");
    setCurrent(null);
    setCurrentTex("");
    try {
      const r = await fetch("/api/ocr/jobs", { method: "POST", body: fd });
      if (!r.ok) {
        const error = await r.json().catch(() => ({}));
        setMsg("失败：" + (error.detail || r.statusText));
        return;
      }
      const { id } = await r.json();
      setJob({ id, status: "running", pages: {} });
      setMsg("已上传，正在逐页处理……");
      await poll(id);
    } catch (e) {
      setMsg("上传失败：" + e.message + "。请检查文件后重试。");
    }
  };

  const selectPage = async (n) => {
    setCurrent(n);
    setCurrentTex(await (await api(`/api/ocr/jobs/${job.id}/pages/${n}/tex`)).text());
  };

  const retry = async (n) => {
    setMsg(`第 ${n} 页重试中……`);
    try {
      await api(`/api/ocr/jobs/${job.id}/pages/${n}/retry`, { method: "POST" });
      const updated = await poll(job.id);
      await selectPage(n);
      if (updated?.status === "done") {
        setMsg("原始 OCR 已保留，可逐页检查或进入结构化审阅");
      } else if (updated?.status === "partial") {
        setMsg("本页重试后仍有失败页面；请查看错误后再次重试");
      } else {
        setMsg("重试已提交，请查看页面状态");
      }
    } catch (e) {
      setMsg(`第 ${n} 页重试失败：${e.message}`);
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
    const timer = setTimeout(() => poll(job.id), 1200);
    return () => clearTimeout(timer);
  }, [job]);

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
          <input type="file" accept=".pdf,.png,.jpg,.jpeg" onChange={(e) => setFile(e.target.files[0])} />
          <input placeholder="页码范围（如 1-5，留空全部）" value={pages} onChange={(e) => setPages(e.target.value)} />
          <select value={dpi} onChange={(e) => setDpi(Number(e.target.value))}>
            <option value={150}>150 DPI</option>
            <option value={200}>200 DPI</option>
            <option value={300}>300 DPI</option>
          </select>
          <button
            className="primary"
            disabled={job?.status === "running" || readiness.blocked}
            onClick={start}
          >
            开始转写
          </button>
        </div>
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
              <span>Token：{(job.cost?.total_tokens || job.usage?.total_tokens || 0).toLocaleString()}</span>
              <span>费用：{job.cost?.estimated_cost_cny == null ? "暂无估价" :
                `约 ¥${job.cost.estimated_cost_cny < 0.01 ? job.cost.estimated_cost_cny.toFixed(4) : job.cost.estimated_cost_cny.toFixed(2)}`}</span>
              {job.status === "done" && <span>{totalPages} 页全部完成</span>}
              {job.status === "partial" && (
                <span>已成功 {successfulPages}/{totalPages} 页，请重试失败页</span>
              )}
              {job.status === "error" && (
                <span>{job.page > 0 ? `处理停止于第 ${job.page} 页` : "处理已停止，可重新开始"}</span>
              )}
              {job.status === "paused" && (
                <span>{job.page > 0 ? `已暂停在第 ${job.page} 页` : "任务已暂停"}</span>
              )}
              {job.status === "running" && job.page > 0 && <span>正在处理第 {job.page} 页</span>}
            </div>
            {job.error && <p className="process-error-message">{job.error}</p>}
          </div>
        )}
        <div className="status">{msg}</div>
        {(job?.status === "done" || job?.status === "partial") && (
          <div className="row">
            {job.status === "done" && (
              <button className="primary" onClick={importProject}>进入结构化审阅（保留原始 OCR）</button>
            )}
            <a href={`/api/ocr/jobs/${job.id}/result`} download="ocr-raw.tex">
              <button>下载原始 OCR{job.status === "partial" ? "（不完整）" : ""}</button>
            </a>
            {job.status === "partial" && <span className="warning">请重试失败页后再进入结构化审阅。</span>}
          </div>
        )}
      </section>
      <div className="ocr-cols">
        <aside className="col tree">
          {pageNums.map((n) => {
            const p = job.pages[n];
            return (
              <div
                key={n}
                className={`tree-item d-${p.status} ${current === n ? "active" : ""}`}
                onClick={() => selectPage(n)}
              >
                <span className="badge">P{n}</span>
                <span className="m">
                  {p.status === "done" ? (p.low_conf ? "⚠ 低置信" : "OK") :
                    p.status === "error" ? "失败，可重试" : p.status}
                </span>
              </div>
            );
          })}
        </aside>
        <main className="col preview">
          {current != null && (
            <img
              src={`/api/ocr/jobs/${job.id}/pages/${current}`}
              alt={`page ${current}`}
              style={{ maxWidth: "100%", border: "1px solid #e2e5ea" }}
            />
          )}
        </main>
        <aside className="col tex">
          {current != null && (
            <>
              <div className="row">
                <b>第 {current} 页 LaTeX</b>
                {(job.pages[current]?.status === "error" || job.pages[current]?.low_conf) && (
                  <button onClick={() => retry(current)}>重试此页</button>
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

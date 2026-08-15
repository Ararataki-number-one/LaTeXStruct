import { useEffect, useState } from "react";
import Editor from "@monaco-editor/react";
import { api } from "./api";

export default function Ocr({ onImport }) {
  const [file, setFile] = useState(null);
  const [pages, setPages] = useState("");
  const [dpi, setDpi] = useState(150);
  const [model, setModel] = useState("");
  const [job, setJob] = useState(null);
  const [current, setCurrent] = useState(null);
  const [currentTex, setCurrentTex] = useState("");
  const [msg, setMsg] = useState("");

  const poll = async (jid) => {
    try {
      const j = await (await api(`/api/ocr/jobs/${jid}`)).json();
      setJob(j);
    } catch (e) {
      setMsg("轮询失败：" + e.message);
    }
  };

  const start = async () => {
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
      await poll(job.id);
      await selectPage(n);
      setMsg("重试完成");
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
    if (!job?.id || job.status !== "running") return undefined;
    const timer = setTimeout(() => poll(job.id), 1200);
    return () => clearTimeout(timer);
  }, [job]);

  useEffect(() => {
    if (current && job?.id) selectPage(current);
  }, [job?.id, current, job?.pages?.[current]?.status]);

  const pageNums = job ? Object.keys(job.pages || {}).map(Number).sort((a, b) => a - b) : [];

  return (
    <div className="ocr">
      <section className="card">
        <h2>OCR 转写（PDF / 图片 → ElegantBook LaTeX，两阶段）</h2>
        <div className="row">
          <input type="file" accept=".pdf,.png,.jpg,.jpeg" onChange={(e) => setFile(e.target.files[0])} />
          <input placeholder="页码范围（如 1-5，留空全部）" value={pages} onChange={(e) => setPages(e.target.value)} />
          <select value={dpi} onChange={(e) => setDpi(Number(e.target.value))}>
            <option value={150}>150 DPI</option>
            <option value={200}>200 DPI</option>
            <option value={300}>300 DPI</option>
          </select>
          <button className="primary" disabled={job?.status === "running"} onClick={start}>开始转写</button>
        </div>
        <details className="advanced">
          <summary>临时指定其他视觉模型（一般无需填写）</summary>
          <div className="row">
            <input placeholder="视觉模型 ID；留空使用设置页选择的模型" value={model} onChange={(e) => setModel(e.target.value)} />
          </div>
        </details>
        {job && (
          <div className={`process-card process-${job.status}`}>
            <div className="process-summary">
              <div><b>{job.phase || job.status}</b><span>完成 {job.done || 0}/{job.total || 0} 页</span></div>
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
              {job.page > 0 && <span>正在处理第 {job.page} 页</span>}
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

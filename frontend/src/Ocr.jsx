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
      if (j.status === "running") {
        setTimeout(() => poll(jid), 1500);
      }
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
    const r = await fetch("/api/ocr/jobs", { method: "POST", body: fd });
    if (!r.ok) {
      setMsg("失败：" + ((await r.json()).detail || r.statusText));
      return;
    }
    const { id } = await r.json();
    setJob({ id, status: "running" });
    poll(id);
  };

  const selectPage = async (n) => {
    setCurrent(n);
    setCurrentTex(await (await api(`/api/ocr/jobs/${job.id}/pages/${n}/tex`)).text());
  };

  const retry = async (n) => {
    setMsg(`第 ${n} 页重试中……`);
    await api(`/api/ocr/jobs/${job.id}/pages/${n}/retry`, { method: "POST" });
    poll(job.id);
    selectPage(n);
  };

  const importProject = async () => {
    const r = await api(`/api/ocr/jobs/${job.id}/import`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    const { id } = await r.json();
    onImport(id);
  };

  useEffect(() => {
    if (current && job) selectPage(current);
  }, [job]);

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
          <input placeholder="视觉模型（需支持图片输入，留空用设置）" value={model} onChange={(e) => setModel(e.target.value)} />
          <button className="primary" onClick={start}>开始转写</button>
        </div>
        {job && (
          <div className="status">
            状态：{job.status} · 第 {job.page || 0}/{job.total || 0} 页 · tokens {job.usage?.total_tokens || 0}
            {job.error && ` · 错误：${job.error}`}
          </div>
        )}
        <div className="status">{msg}</div>
        {job?.status === "done" && (
          <div className="row">
            <button className="primary" onClick={importProject}>导入为项目并整理</button>
            <a href={`/api/ocr/jobs/${job.id}/result`} download="ocr-book.tex"><button>下载转写 .tex</button></a>
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
                  {p.status === "done" ? (p.low_conf ? "⚠ 低置信" : "OK") : p.status}
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
                {job.pages[current]?.status === "done" && job.pages[current].low_conf && (
                  <button onClick={() => retry(current)}>重试此页</button>
                )}
              </div>
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

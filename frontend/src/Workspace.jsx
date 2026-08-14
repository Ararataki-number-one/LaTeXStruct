import { useEffect, useState } from "react";
import Editor from "@monaco-editor/react";
import { api, apiText } from "./api";

export default function Workspace({ pid }) {
  const [info, setInfo] = useState(null);
  const [source, setSource] = useState("");
  const [result, setResult] = useState("");
  const [report, setReport] = useState("");
  const [status, setStatus] = useState("");
  const [decisions, setDecisions] = useState([]);
  const [graph, setGraph] = useState(null);

  const load = async () => {
    if (!pid) return;
    setSource(await apiText(`/api/projects/${pid}/source`));
    setReport("尚未处理。");
    setResult("");
    try {
      setResult(await apiText(`/api/projects/${pid}/result`));
      setReport(await apiText(`/api/projects/${pid}/report`));
    } catch {
      /* 未处理 */
    }
    try {
      const d = await (await api(`/api/projects/${pid}/decisions`)).json();
      setDecisions(d.items || []);
    } catch {
      setDecisions([]);
    }
    try {
      const g = await (await api(`/api/projects/${pid}/graph`)).json();
      setGraph(g.graph);
    } catch {
      setGraph(null);
    }
    try {
      const p = await (await api(`/api/projects/${pid}`)).json();
      setInfo(p);
    } catch {
      setInfo(null);
    }
  };

  useEffect(() => {
    load();
  }, [pid]);

  const runProcess = async () => {
    setStatus("处理中……");
    try {
      const r = await (await api(`/api/projects/${pid}/process`, { method: "POST" })).json();
      setStatus(`完成：补丁 ${r.applied} · 拒绝 ${r.rejected} · 歧义 ${r.ambiguous}` +
        (r.degraded ? "（AI 降级规则）" : ""));
      await load();
    } catch (e) {
      setStatus("失败：" + e.message);
    }
  };

  const rejectOne = async (cid) => {
    if (!confirm(`拒绝修改 ${cid}？该处恢复原文，其余修改保留。`)) return;
    setStatus("重新整理中……");
    try {
      await api(`/api/projects/${pid}/decisions/${cid}/reject`, { method: "POST" });
      await load();
      setStatus("已拒绝该修改并重新校验");
    } catch (e) {
      setStatus("拒绝失败：" + e.message);
    }
  };

  if (!pid) return <section className="card">请在「项目」页选择或创建一个项目。</section>;

  return (
    <div className="workspace">
      <section className="card">
        <div className="row">
          <b>{info ? `${info.name}（${info.mode}）` : pid}</b>
          <button className="primary" onClick={runProcess}>运行结构化整理</button>
          <a href={`/api/projects/${pid}/export`} download="result.tex">
            <button>导出 result.tex</button>
          </a>
          {graph && (
            <a href={`/api/projects/${pid}/export-folder`}>
              <button>导出结构化文件夹 zip</button>
            </a>
          )}
        </div>
        {graph && (
          <div className="graph-info">
            依赖图：主文件 {graph.main_rel} · {graph.files.length} 个依赖文件
            {graph.missing.length > 0 && ` · ${graph.missing.length} 处缺失`}
            {graph.cycles.length > 0 && ` · ${graph.cycles.length} 处循环`}
          </div>
        )}
        <div className="status">{status}</div>
      </section>
      <div className="editors">
        <div className="editor-pane">
          <div className="pane-title">原文</div>
          <Editor height="60vh" language="latex" value={source} options={{ readOnly: true, minimap: { enabled: false } }} />
        </div>
        <div className="editor-pane">
          <div className="pane-title">整理后</div>
          <Editor height="60vh" language="latex" value={result} options={{ readOnly: true, minimap: { enabled: false } }} />
        </div>
      </div>
      <section className="card">
        <h2>决策清单（{decisions.length}）</h2>
        <ul className="decisions">
          {decisions.map((d) => (
            <li key={d.candidate_id} className={`d-${d.status}`}>
              <span className="badge">{d.kind === "theorem-like" ? d.env : d.kind}</span>
              <span className="title">{d.title}</span>
              <span className="meta">
                {d.section || `§${d.line}`} · L{d.line} · {Math.round((d.confidence || 0) * 100)}% · {d.status}
              </span>
              {d.status === "applied" && (
                <button onClick={() => rejectOne(d.candidate_id)}>拒绝</button>
              )}
            </li>
          ))}
        </ul>
      </section>
      <section className="card">
        <h2>汇报</h2>
        <pre className="report">{report}</pre>
      </section>
    </div>
  );
}

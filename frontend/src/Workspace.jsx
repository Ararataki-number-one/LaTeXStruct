import { useEffect, useMemo, useRef, useState } from "react";
import { DiffEditor } from "@monaco-editor/react";
import { api, apiText } from "./api";

export default function Workspace({ pid }) {
  const [info, setInfo] = useState(null);
  const [source, setSource] = useState("");
  const [result, setResult] = useState("");
  const [report, setReport] = useState("");
  const [status, setStatus] = useState("");
  const [decisions, setDecisions] = useState([]);
  const [graph, setGraph] = useState(null);
  const [selected, setSelected] = useState(null);
  const [filter, setFilter] = useState("all");
  const editorRef = useRef(null);

  const load = async () => {
    if (!pid) return;
    setSource(await apiText(`/api/projects/${pid}/source`));
    try {
      setResult(await apiText(`/api/projects/${pid}/result`));
      setReport(await apiText(`/api/projects/${pid}/report`));
    } catch {
      setResult("");
      setReport("尚未处理。点击「运行结构化整理」。");
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
      setInfo(await (await api(`/api/projects/${pid}`)).json());
    } catch {
      setInfo(null);
    }
  };

  useEffect(() => {
    load();
  }, [pid]);

  const rerun = async (path, opts) => {
    setStatus("重新整理中……");
    try {
      await api(path, opts);
      await load();
      setStatus("已完成并重新校验");
    } catch (e) {
      setStatus("失败：" + e.message);
    }
  };

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

  const visible = useMemo(() => {
    let items = decisions;
    if (filter === "proof") items = items.filter((d) => d.env === "proof" || d.kind === "proof");
    if (filter === "ambiguous") items = items.filter((d) => d.status === "ambiguous");
    if (filter === "high") items = items.filter((d) => d.confidence >= 0.9);
    return items;
  }, [decisions, filter]);

  const groups = useMemo(() => {
    const g = {};
    for (const d of visible) {
      const key = d.section || `§ ${d.line}`;
      (g[key] = g[key] || []).push(d);
    }
    return g;
  }, [visible]);

  const select = (d) => {
    setSelected(d);
    const ed = editorRef.current;
    if (ed) {
      const m = ed.getModifiedEditor();
      m.revealLineInCenter(d.line);
      m.setPosition({ lineNumber: d.line, column: 1 });
    }
  };

  if (!pid) return <section className="card">请在「项目」页选择或创建一个项目。</section>;

  return (
    <div className="workspace3">
      <section className="card toolbar">
        <b>{info ? `${info.name}（${info.mode}）` : pid}</b>
        <button className="primary" onClick={runProcess}>运行结构化整理</button>
        <a href={`/api/projects/${pid}/export`} download="result.tex"><button>导出 result.tex</button></a>
        {graph && <a href={`/api/projects/${pid}/export-folder`}><button>导出文件夹 zip</button></a>}
        <button onClick={() => rerun(`/api/projects/${pid}/decisions/reset`, { method: "POST" })}>
          撤销全部拒绝
        </button>
        <div className="filters">
          {[["all", "全部"], ["proof", "只看 Proof"], ["ambiguous", "只看歧义"], ["high", "高置信"]]
            .map(([k, label]) => (
              <button key={k} className={filter === k ? "primary" : ""} onClick={() => setFilter(k)}>
                {label}
              </button>
            ))}
        </div>
        {graph && (
          <span className="graph-info">
            主文件 {graph.main_rel} · 依赖 {graph.files.length}
            {graph.missing.length > 0 && ` · 缺失 ${graph.missing.length}`}
            {graph.cycles.length > 0 && ` · 循环 ${graph.cycles.length}`}
          </span>
        )}
        <span className="status">{status}</span>
      </section>
      <div className="three-col">
        <aside className="col tree">
          {Object.entries(groups).map(([section, items]) => (
            <div key={section}>
              <div className="group-title">{section}</div>
              {items.map((d) => (
                <div
                  key={d.candidate_id}
                  className={`tree-item d-${d.status} ${selected?.candidate_id === d.candidate_id ? "active" : ""}`}
                  onClick={() => select(d)}
                >
                  <span className="badge">{d.kind === "theorem-like" ? d.env : d.kind}</span>
                  <span className="t">{d.title}</span>
                  <span className="m">L{d.line} {Math.round((d.confidence || 0) * 100)}%</span>
                </div>
              ))}
            </div>
          ))}
        </aside>
        <main className="col diff">
          <DiffEditor
            original={source}
            modified={result}
            language="latex"
            onMount={(ed) => (editorRef.current = ed)}
            options={{ readOnly: true, minimap: { enabled: false }, renderSideBySide: true }}
            height="72vh"
          />
        </main>
        <aside className="col inspector">
          {selected ? (
            <>
              <h3>{selected.kind === "theorem-like" ? selected.env : selected.kind}</h3>
              <p className="t">{selected.title}</p>
              <dl>
                <dt>位置</dt><dd>{selected.section || `§ ${selected.line}`} · 第 {selected.line} 行</dd>
                <dt>置信度</dt><dd>{Math.round((selected.confidence || 0) * 100)}%</dd>
                <dt>来源</dt><dd>{selected.source}</dd>
                <dt>状态</dt><dd>{selected.status}</dd>
                <dt>原因</dt><dd>{selected.reason || "—"}</dd>
              </dl>
              {selected.status === "applied" && (
                <div className="actions">
                  <button onClick={() => rerun(`/api/projects/${pid}/decisions/${selected.candidate_id}/reject`, { method: "POST" })}>
                    拒绝此修改
                  </button>
                  <button
                    onClick={() => {
                      const cids = decisions
                        .filter((d) => d.status === "applied" && d.env === selected.env &&
                          d.candidate_id !== selected.candidate_id)
                        .map((d) => d.candidate_id);
                      if (!cids.length) return alert("没有同类型的其他修改");
                      if (!confirm(`拒绝同类型（${selected.env}）的其他 ${cids.length} 处修改？`)) return;
                      rerun(`/api/projects/${pid}/decisions/reject-batch`, {
                        method: "POST",
                        body: JSON.stringify({ cids }),
                      });
                    }}
                  >
                    拒绝同类型其余
                  </button>
                </div>
              )}
            </>
          ) : (
            <p className="muted">点击左侧决策项查看详情并跳转 diff 对应行。</p>
          )}
          <h3>汇报</h3>
          <pre className="report">{report}</pre>
        </aside>
      </div>
    </div>
  );
}

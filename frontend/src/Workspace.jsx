import { useEffect, useMemo, useRef, useState } from "react";
import * as monaco from "monaco-editor";
import editorWorker from "monaco-editor/esm/vs/editor/editor.worker?worker";
import { DiffEditor, Editor, loader } from "@monaco-editor/react";
import { api, apiText } from "./api";

// 本地 Monaco（无 CDN）。本模块由 App 按页加载，因此导入/OCR/设置页无需先解析编辑器。
self.MonacoEnvironment = {
  getWorker() {
    return new editorWorker();
  },
};
loader.config({ monaco });

const KINDS = [
  ["all", "全部"],
  ["theorem", "定理类"],
  ["proof", "证明"],
  ["section", "章节"],
  ["exercise", "习题"],
  ["ambiguous", "歧义"],
];

export default function Workspace({ pid }) {
  const [info, setInfo] = useState(null);
  const [source, setSource] = useState("");
  const [result, setResult] = useState("");
  const [report, setReport] = useState("");
  const [status, setStatus] = useState("");
  const [decisions, setDecisions] = useState([]);
  const [verification, setVerification] = useState(null);
  const [graph, setGraph] = useState(null);
  const [selected, setSelected] = useState(null);
  const [filter, setFilter] = useState("all");
  const [conf, setConf] = useState("all");
  const [query, setQuery] = useState("");
  const [view, setView] = useState("side"); // side | orig | mod
  const [reviewed, setReviewed] = useState(() => {
    try {
      return new Set(JSON.parse(localStorage.getItem(`ls-reviewed-${pid}`) || "[]"));
    } catch {
      return new Set();
    }
  });
  const undoStack = useRef([]);
  const editorRef = useRef(null);
  const treeRef = useRef(null);

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
      const items = d.items || [];
      setDecisions(items);
      setSelected((previous) =>
        previous ? items.find((item) => item.candidate_id === previous.candidate_id) || null : null);
      setVerification(d.verification || null);
    } catch {
      setDecisions([]);
      setVerification(null);
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
    try {
      setReviewed(new Set(JSON.parse(localStorage.getItem(`ls-reviewed-${pid}`) || "[]")));
    } catch {
      setReviewed(new Set());
    }
    setSelected(null);
    undoStack.current = [];
    load();
  }, [pid]);

  useEffect(() => {
    try {
      localStorage.setItem(`ls-reviewed-${pid}`, JSON.stringify([...reviewed]));
    } catch {}
  }, [reviewed, pid]);

  const rerun = async (path, opts) => {
    setStatus("重新整理并校验中……");
    try {
      await api(path, opts);
      await load();
      setStatus("已完成并重新校验");
      return true;
    } catch (e) {
      setStatus("失败：" + e.message);
      return false;
    }
  };

  const runProcess = async () => {
    setStatus("处理中……");
    try {
      const r = await (await api(`/api/projects/${pid}/process`, { method: "POST" })).json();
      setReviewed(new Set());
      setStatus((r.ok ? "安全检查通过" : "安全检查未通过，已回退并禁止导出") +
        `：补丁 ${r.applied} · 拒绝 ${r.rejected} · 歧义 ${r.ambiguous}` +
        (r.degraded ? "（AI 降级规则）" : ""));
      await load();
    } catch (e) {
      setStatus("失败：" + e.message);
    }
  };

  const visible = useMemo(() => {
    let items = decisions;
    if (filter === "theorem") items = items.filter((d) => d.kind === "theorem-like");
    if (filter === "proof") items = items.filter((d) => d.kind === "proof");
    if (filter === "section") items = items.filter((d) => ["bilingual-title", "scope-fix", "add-toc"].includes(d.kind));
    if (filter === "exercise") items = items.filter((d) => d.kind === "exercise-section");
    if (filter === "ambiguous") items = items.filter((d) => d.status === "ambiguous");
    if (conf === "high") items = items.filter((d) => (d.confidence || 0) >= 0.9);
    if (conf === "low") items = items.filter((d) => (d.confidence || 0) < 0.9);
    const q = query.trim().toLowerCase();
    if (q) items = items.filter((d) =>
      (d.title || "").toLowerCase().includes(q) || (d.reason || "").toLowerCase().includes(q));
    return items;
  }, [decisions, filter, conf, query]);

  const groups = useMemo(() => {
    const g = {};
    for (const d of visible) {
      const key = d.section || `§ ${d.line}`;
      (g[key] = g[key] || []).push(d);
    }
    return g;
  }, [visible]);

  const flat = useMemo(() => Object.values(groups).flat(), [groups]);
  const applied = decisions.filter((d) => d.status === "applied");
  const reviewedCount = applied.filter((d) => reviewed.has(d.candidate_id)).length;
  const lowConfidenceCount = applied.filter((d) => (d.confidence || 0) < 0.9).length;
  const safeToExport = verification?.safe_to_export === true;
  const reviewComplete = applied.length === 0 || reviewedCount === applied.length;
  const canExport = safeToExport && reviewComplete;
  const largeDiff = source.length + result.length > 1_000_000;
  const showDiffEditor = view === "side" && !largeDiff;

  const select = (d, scroll = true) => {
    setSelected(d);
    const ed = editorRef.current;
    if (ed && d.line) {
      const m = showDiffEditor && ed.getModifiedEditor ? ed.getModifiedEditor() : ed;
      if (m && m.revealLineInCenter) {
        m.revealLineInCenter(d.line);
        m.setPosition({ lineNumber: d.line, column: 1 });
      }
    }
    if (scroll && treeRef.current) {
      const el = treeRef.current.querySelector(`[data-cid="${d.candidate_id}"]`);
      if (el) el.scrollIntoView({ block: "nearest" });
    }
  };

  const move = (delta) => {
    if (!flat.length) return;
    const idx = flat.findIndex((d) => d.candidate_id === selected?.candidate_id);
    const next = idx < 0 ? flat[0] : flat[Math.min(flat.length - 1, Math.max(0, idx + delta))];
    select(next);
  };

  const accept = (d) => {
    setReviewed((prev) => new Set(prev).add(d.candidate_id));
  };

  const acceptSimilar = (d) => {
    setReviewed((prev) => {
      const next = new Set(prev);
      applied.filter((x) => x.kind === d.kind && x.env === d.env)
        .forEach((x) => next.add(x.candidate_id));
      return next;
    });
  };

  const acceptAll = () => {
    if (lowConfidenceCount > 0 && !confirm(`其中有 ${lowConfidenceCount} 条低置信修改，仍要全部确认保留吗？`)) {
      return;
    }
    setReviewed((prev) => {
      const next = new Set(prev);
      applied.forEach((x) => next.add(x.candidate_id));
      return next;
    });
  };

  const reject = async (d) => {
    const ok = await rerun(`/api/projects/${pid}/decisions/${d.candidate_id}/reject`, { method: "POST" });
    if (ok) undoStack.current.push(d.candidate_id);
  };

  const undo = async () => {
    const cid = undoStack.current.pop();
    if (!cid) {
      setStatus("没有可撤销的拒绝");
      return;
    }
    await rerun(`/api/projects/${pid}/decisions/${cid}/unreject`, { method: "POST" });
  };

  // 全局快捷键：↑↓ 切换 · A 确认保留 · R 拒绝 · Ctrl+Z 撤销上次拒绝
  useEffect(() => {
    const onKey = (e) => {
      const target = e.target;
      if (target?.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(target?.tagName)) return;
      const isMac = navigator.platform?.toLowerCase().includes("mac");
      const mod = isMac ? e.metaKey : e.ctrlKey;
      if (mod && (e.key === "z" || e.key === "Z")) {
        e.preventDefault();
        undo();
        return;
      }
      if (e.key === "ArrowDown") { e.preventDefault(); move(1); }
      else if (e.key === "ArrowUp") { e.preventDefault(); move(-1); }
      else if ((e.key === "a" || e.key === "A") && selected) { e.preventDefault(); accept(selected); }
      else if ((e.key === "r" || e.key === "R") && selected) { e.preventDefault(); reject(selected); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [selected, flat, view]);

  if (!pid) return <section className="card">请在「项目」页选择或创建一个项目。</section>;

  const selApplied = selected && selected.status === "applied";
  const selReviewed = selected && reviewed.has(selected.candidate_id);

  return (
    <div className="workspace3">
      <section className="card toolbar">
        <b>{info ? `${info.name}（${info.mode}）` : pid}</b>
        <button className="primary" onClick={runProcess}>运行结构化整理</button>
        {canExport ? (
          <a href={`/api/projects/${pid}/export`} download="result.tex"><button>导出 result.tex</button></a>
        ) : <button disabled title="需先通过安全检查并完成审阅">导出 result.tex</button>}
        {graph && (canExport ? (
          <a href={`/api/projects/${pid}/export-folder`}><button>导出文件夹 zip</button></a>
        ) : <button disabled title="需先通过安全检查并完成审阅">导出文件夹 zip</button>)}
        <button onClick={() => { if (confirm("撤销全部拒绝并重新应用所有修改？")) rerun(`/api/projects/${pid}/decisions/reset`, { method: "POST" }); }}>
          撤销全部拒绝
        </button>
        <span className="progress">
          已审阅 {reviewedCount}/{applied.length}
          <button onClick={acceptAll} disabled={!applied.length}>全部接受</button>
        </span>
        <div className="filters">
          {KINDS.map(([k, label]) => (
            <button key={k} className={filter === k ? "primary" : ""} onClick={() => setFilter(k)}>
              {label}
            </button>
          ))}
          {[["all", "全部置信度"], ["high", "高置信"], ["low", "低置信"]].map(([k, label]) => (
            <button key={k} className={conf === k ? "primary" : ""} onClick={() => setConf(k)}>
              {label}
            </button>
          ))}
        </div>
        <input
          className="search"
          placeholder="搜索标题/原因……"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        <div className="view-toggle">
          {[["side", "并排"], ["orig", "只看原文"], ["mod", "只看修改后"]].map(([k, label]) => (
            <button key={k} className={view === k ? "primary" : ""} onClick={() => setView(k)}>
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
        {verification?.checks && (
          <span className={`safety ${safeToExport ? "safe" : "unsafe"}`}>
            安全检查：{verification.checks.map((c) =>
              `${c.ok ? "✓" : "✗"}${c.label}${c.skipped ? "（未运行）" : ""}`).join(" · ")}
          </span>
        )}
        {safeToExport && !reviewComplete && (
          <span className="warning">完成全部审阅后才可导出。</span>
        )}
        <span className="kbd-hint">↑↓ 切换 · A 确认保留 · R 拒绝 · Ctrl+Z 撤销上次拒绝</span>
      </section>
      <div className="three-col">
        <aside className="col tree" ref={treeRef}>
          {Object.entries(groups).map(([section, items]) => (
            <div key={section}>
              <div className="group-title">{section}</div>
              {items.map((d) => (
                <div
                  key={d.candidate_id}
                  data-cid={d.candidate_id}
                  className={`tree-item d-${d.status} ${selected?.candidate_id === d.candidate_id ? "active" : ""}`}
                  onClick={() => select(d)}
                >
                  <span className="badge">{d.kind === "theorem-like" ? d.env : d.kind}</span>
                  <span className="t">{d.title}</span>
                  <span className="m">
                    L{d.line} {Math.round((d.confidence || 0) * 100)}%
                    {(d.confidence || 0) < 0.9 && " ⚠"}
                    {reviewed.has(d.candidate_id) && <b className="rev-mark"> ✓</b>}
                  </span>
                </div>
              ))}
            </div>
          ))}
          {!flat.length && <p className="muted">没有匹配当前过滤条件的决策。</p>}
        </aside>
        <main className="col diff">
          {showDiffEditor ? (
            <DiffEditor
              original={source}
              modified={result}
              language="latex"
              onMount={(ed) => (editorRef.current = ed)}
              options={{ readOnly: true, minimap: { enabled: false }, renderSideBySide: true,
                maxComputationTime: 5000, ignoreTrimWhitespace: false }}
              height="72vh"
            />
          ) : (
            <Editor
              value={view === "orig" ? source : result}
              language="latex"
              onMount={(ed) => (editorRef.current = ed)}
              options={{ readOnly: true, minimap: { enabled: false } }}
              height="72vh"
            />
          )}
          {largeDiff && view === "side" && (
            <p className="warning">文档较大，已暂停整本并排 Diff 以避免界面卡顿；可用左侧决策逐条定位，或切换原文/修改后视图。</p>
          )}
        </main>
        <aside className="col inspector">
          {selected ? (
            <>
              <div className="inspector-nav">
                <button onClick={() => move(-1)} disabled={flat[0]?.candidate_id === selected.candidate_id}>↑ 上一条</button>
                <button onClick={() => move(1)} disabled={flat[flat.length - 1]?.candidate_id === selected.candidate_id}>↓ 下一条</button>
                <span>{flat.findIndex((d) => d.candidate_id === selected.candidate_id) + 1}/{flat.length}</span>
              </div>
              <h3>{selected.kind === "theorem-like" ? selected.env : selected.kind}</h3>
              <p className="t">{selected.title}</p>
              <dl>
                <dt>位置</dt><dd>{selected.section || `§ ${selected.line}`} · 第 {selected.line} 行</dd>
                <dt>置信度</dt><dd>{Math.round((selected.confidence || 0) * 100)}%</dd>
                <dt>来源</dt><dd>{selected.source}</dd>
                <dt>状态</dt><dd>{selected.status}{selReviewed ? " · 已确认保留 ✓" : ""}</dd>
                <dt>原因</dt><dd>{selected.reason || "—"}</dd>
              </dl>
              <div className="actions">
                {selApplied && !selReviewed && (
                  <button className="primary" onClick={() => accept(selected)}>A 确认保留</button>
                )}
                {selApplied && (
                  <button onClick={() => reject(selected)}>R 拒绝此修改</button>
                )}
                {selApplied && (
                  <button onClick={() => acceptSimilar(selected)}>同类全部保留</button>
                )}
                {selected.status === "rejected" && (
                  <button onClick={() => rerun(`/api/projects/${pid}/decisions/${selected.candidate_id}/unreject`, { method: "POST" })}>
                    撤销拒绝（恢复此修改）
                  </button>
                )}
              </div>
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

import { useEffect, useRef, useState } from "react";
import { api } from "./api";

export default function Projects({ onOpen }) {
  const [projects, setProjects] = useState([]);
  const [packs, setPacks] = useState([]);
  const [name, setName] = useState("");
  const [mode, setMode] = useState("rule");
  const [pack, setPack] = useState("bilingual");
  const [template, setTemplate] = useState(false);
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [graph, setGraph] = useState(null);
  const fileRef = useRef(null);
  const folderRef = useRef(null);

  const reload = async () => {
    const r = await api("/api/projects");
    setProjects(await r.json());
  };

  useEffect(() => {
    reload();
    api("/api/rulesets")
      .then((r) => r.json())
      .then((d) => {
        setPacks(d.packs);
        setPack(d.default);
      })
      .catch(() => {});
  }, []);

  const doCreate = async () => {
    if (!text.trim()) return alert("请粘贴内容或选择文件");
    setBusy(true);
    try {
      const r = await api("/api/projects", {
        method: "POST",
        body: JSON.stringify({
          text,
          name,
          mode,
          template: template ? "elegantbook" : "",
          pack,
        }),
      });
      const { id } = await r.json();
      await reload();
      onOpen(id);
    } catch (e) {
      alert("创建失败：" + e.message);
    } finally {
      setBusy(false);
    }
  };

  const doFolder = async (fileList) => {
    const files = {};
    for (const f of fileList) {
      if (f.name.endsWith(".tex") || f.name.endsWith(".sty") || f.name.endsWith(".cls") ||
          f.name.endsWith(".bib") || f.webkitRelativePath.split("/").length > 2) {
        files[f.webkitRelativePath] = await f.text();
      }
    }
    if (!Object.keys(files).length) return alert("文件夹中没有可用文件");
    setBusy(true);
    try {
      const r = await api("/api/projects/folder", {
        method: "POST",
        body: JSON.stringify({ files, name, mode, template: template ? "elegantbook" : "", pack }),
      });
      const d = await r.json();
      setGraph(d.graph);
      await reload();
      onOpen(d.id);
    } catch (e) {
      alert("文件夹导入失败：" + e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="projects">
      <section className="card">
        <h2>新建项目</h2>
        <div className="row">
          <input placeholder="项目名称（可选）" value={name} onChange={(e) => setName(e.target.value)} />
          <select value={mode} onChange={(e) => setMode(e.target.value)}>
            <option value="rule">规则模式（无需 AI Key）</option>
            <option value="ai">AI 模式（决策 + 复查）</option>
          </select>
          <select value={pack} onChange={(e) => setPack(e.target.value)}>
            {packs.map((p) => (
              <option key={p} value={p}>{p}</option>
            ))}
          </select>
          <label>
            <input type="checkbox" checked={template} onChange={(e) => setTemplate(e.target.checked)} />
            ElegantBook 模板转换
          </label>
        </div>
        <div className="row">
          <input
            ref={fileRef}
            type="file"
            accept=".tex,.txt"
            onChange={async (e) => setText(await e.target.files[0].text())}
            style={{ display: "none" }}
          />
          <button onClick={() => fileRef.current.click()}>选择 .tex 文件</button>
          <input
            ref={folderRef}
            type="file"
            webkitdirectory=""
            directory=""
            style={{ display: "none" }}
            onChange={(e) => doFolder(e.target.files)}
          />
          <button onClick={() => folderRef.current.click()}>导入项目文件夹（多文件）</button>
          <button className="primary" disabled={busy} onClick={doCreate}>
            {busy ? "处理中……" : "创建项目"}
          </button>
        </div>
        <textarea
          placeholder="粘贴 .tex 全文……"
          value={text}
          onChange={(e) => setText(e.target.value)}
        />
        {graph && (
          <div className="graph-info">
            <b>依赖图</b>：主文件 {graph.main_rel} · 依赖文件 {graph.files.length} 个
            {graph.missing.length > 0 && ` · 缺失 ${graph.missing.length} 处`}
            {graph.cycles.length > 0 && ` · 循环 ${graph.cycles.length} 处`}
            <ul>
              {graph.missing.map((m, i) => <li key={i}>缺失：{m}</li>)}
              {graph.cycles.map((c, i) => <li key={i}>循环：{c.join(" → ")}</li>)}
            </ul>
          </div>
        )}
      </section>
      <section className="card">
        <h2>项目列表</h2>
        <table>
          <thead>
            <tr><th>名称</th><th>模式</th><th>规则包</th><th>创建</th><th></th></tr>
          </thead>
          <tbody>
            {projects.map((p) => (
              <tr key={p.id}>
                <td>{p.name}</td>
                <td>{p.mode}</td>
                <td>{p.pack || "默认"}</td>
                <td>{p.created}</td>
                <td>
                  <button onClick={() => onOpen(p.id)}>打开</button>{" "}
                  <button
                    onClick={async () => {
                      if (!confirm("删除该项目？")) return;
                      await api("/api/projects/" + p.id, { method: "DELETE" });
                      reload();
                    }}
                  >
                    删除
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}

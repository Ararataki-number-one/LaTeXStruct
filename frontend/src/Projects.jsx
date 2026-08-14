import { useEffect, useRef, useState } from "react";
import { api } from "./api";

const TEXT_EXTENSIONS = new Set([
  ".tex", ".sty", ".cls", ".bib", ".bst", ".cfg", ".def", ".bbx", ".cbx", ".lbx", ".txt",
]);

function bytesToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

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
    const selected = Array.from(fileList);
    const totalBytes = selected.reduce((sum, f) => sum + f.size, 0);
    if (selected.length > 1000) return alert("项目文件过多（最多 1000 个）");
    if (totalBytes > 100 * 1024 * 1024) return alert("项目超过 100 MB，请精简后重试");
    const files = {};
    for (const f of selected) {
      const browserPath = f.webkitRelativePath || f.name;
      const parts = browserPath.split("/").filter(Boolean);
      const rel = (parts.length > 1 ? parts.slice(1) : parts).join("/");
      const dot = f.name.lastIndexOf(".");
      const ext = dot >= 0 ? f.name.slice(dot).toLowerCase() : "";
      files[rel] = TEXT_EXTENSIONS.has(ext)
        ? await f.text()
        : { encoding: "base64", data: bytesToBase64(await f.arrayBuffer()) };
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
        <h2>导入项目</h2>
        <div className="row">
          <input placeholder="项目名称（可选）" value={name} onChange={(e) => setName(e.target.value)} />
        </div>
        <details className="advanced">
          <summary>高级选项</summary>
          <div className="row">
            <select value={mode} onChange={(e) => setMode(e.target.value)}>
              <option value="rule">规则模式（默认，无需 AI Key）</option>
              <option value="ai">AI 决策 + 复查</option>
            </select>
            <select value={pack} onChange={(e) => setPack(e.target.value)}>
              {packs.map((p) => (
                <option key={p} value={p}>{p}</option>
              ))}
            </select>
            <label>
              <input type="checkbox" checked={template} onChange={(e) => setTemplate(e.target.checked)} />
              转换为 ElegantBook（显式变换）
            </label>
          </div>
        </details>
        <div className="row">
          <input
            ref={fileRef}
            type="file"
            accept=".tex,.txt"
            onChange={async (e) => {
              const selectedFile = e.target.files?.[0];
              if (selectedFile) setText(await selectedFile.text());
            }}
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
            {busy ? "处理中……" : "导入并打开"}
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
                      try {
                        await api("/api/projects/" + p.id, { method: "DELETE" });
                        reload();
                      } catch (e) {
                        alert("删除失败：" + e.message);
                      }
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

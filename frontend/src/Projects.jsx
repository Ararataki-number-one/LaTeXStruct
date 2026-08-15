import { useEffect, useRef, useState } from "react";
import { api } from "./api";

const TEXT_EXTENSIONS = new Set([
  ".tex", ".sty", ".cls", ".bib", ".bst", ".cfg", ".def", ".bbx", ".cbx", ".lbx", ".txt",
]);
const ACTIVE_TASKS = new Set(["running", "pausing", "paused", "cancelling", "committing"]);

function extension(name) {
  const dot = name.lastIndexOf(".");
  return dot >= 0 ? name.slice(dot).toLowerCase() : "";
}

function bytesToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

function readDirectory(reader) {
  return new Promise((resolve, reject) => {
    const entries = [];
    const next = () => reader.readEntries((batch) => {
      if (!batch.length) resolve(entries);
      else {
        entries.push(...batch);
        next();
      }
    }, reject);
    next();
  });
}

async function walkEntry(entry, parent = "") {
  if (entry.isFile) {
    const file = await new Promise((resolve, reject) => entry.file(resolve, reject));
    return [{ file, path: parent + file.name }];
  }
  if (!entry.isDirectory) return [];
  const children = await readDirectory(entry.createReader());
  const nested = await Promise.all(children.map((child) =>
    walkEntry(child, parent + entry.name + "/")));
  return nested.flat();
}

function describeFiles(fileList) {
  return Array.from(fileList || []).map((file) => ({
    file,
    path: file.webkitRelativePath || file.name,
  }));
}

function normalizedEntries(entries) {
  const clean = entries.map(({ file, path }) => ({
    file,
    path: String(path || file.name).replace(/\\/g, "/").replace(/^\/+/, ""),
  }));
  const roots = new Set(clean.map((item) => item.path.split("/")[0]));
  const stripRoot = roots.size === 1 && clean.every((item) => item.path.includes("/"));
  return clean.map((item) => ({
    file: item.file,
    path: stripRoot ? item.path.split("/").slice(1).join("/") : item.path,
  }));
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
  const [dragging, setDragging] = useState(false);
  const [importState, setImportState] = useState(null);
  const [graph, setGraph] = useState(null);
  const fileRef = useRef(null);
  const folderRef = useRef(null);
  const archiveRef = useRef(null);

  const reload = async () => {
    const response = await api("/api/projects");
    setProjects(await response.json());
  };

  useEffect(() => {
    reload();
    api("/api/rulesets")
      .then((response) => response.json())
      .then((data) => {
        setPacks(data.packs);
        setPack(data.default);
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (!projects.some((project) => ACTIVE_TASKS.has(project.processing?.status))) return undefined;
    const timer = window.setTimeout(() => reload().catch(() => {}), 1200);
    return () => window.clearTimeout(timer);
  }, [projects]);

  const projectOptions = {
    name,
    mode,
    template: template ? "elegantbook" : "",
    pack,
  };

  const doCreate = async () => {
    if (!text.trim()) return alert("请粘贴内容，或拖入/选择一个 .tex 文件");
    setBusy(true);
    setImportState({ progress: 0.25, message: "正在读取单文件项目" });
    try {
      const response = await api("/api/projects", {
        method: "POST",
        body: JSON.stringify({ text, ...projectOptions }),
      });
      const { id } = await response.json();
      setImportState({ progress: 1, message: "导入完成，准备进入分析与审阅" });
      await reload();
      onOpen(id);
    } catch (error) {
      setImportState({ progress: 0, error: true, message: "导入失败：" + error.message });
    } finally {
      setBusy(false);
    }
  };

  const doFolder = async (incoming) => {
    const selected = normalizedEntries(incoming);
    const totalBytes = selected.reduce((sum, item) => sum + item.file.size, 0);
    if (selected.length > 1000) return alert("项目文件过多（最多 1000 个）");
    if (selected.some((item) => item.file.size > 25 * 1024 * 1024)) {
      return alert("项目中有超过 25 MB 的单个文件，请精简后重试");
    }
    if (totalBytes > 100 * 1024 * 1024) return alert("项目超过 100 MB，请精简后重试");
    const files = {};
    setBusy(true);
    try {
      for (let index = 0; index < selected.length; index += 1) {
        const { file, path } = selected[index];
        if (!path || files[path]) throw new Error("项目中存在重复或无效路径：" + path);
        files[path] = TEXT_EXTENSIONS.has(extension(file.name))
          ? await file.text()
          : { encoding: "base64", data: bytesToBase64(await file.arrayBuffer()) };
        setImportState({
          progress: 0.1 + 0.55 * (index + 1) / Math.max(1, selected.length),
          message: `正在读取项目文件 ${index + 1}/${selected.length}：${path}`,
        });
      }
      if (!Object.keys(files).length) throw new Error("文件夹中没有可用文件");
      setImportState({ progress: 0.72, message: "正在智能识别 main.tex 与 input/include 依赖" });
      const response = await api("/api/projects/folder", {
        method: "POST",
        body: JSON.stringify({ files, ...projectOptions, defer_process: true }),
      });
      const data = await response.json();
      setGraph(data.graph);
      setImportState({
        progress: 1,
        message: `已识别主文件 ${data.graph.main_rel}，进入工作台后即可开始分析`,
      });
      await reload();
      onOpen(data.id);
    } catch (error) {
      setImportState({ progress: 0, error: true, message: "文件夹导入失败：" + error.message });
    } finally {
      setBusy(false);
    }
  };

  const doArchive = async (file) => {
    if (!file || extension(file.name) !== ".zip") return alert("请选择 .zip 项目压缩包");
    if (file.size > 100 * 1024 * 1024) return alert("ZIP 超过 100 MB，请精简后重试");
    const form = new FormData();
    form.append("file", file);
    form.append("name", name || file.name.replace(/\.zip$/i, ""));
    form.append("mode", mode);
    form.append("template", template ? "elegantbook" : "");
    form.append("pack", pack);
    form.append("defer_process", "true");
    setBusy(true);
    setImportState({ progress: 0.35, message: "正在安全解压 ZIP 并检查项目结构" });
    try {
      const response = await api("/api/projects/archive", { method: "POST", body: form });
      const data = await response.json();
      setGraph(data.graph);
      setImportState({
        progress: 1,
        message: `ZIP 导入完成，已智能识别主文件 ${data.graph.main_rel}`,
      });
      await reload();
      onOpen(data.id);
    } catch (error) {
      setImportState({ progress: 0, error: true, message: "ZIP 导入失败：" + error.message });
    } finally {
      setBusy(false);
    }
  };

  const handleSingle = async (file) => {
    if (extension(file.name) === ".zip") return doArchive(file);
    if (![".tex", ".txt"].includes(extension(file.name))) {
      return alert("单文件请选择 .tex/.txt；多文件项目请拖入整个文件夹或 ZIP");
    }
    setText(await file.text());
    if (!name) setName(file.name.replace(/\.[^.]+$/, ""));
    setImportState({ progress: 1, message: `已读取 ${file.name}，点击“导入并打开”继续` });
  };

  const onDrop = async (event) => {
    event.preventDefault();
    setDragging(false);
    if (busy) return;
    try {
      const transferItems = Array.from(event.dataTransfer.items || []);
      const entries = transferItems.map((item) => item.webkitGetAsEntry?.()).filter(Boolean);
      let described;
      if (entries.length) {
        described = (await Promise.all(entries.map((entry) => walkEntry(entry)))).flat();
      } else {
        described = describeFiles(event.dataTransfer.files);
      }
      if (!described.length) throw new Error("没有读到可用文件");
      if (described.length === 1 && !described[0].path.includes("/")) {
        await handleSingle(described[0].file);
      } else {
        await doFolder(described);
      }
    } catch (error) {
      setImportState({ progress: 0, error: true, message: "拖拽导入失败：" + error.message });
    }
  };

  const controlProject = async (project, action) => {
    try {
      await api(`/api/projects/${project.id}/process/${action}`, { method: "POST" });
      await reload();
    } catch (error) {
      alert("操作失败：" + error.message);
    }
  };

  return (
    <div className="projects">
      <section className="card import-card">
        <div className="import-heading">
          <div><h2>导入 LaTeX 项目</h2><p>拖入单个 .tex、整个项目文件夹，或 ZIP 压缩包。</p></div>
          <input placeholder="项目名称（可选）" value={name} onChange={(event) => setName(event.target.value)} />
        </div>
        <div
          className={`drop-zone ${dragging ? "dragging" : ""} ${busy ? "busy" : ""}`}
          onDragEnter={(event) => { event.preventDefault(); setDragging(true); }}
          onDragOver={(event) => event.preventDefault()}
          onDragLeave={(event) => {
            if (!event.currentTarget.contains(event.relatedTarget)) setDragging(false);
          }}
          onDrop={onDrop}
        >
          <div className="drop-icon">⇩</div>
          <b>{dragging ? "松开即可智能导入" : "把项目拖到这里"}</b>
          <span>支持 .tex / 项目文件夹 / .zip · ZIP 会自动寻找 main.tex</span>
          <div className="drop-actions">
            <input
              ref={fileRef}
              type="file"
              accept=".tex,.txt"
              hidden
              onChange={(event) => handleSingle(event.target.files?.[0])}
            />
            <button onClick={() => fileRef.current?.click()}>选择 .tex</button>
            <input
              ref={folderRef}
              type="file"
              webkitdirectory=""
              directory=""
              hidden
              onChange={(event) => doFolder(describeFiles(event.target.files))}
            />
            <button onClick={() => folderRef.current?.click()}>选择文件夹</button>
            <input
              ref={archiveRef}
              type="file"
              accept=".zip,application/zip"
              hidden
              onChange={(event) => doArchive(event.target.files?.[0])}
            />
            <button onClick={() => archiveRef.current?.click()}>选择 ZIP</button>
          </div>
          {importState && (
            <div className={`import-progress ${importState.error ? "error" : ""}`} role="status">
              <div className="mini-progress"><span style={{ width: `${Math.round(importState.progress * 100)}%` }} /></div>
              <span>{importState.message}</span>
            </div>
          )}
        </div>

        <details className="advanced">
          <summary>粘贴源码或调整处理方式</summary>
          <div className="row">
            <select value={mode} onChange={(event) => setMode(event.target.value)}>
              <option value="rule">规则模式（默认，无需 API Key）</option>
              <option value="ai">AI 模式（判断 + 复查）</option>
            </select>
            <select value={pack} onChange={(event) => setPack(event.target.value)}>
              {packs.map((item) => <option key={item} value={item}>{item}</option>)}
            </select>
            <label>
              <input type="checkbox" checked={template} onChange={(event) => setTemplate(event.target.checked)} />
              转换为 ElegantBook（显式变换）
            </label>
          </div>
          <textarea
            placeholder="也可以在这里粘贴 .tex 全文……"
            value={text}
            onChange={(event) => setText(event.target.value)}
          />
        </details>
        <div className="import-footer">
          <span className="hint">导入只创建项目副本，不会覆盖你的原文件。</span>
          <button className="primary" disabled={busy || !text.trim()} onClick={doCreate}>
            {busy ? "正在导入……" : "导入并打开"}
          </button>
        </div>
        {graph && (
          <div className="graph-info">
            <b>已识别</b>：主文件 {graph.main_rel} · 依赖文件 {graph.files.length} 个
            {graph.missing.length > 0 && ` · 缺失 ${graph.missing.length} 处`}
            {graph.cycles.length > 0 && ` · 循环 ${graph.cycles.length} 处`}
          </div>
        )}
      </section>

      <section className="card">
        <h2>我的项目</h2>
        <table className="project-table">
          <thead>
            <tr><th>名称</th><th>状态</th><th>模式</th><th>创建时间</th><th>操作</th></tr>
          </thead>
          <tbody>
            {projects.map((project) => {
              const task = project.processing;
              const active = ACTIVE_TASKS.has(task?.status);
              return (
                <tr key={project.id}>
                  <td><b>{project.name}</b>{project.kind === "folder" && <span className="file-badge">多文件</span>}</td>
                  <td>
                    {task ? (
                      <span className={`task-chip ${task.status}`}>
                        {task.status === "paused" ? "已暂停" : task.status === "pausing" ? "暂停中" : "处理中"}
                        {" "}{Math.round((task.progress || 0) * 100)}%
                      </span>
                    ) : project.has_result ? <span className="task-chip done">待审阅</span> : <span className="muted">未分析</span>}
                  </td>
                  <td>{project.mode === "ai" ? "AI" : "规则"}</td>
                  <td>{project.created}</td>
                  <td className="table-actions">
                    <button onClick={() => onOpen(project.id)}>打开</button>
                    {task?.status === "paused" ? (
                      <button onClick={() => controlProject(project, "resume")}>继续</button>
                    ) : ["running", "pausing"].includes(task?.status) ? (
                      <button onClick={() => controlProject(project, "pause")}>暂停</button>
                    ) : null}
                    <button
                      disabled={active}
                      title={active ? "请先取消活动任务" : ""}
                      onClick={async () => {
                        if (!confirm("删除该项目副本？原始文件不会受影响。")) return;
                        try {
                          await api("/api/projects/" + project.id, { method: "DELETE" });
                          reload();
                        } catch (error) {
                          alert("删除失败：" + error.message);
                        }
                      }}
                    >
                      删除
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {!projects.length && <p className="muted">还没有项目。上方拖入一个 .tex、文件夹或 ZIP 即可开始。</p>}
      </section>
    </div>
  );
}

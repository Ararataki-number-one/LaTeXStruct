import { lazy, Suspense, useEffect, useState } from "react";
import { api } from "./api";
import Projects from "./Projects";
import Settings from "./Settings";

// Monaco 只在审阅与 OCR 校对页需要。按页加载可避免导入/设置首屏先解析数 MB 编辑器代码。
const Workspace = lazy(() => import("./Workspace"));
const Ocr = lazy(() => import("./Ocr"));

export default function App() {
  const [tab, setTab] = useState("projects");
  const [currentPid, setCurrentPid] = useState(null);
  const [version, setVersion] = useState("?");
  const [updateInfo, setUpdateInfo] = useState(null);
  const [updating, setUpdating] = useState(false);

  useEffect(() => {
    api("/api/health")
      .then((r) => r.json())
      .then((h) => setVersion(h.version))
      .catch(() => {});
    api("/api/update/check")
      .then((r) => r.json())
      .then((u) => u.available && setUpdateInfo(u))
      .catch(() => {});
  }, []);

  const openProject = (pid) => {
    setCurrentPid(pid);
    setTab("workspace");
  };

  return (
    <div className="app">
      <header className="topbar">
        <h1>LaTeXStruct</h1>
        <span className="sub">数学 LaTeX 安全结构化重构器 · v{version}</span>
        <nav>
          <button className={tab === "projects" ? "active" : ""} onClick={() => setTab("projects")}>导入项目</button>
          <button className={tab === "workspace" ? "active" : ""} onClick={() => setTab("workspace")}>分析与审阅</button>
          <button className={tab === "ocr" ? "active" : ""} onClick={() => setTab("ocr")}>OCR 导入</button>
          <button className={tab === "settings" ? "active" : ""} onClick={() => setTab("settings")}>设置</button>
        </nav>
      </header>
      {updateInfo && (
        <div className="banner">
          <span>
            {updating
              ? "正在下载并校验更新包，完成后将安全关闭并重启应用……"
              : `发现新版本 v${updateInfo.latest}（当前 v${version}）`}
          </span>
          <button
            disabled={updating}
            onClick={async () => {
              const confirmed = window.confirm(
                "更新会关闭并自动重启 LaTeXStruct。请先完成或安全取消运行中的任务，"
                  + "并将已完成 OCR 导入项目或下载原始结果。是否继续？",
              );
              if (!confirmed) return;
              setUpdating(true);
              try {
                const response = await api("/api/update/install", { method: "POST" });
                const result = await response.json();
                if (!result.ok) throw new Error(result.error || "更新准备失败");
              } catch (e) {
                setUpdating(false);
                alert("更新失败：" + e.message);
              }
            }}
          >
            {updating ? "正在准备更新…" : "立即更新"}
          </button>
          {!updating && (
            <button className="secondary" onClick={() => setUpdateInfo(null)}>稍后</button>
          )}
        </div>
      )}
      <main className="content">
        {tab === "projects" && <Projects onOpen={openProject} />}
        {tab === "workspace" && (
          <Suspense fallback={<section className="card">正在加载审阅工作台……</section>}>
            <Workspace pid={currentPid} />
          </Suspense>
        )}
        {tab === "ocr" && (
          <Suspense fallback={<section className="card">正在加载 OCR 校对页……</section>}>
            <Ocr onImport={openProject} onOpenSettings={() => setTab("settings")} />
          </Suspense>
        )}
        {tab === "settings" && <Settings />}
      </main>
    </div>
  );
}

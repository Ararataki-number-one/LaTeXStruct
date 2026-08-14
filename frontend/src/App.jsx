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
          <span>发现新版本 v{updateInfo.latest}（当前 v{version}）</span>
          <button
            onClick={async () => {
              try {
                await api("/api/update/install", { method: "POST" });
                alert("安装器已启动，安装完成后应用将自动重启。");
              } catch (e) {
                alert("更新失败：" + e.message);
              }
            }}
          >
            立即更新
          </button>
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
            <Ocr onImport={openProject} />
          </Suspense>
        )}
        {tab === "settings" && <Settings />}
      </main>
    </div>
  );
}

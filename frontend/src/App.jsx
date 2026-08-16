import { lazy, Suspense, useEffect, useState } from "react";
import { api } from "./api";
import Projects from "./Projects";
import Settings from "./Settings";

// Monaco 只在审阅与 OCR 校对页需要。按页加载可避免导入/设置首屏先解析数 MB 编辑器代码。
const Workspace = lazy(() => import("./Workspace"));
const Ocr = lazy(() => import("./Ocr"));

function displayVersion(value) {
  return String(value || "?")
    .replace(/^v/i, "")
    .replace(/^(\d+\.\d+\.\d+)\.0$/, "$1");
}

function formatBytes(value) {
  const bytes = Number(value || 0);
  if (!Number.isFinite(bytes) || bytes <= 0) return "";
  if (bytes < 1024 * 1024) return `${Math.max(1, Math.round(bytes / 1024))} KB`;
  return `${(bytes / 1024 / 1024).toFixed(bytes >= 10 * 1024 * 1024 ? 1 : 2)} MB`;
}

function sessionValue(key, value) {
  try {
    if (value === undefined) return window.sessionStorage.getItem(key);
    window.sessionStorage.setItem(key, value);
  } catch {
    return null;
  }
  return value;
}

function cleanMarkdownInline(value) {
  return String(value || "")
    .replace(/!\[([^\]]*)\]\([^)]*\)/g, "$1")
    .replace(/\[([^\]]+)\]\([^)]*\)/g, "$1")
    .replace(/`([^`]+)`/g, "$1")
    .replace(/\*\*([^*]+)\*\*/g, "$1")
    .replace(/__([^_]+)__/g, "$1")
    .trim();
}

function ReleaseNotes({ notes, emptyText = "本次更新包含稳定性与使用体验改进。" }) {
  const lines = String(notes || "").replace(/\r/g, "").split("\n");
  const blocks = [];
  let bullets = [];

  const flushBullets = () => {
    if (!bullets.length) return;
    blocks.push(
      <ul key={`list-${blocks.length}`}>
        {bullets.map((item, index) => <li key={`${index}-${item}`}>{item}</li>)}
      </ul>,
    );
    bullets = [];
  };

  lines.forEach((raw, index) => {
    const line = raw.trim();
    if (!line || /^---+$/.test(line)) {
      flushBullets();
      return;
    }
    const heading = line.match(/^#{1,6}\s+(.+)$/);
    if (heading) {
      flushBullets();
      blocks.push(<h4 key={`heading-${index}`}>{cleanMarkdownInline(heading[1])}</h4>);
      return;
    }
    const bullet = line.match(/^[-*+]\s+(.+)$/);
    if (bullet) {
      bullets.push(cleanMarkdownInline(bullet[1]));
      return;
    }
    if (/^\s{2,}\S/.test(raw) && bullets.length) {
      bullets[bullets.length - 1] += ` ${cleanMarkdownInline(line)}`;
      return;
    }
    flushBullets();
    blocks.push(<p key={`paragraph-${index}`}>{cleanMarkdownInline(line)}</p>);
  });
  flushBullets();

  return <div className="update-notes">{blocks.length ? blocks : <p>{emptyText}</p>}</div>;
}

function UpdateIcon({ success = false }) {
  return (
    <span className={`update-icon ${success ? "success" : ""}`} aria-hidden="true">
      {success ? "✓" : "↻"}
    </span>
  );
}

function ModalShell({ title, success = false, closable = true, onClose, children, footer }) {
  useEffect(() => {
    const oldOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => { document.body.style.overflow = oldOverflow; };
  }, []);

  return (
    <div className="update-overlay" role="presentation">
      <section
        className="update-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="update-dialog-title"
      >
        <header className="update-dialog-header">
          <UpdateIcon success={success} />
          <h2 id="update-dialog-title">{title}</h2>
          <button
            className="update-dialog-close"
            type="button"
            aria-label="关闭"
            disabled={!closable}
            onClick={onClose}
          >
            ×
          </button>
        </header>
        <div className="update-dialog-body">{children}</div>
        <footer className="update-dialog-footer">{footer}</footer>
      </section>
    </div>
  );
}

function UpdateAvailableDialog({ info, current, job, onClose, onStart, onCancel }) {
  const status = job?.status || "available";
  const active = ["checking", "downloading", "cancelling", "verifying", "restarting"].includes(status);
  const cancellable = Boolean(job?.id)
    && ["checking", "downloading", "cancelling"].includes(status);
  const latest = displayVersion(job?.latest || info?.latest);
  const percent = Math.max(0, Math.min(100, Math.round(Number(job?.progress || 0) * 100)));
  const hasProgress = ["downloading", "cancelling", "verifying", "restarting"].includes(status);
  const isError = status === "error";
  const isCancelled = status === "cancelled";
  const buttonLabel = isError ? "重试更新" : "立即更新";

  return (
    <ModalShell
      title={active ? "正在更新" : "发现新版本"}
      closable={!active}
      onClose={onClose}
      footer={active ? (
        <>
          <button type="button" disabled={!cancellable || status === "cancelling"} onClick={onCancel}>
            {status === "cancelling" ? "正在取消…" : "取消下载"}
          </button>
          <button type="button" className="primary update-primary" disabled>
            {status === "restarting" ? "即将重启…" : status === "verifying" ? "校验完成" : "下载中…"}
          </button>
        </>
      ) : (
        <>
          <button type="button" onClick={onClose}>稍后</button>
          <button type="button" className="primary update-primary" onClick={onStart}>{buttonLabel}</button>
        </>
      )}
    >
      <div className="update-version">v{latest}</div>
      <p className="update-summary">当前版本 v{displayVersion(current)}，新版本已可用。</p>

      {active && (
        <div className="update-progress-block" aria-live="polite">
          <div
            className={`update-progress ${!hasProgress ? "indeterminate" : ""}`}
            role="progressbar"
            aria-label="更新下载进度"
            aria-valuemin="0"
            aria-valuemax="100"
            aria-valuenow={hasProgress ? percent : undefined}
          >
            <span style={{ width: hasProgress ? `${percent}%` : "36%" }} />
          </div>
          <div className="update-progress-meta">
            <strong>{job?.message || "正在确认新版安装包"}</strong>
            {status === "downloading" && (
              <span>
                {percent}%
                {job?.total_bytes ? ` · ${formatBytes(job.downloaded_bytes)} / ${formatBytes(job.total_bytes)}` : ""}
              </span>
            )}
          </div>
        </div>
      )}

      {(isError || isCancelled) && (
        <div className={`update-feedback ${isError ? "error" : "neutral"}`} role="alert">
          {job?.error || job?.message || "更新已取消，当前版本未发生变化。"}
        </div>
      )}

      <div className="update-divider" />
      <h3>更新内容</h3>
      <ReleaseNotes notes={job?.notes || info?.notes} />
      <p className="update-safety-note">
        安装包会先校验大小与 SHA-256；有运行任务或未保存的 OCR 成果时不会关闭应用。
      </p>
    </ModalShell>
  );
}

function UpdateSuccessDialog({ result, onClose }) {
  return (
    <ModalShell
      title="更新成功！"
      success
      onClose={onClose}
      footer={<button type="button" className="primary update-primary" onClick={onClose}>我知道了</button>}
    >
      <div className="update-version">v{displayVersion(result.current)}</div>
      <p className="update-summary">
        已从 v{displayVersion(result.previous)} 更新到 v{displayVersion(result.current)}。
      </p>
      <div className="update-divider" />
      <h3>更新内容</h3>
      <ReleaseNotes notes={result.notes} />
    </ModalShell>
  );
}

export default function App() {
  const [tab, setTab] = useState("projects");
  const [currentPid, setCurrentPid] = useState(null);
  const [version, setVersion] = useState("?");
  const [updateInfo, setUpdateInfo] = useState(null);
  const [updateDialogOpen, setUpdateDialogOpen] = useState(false);
  const [updateJobId, setUpdateJobId] = useState(null);
  const [updateJob, setUpdateJob] = useState(null);
  const [updateSuccess, setUpdateSuccess] = useState(null);
  const [currentReleaseNotes, setCurrentReleaseNotes] = useState("");

  useEffect(() => {
    let alive = true;

    Promise.all([
      api("/api/health").then((r) => r.json()),
      api("/api/update/result").then((r) => r.json()).catch(() => ({ updated: false })),
    ]).then(([health, result]) => {
      if (!alive) return;
      setVersion(health.version);
      if (result.updated) {
        const dismissKey = `latexstruct-update-success-${result.previous}-${result.current}`;
        if (sessionValue(dismissKey) !== "dismissed") {
          setUpdateSuccess({ ...result, notes: "", dismissKey });
        }
      }
    }).catch(() => {});

    api("/api/update/check")
      .then((r) => r.json())
      .then((info) => {
        if (!alive) return;
        if (info.available) {
          setUpdateInfo(info);
          setUpdateDialogOpen(true);
        } else if (info.notes && displayVersion(info.latest) === displayVersion(info.current)) {
          setCurrentReleaseNotes(info.notes);
        }
      })
      .catch(() => {});

    return () => { alive = false; };
  }, []);

  useEffect(() => {
    if (!updateJobId) return undefined;
    let stopped = false;
    let timer = null;
    let lastStatus = "";

    const poll = async () => {
      try {
        const response = await api(`/api/update/status/${updateJobId}`);
        const snapshot = await response.json();
        if (stopped) return;
        lastStatus = snapshot.status;
        setUpdateJob(snapshot);
        if (["checking", "downloading", "cancelling", "verifying", "restarting"].includes(snapshot.status)) {
          timer = window.setTimeout(poll, snapshot.status === "restarting" ? 900 : 350);
        }
      } catch {
        if (stopped || lastStatus === "restarting") return;
        timer = window.setTimeout(poll, 1200);
      }
    };

    poll();
    return () => {
      stopped = true;
      if (timer) window.clearTimeout(timer);
    };
  }, [updateJobId]);

  const openProject = (pid) => {
    setCurrentPid(pid);
    setTab("workspace");
  };

  const startUpdate = async () => {
    setUpdateDialogOpen(true);
    // 重试前停止旧任务轮询，避免旧的 error/cancelled 快照覆盖新请求状态。
    setUpdateJobId(null);
    setUpdateJob({ status: "checking", progress: 0, message: "正在确认新版安装包" });
    try {
      const response = await api("/api/update/install", { method: "POST" });
      const result = await response.json();
      setUpdateJobId(result.job_id);
      setUpdateJob((previous) => ({ ...(previous || {}), id: result.job_id }));
    } catch (error) {
      setUpdateJobId(null);
      setUpdateJob({
        status: "error",
        progress: 0,
        message: "更新没有开始，当前应用保持运行",
        error: error.message,
      });
    }
  };

  const cancelUpdate = async () => {
    if (!updateJobId) return;
    try {
      await api(`/api/update/status/${updateJobId}/cancel`, { method: "POST" });
      setUpdateJob((previous) => ({
        ...(previous || {}),
        status: "cancelling",
        message: "正在安全取消下载",
      }));
    } catch (error) {
      setUpdateJob((previous) => ({ ...(previous || {}), error: error.message }));
    }
  };

  const closeUpdateDialog = () => {
    setUpdateDialogOpen(false);
    if (["cancelled", "error"].includes(updateJob?.status)) {
      setUpdateJobId(null);
      setUpdateJob(null);
    }
  };

  const closeSuccessDialog = () => {
    if (updateSuccess?.dismissKey) {
      sessionValue(updateSuccess.dismissKey, "dismissed");
    }
    setUpdateSuccess(null);
  };

  return (
    <div className="app">
      <header className="topbar">
        <h1>LaTeXStruct</h1>
        <span className="sub">数学 LaTeX 安全结构化重构器 · v{version}</span>
        <nav>
          {updateInfo && !updateDialogOpen && (
            <button className="update-chip" onClick={() => setUpdateDialogOpen(true)}>
              新版本 v{displayVersion(updateInfo.latest)}
            </button>
          )}
          <button className={tab === "projects" ? "active" : ""} onClick={() => setTab("projects")}>导入项目</button>
          <button className={tab === "workspace" ? "active" : ""} onClick={() => setTab("workspace")}>分析与审阅</button>
          <button className={tab === "ocr" ? "active" : ""} onClick={() => setTab("ocr")}>OCR 导入</button>
          <button className={tab === "settings" ? "active" : ""} onClick={() => setTab("settings")}>设置</button>
        </nav>
      </header>
      <main className={`content ${tab === "workspace" || tab === "ocr" ? "content-workbench" : ""}`}>
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

      {updateDialogOpen && updateInfo && !updateSuccess && (
        <UpdateAvailableDialog
          info={updateInfo}
          current={version}
          job={updateJob}
          onClose={closeUpdateDialog}
          onStart={startUpdate}
          onCancel={cancelUpdate}
        />
      )}
      {updateSuccess && (
        <UpdateSuccessDialog
          result={{ ...updateSuccess, notes: updateSuccess.notes || currentReleaseNotes }}
          onClose={closeSuccessDialog}
        />
      )}
    </div>
  );
}

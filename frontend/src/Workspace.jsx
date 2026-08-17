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

const ACTIVE_TASKS = new Set(["running", "pausing", "paused", "cancelling", "committing"]);
const TERMINAL_TASKS = new Set(["done", "blocked", "error", "cancelled"]);
// @monaco-editor/react 4.7 disposes DiffEditor models before its widget during
// unmount unless keepCurrent* is enabled. Reuse one stable pair across the sole
// Workspace instance so route switches dispose the widget first without leaking
// a new anonymous model for every visit.
const ORIGINAL_MODEL_PATH = "inmemory://latexstruct/workspace/source.tex";
const MODIFIED_MODEL_PATH = "inmemory://latexstruct/workspace/result.tex";
const EDITOR_HEIGHT = "clamp(560px, 68vh, 900px)";

function processIssueGuidance(job) {
  const detail = String(job?.error || job?.message || "");
  if (job?.status === "cancelled" || /取消|cancel/i.test(detail)) {
    return "任务已安全取消，未验证草稿没有保存；需要时可点击“开始分析”重新开始。";
  }
  if (/api\s*key|api\s*base|base\s*url|endpoint|鉴权|认证|unauthori[sz]ed|forbidden|http\s*(401|403)|模型|\bmodel\b/i.test(detail)) {
    return "请打开顶部“设置”，检查服务商、API Key 和模型后再重试。";
  }
  if (/编译|compile|latexmk|xelatex|pdflatex|lualatex|安全检查|公式|数学|label|ref|引用|图片路径|正文变化|回退/i.test(detail)) {
    return "请查看下方安全检查，修复标记的问题后再点击“重新分析”。";
  }
  if (/文件|目录|路径|读取|写入|权限|占用|磁盘|编码|zip|压缩|解压|input|include/i.test(detail)) {
    return "请检查项目文件是否完整、可读且未被占用，然后点击“重新分析”重试。";
  }
  if (/规则|解析|扫描|scanner|parser|patch|补丁|候选|environment|环境/i.test(detail)) {
    return "原文已保留；可点击“重新分析”重试，并根据上面的错误详情定位具体规则。";
  }
  return "原项目没有被覆盖；可点击“重新分析”重试，若仍失败请保留上面的错误详情。";
}

function needsAiSettings(job) {
  const detail = String(job?.error || job?.message || "");
  return /api\s*key|api\s*base|base\s*url|endpoint|鉴权|认证|unauthori[sz]ed|forbidden|http\s*(401|403)|模型|\bmodel\b/i.test(detail);
}

function VerificationFailures({ failures = [], persisted = false }) {
  return (
    <div className="verification-failures" role="alert">
      <b>
        {persisted
          ? "这是上次未通过检查的诊断草稿；原项目和上一次安全结果均未覆盖。"
          : "本次结果没有保存；原项目和上一次安全结果均未覆盖。"}
      </b>
      {failures.length ? failures.map((failure, failureIndex) => (
        <details key={failure.id || `failure-${failureIndex}`} open>
          <summary>{failure.label || "安全检查"}：{failure.summary || "检查未通过"}</summary>
          {Array.isArray(failure.details) && failure.details.slice(0, 5).map((detail, index) => {
            const text = typeof detail === "string"
              ? detail
              : detail?.reason || detail?.message || detail?.path || "请按下方建议检查此项";
            return <p key={`${failure.id || failureIndex}-${index}`}>{text}</p>;
          })}
          <small>下一步：{failure.action || "修复上述问题后点击“重新分析”。"}</small>
        </details>
      )) : (
        <small>失败详情暂时不可用；请点击“重新分析”重试，原项目仍保持不变。</small>
      )}
    </div>
  );
}

function inlineMarkdown(text, keyPrefix) {
  return String(text || "").split(/(`[^`\n]+`)/g).filter(Boolean).map((part, index) => {
    const key = `${keyPrefix}-${index}`;
    if (part.startsWith("`") && part.endsWith("`")) {
      return <code key={key}>{part.slice(1, -1)}</code>;
    }
    return <span key={key}>{part}</span>;
  });
}

function parseReportBlocks(markdown) {
  const blocks = [];
  let paragraph = [];
  let list = null;
  const flushParagraph = () => {
    if (paragraph.length) {
      blocks.push({ type: "paragraph", text: paragraph.join(" ") });
      paragraph = [];
    }
  };
  const flushList = () => {
    if (list) {
      blocks.push(list);
      list = null;
    }
  };

  String(markdown || "").replace(/\r\n?/g, "\n").split("\n").forEach((line) => {
    const heading = line.match(/^(#{1,6})\s+(.+)$/);
    const unordered = line.match(/^\s*[-*+]\s+(.+)$/);
    const ordered = line.match(/^\s*\d+[.)]\s+(.+)$/);
    if (heading) {
      flushParagraph();
      flushList();
      blocks.push({ type: "heading", level: heading[1].length, text: heading[2] });
    } else if (unordered || ordered) {
      flushParagraph();
      const type = ordered ? "ordered" : "unordered";
      if (!list || list.type !== type) {
        flushList();
        list = { type, items: [] };
      }
      list.items.push((ordered || unordered)[1]);
    } else if (!line.trim()) {
      flushParagraph();
      flushList();
    } else {
      flushList();
      paragraph.push(line.trim());
    }
  });
  flushParagraph();
  flushList();
  return blocks;
}

function MarkdownReport({ markdown }) {
  const blocks = useMemo(() => parseReportBlocks(markdown), [markdown]);
  return (
    <div className="report-rendered">
      {blocks.map((block, index) => {
        if (block.type === "heading") {
          const Tag = `h${Math.min(4, block.level + 1)}`;
          return <Tag key={`heading-${index}`}>{inlineMarkdown(block.text, `heading-${index}`)}</Tag>;
        }
        if (block.type === "ordered" || block.type === "unordered") {
          const Tag = block.type === "ordered" ? "ol" : "ul";
          return (
            <Tag key={`list-${index}`}>
              {block.items.map((item, itemIndex) => (
                <li key={`item-${index}-${itemIndex}`}>
                  {inlineMarkdown(item, `item-${index}-${itemIndex}`)}
                </li>
              ))}
            </Tag>
          );
        }
        return <p key={`paragraph-${index}`}>{inlineMarkdown(block.text, `paragraph-${index}`)}</p>;
      })}
    </div>
  );
}

export default function Workspace({ pid, onOpenSettings }) {
  const [info, setInfo] = useState(null);
  const [source, setSource] = useState("");
  const [result, setResult] = useState("");
  const [report, setReport] = useState("");
  const [status, setStatus] = useState("");
  const [fileAction, setFileAction] = useState("");
  const [savedExport, setSavedExport] = useState(null);
  const [job, setJob] = useState(null);
  const [livePreview, setLivePreview] = useState("");
  const [failedAttempt, setFailedAttempt] = useState(null);
  const [pollGeneration, setPollGeneration] = useState(0);
  const [decisions, setDecisions] = useState([]);
  const [verification, setVerification] = useState(null);
  const [graph, setGraph] = useState(null);
  const [selected, setSelected] = useState(null);
  const [filter, setFilter] = useState("all");
  const [conf, setConf] = useState("all");
  const [query, setQuery] = useState("");
  const [view, setView] = useState("side"); // side | orig | mod
  const [focusPreview, setFocusPreview] = useState(false);
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
  const previewVersionRef = useRef({ jobId: null, revision: null });
  const pollFailuresRef = useRef(0);
  const autoFocusedJobRef = useRef(null);

  const load = async () => {
    if (!pid) return;
    let project = null;
    try {
      project = await (await api(`/api/projects/${pid}`)).json();
      setInfo(project);
    } catch {
      setInfo(null);
    }
    setSource(await apiText(`/api/projects/${pid}/source`));
    if (project?.has_result) {
      try {
        setResult(await apiText(`/api/projects/${pid}/result`));
        setReport(await apiText(`/api/projects/${pid}/report`));
      } catch {
        setResult("");
        setReport("结果读取失败，请重新分析；原始内容仍已保留。");
      }
    } else {
      setResult("");
      setReport("尚未分析。点击上方「开始分析」。");
    }
    let decisionsResponse = null;
    let decisionsLoaded = false;
    try {
      const d = await (await api(`/api/projects/${pid}/decisions`)).json();
      decisionsLoaded = true;
      decisionsResponse = d;
      const items = d.items || [];
      setDecisions(items);
      setSelected((previous) =>
        previous ? items.find((item) => item.candidate_id === previous.candidate_id) || null : null);
      setVerification(d.verification || null);
    } catch {
      setDecisions([]);
      setVerification(null);
    }
    if (decisionsResponse?.attempt === "blocked") {
      try {
        const failed = await (await api(`/api/projects/${pid}/failed-draft`)).json();
        if (failed?.attempt !== "blocked" || typeof failed?.draft !== "string") {
          throw new Error("诊断草稿格式无效");
        }
        setFailedAttempt(failed);
        setLivePreview(failed.draft);
        setReport(failed.report || "本次草稿未通过安全检查；原项目保持不变。");
        setFocusPreview(true);
      } catch (error) {
        setFailedAttempt(null);
        setStatus(`安全检查未通过，但诊断草稿无法读取：${error.message}。原项目仍保持不变。`);
      }
    } else if (decisionsLoaded) {
      setFailedAttempt(null);
    }
    try {
      const g = await (await api(`/api/projects/${pid}/graph`)).json();
      setGraph(g.graph);
    } catch {
      setGraph(null);
    }
  };

  useEffect(() => {
    try {
      setReviewed(new Set(JSON.parse(localStorage.getItem(`ls-reviewed-${pid}`) || "[]")));
    } catch {
      setReviewed(new Set());
    }
    setSelected(null);
    setJob(null);
    setLivePreview("");
    setFailedAttempt(null);
    setFileAction("");
    setSavedExport(null);
    setFocusPreview(false);
    previewVersionRef.current = { jobId: null, revision: null };
    pollFailuresRef.current = 0;
    autoFocusedJobRef.current = null;
    undoStack.current = [];
    load();
  }, [pid]);

  useEffect(() => {
    if (!pid) return undefined;
    let stopped = false;
    let timer = null;
    let terminalLoaded = false;
    const schedule = (delay) => {
      if (!stopped) timer = window.setTimeout(poll, delay);
    };
    const poll = async () => {
      try {
        const state = await (await api(`/api/projects/${pid}/process/status`)).json();
        if (stopped) return;
        const priorFailures = pollFailuresRef.current;
        pollFailuresRef.current = 0;
        setJob(state);
        if (state.id && ACTIVE_TASKS.has(state.status) && autoFocusedJobRef.current !== state.id) {
          // 每个任务只自动聚焦一次；用户手动切回全景后不再抢走布局。
          autoFocusedJobRef.current = state.id;
          setFocusPreview(true);
        }
        if (priorFailures) setStatus("连接已恢复，正在继续读取任务进度");

        if (previewVersionRef.current.jobId !== state.id) {
          previewVersionRef.current = { jobId: state.id || null, revision: null };
        }
        const previewRevision = Number(state.preview_revision);
        const hasNewPreview = !Number.isFinite(previewRevision)
          || previewVersionRef.current.revision !== previewRevision;
        if (state.preview_ready && (ACTIVE_TASKS.has(state.status) || state.status === "blocked") && hasNewPreview) {
          try {
            const response = await api(`/api/projects/${pid}/process/preview`);
            const preview = await response.text();
            if (!stopped) {
              setLivePreview(preview);
              const receivedRevision = Number(response.headers.get("X-LaTeXStruct-Preview-Revision"));
              previewVersionRef.current = {
                jobId: state.id || null,
                revision: Number.isFinite(receivedRevision) ? receivedRevision : previewRevision,
              };
            }
          } catch (error) {
            if (!stopped) setStatus("实时草稿暂时读取失败，将随进度自动重试：" + error.message);
          }
        }
        if (ACTIVE_TASKS.has(state.status)) {
          schedule((state.preview_chars || 0) > 1_000_000 ? 1500 : 650);
        } else if (TERMINAL_TASKS.has(state.status) && !terminalLoaded) {
          terminalLoaded = true;
          if (state.status !== "blocked") setLivePreview("");
          await load();
          if (state.status === "done") {
            const summary = state.result || {};
            setStatus((summary.ok ? "安全检查通过" : "安全检查未通过，已回退并禁止导出") +
              `：补丁 ${summary.applied || 0} · 拒绝 ${summary.rejected || 0} · 歧义 ${summary.ambiguous || 0}` +
              (summary.degraded ? "（AI 已降级为规则）" : ""));
          } else if (state.status === "blocked") {
            const summary = state.result || {};
            setStatus(`安全检查未通过，失败草稿已保留供检查：${summary.failure_summary || state.message || "原项目保持不变"}`);
            setFocusPreview(true);
          } else if (state.status === "cancelled") {
            setStatus("任务已取消；未验证草稿未保存，原项目保持不变");
          } else {
            setStatus("处理未完成：" + (state.error || state.message || "原项目保持不变，可重新分析"));
          }
        }
      } catch (error) {
        if (!stopped) {
          const failures = Math.min(pollFailuresRef.current + 1, 6);
          pollFailuresRef.current = failures;
          const retryDelay = Math.min(8000, 650 * (2 ** (failures - 1)));
          setStatus(`暂时无法读取任务进度，${Math.ceil(retryDelay / 1000)} 秒后自动重试：${error.message}`);
          schedule(retryDelay);
        }
      }
    };
    poll();
    return () => {
      stopped = true;
      if (timer) window.clearTimeout(timer);
    };
  }, [pid, pollGeneration]);

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
    setStatus("正在启动可暂停的后台任务……");
    try {
      const state = await (await api(`/api/projects/${pid}/process/start`, { method: "POST" })).json();
      setReviewed(new Set());
      setFailedAttempt(null);
      setJob(state);
      autoFocusedJobRef.current = state.id || null;
      setFocusPreview(true);
      setLivePreview(source);
      previewVersionRef.current = {
        jobId: state.id || null,
        revision: Number.isFinite(Number(state.preview_revision)) ? Number(state.preview_revision) : null,
      };
      pollFailuresRef.current = 0;
      setStatus("后台处理已开始，可随时暂停或取消");
      setPollGeneration((value) => value + 1);
    } catch (e) {
      setStatus("失败：" + e.message);
    }
  };

  const controlTask = async (action) => {
    try {
      const state = await (await api(`/api/projects/${pid}/process/${action}`, { method: "POST" })).json();
      setJob(state);
      setStatus(action === "pause" ? "已请求安全暂停" : action === "resume" ? "已继续处理" : "正在安全取消");
      setPollGeneration((value) => value + 1);
    } catch (error) {
      setStatus("操作失败：" + error.message);
    }
  };

  const copyText = async (label, text) => {
    if (!text) {
      setFileAction(`${label} 暂无可复制内容`);
      return;
    }
    try {
      let copied = false;
      if (navigator.clipboard?.writeText) {
        try {
          await navigator.clipboard.writeText(text);
          copied = true;
        } catch {
          // Electron/浏览器可能暴露 API 却因权限拒绝；继续尝试本地 textarea。
        }
      }
      if (!copied) {
        const area = document.createElement("textarea");
        area.value = text;
        area.setAttribute("readonly", "");
        area.style.position = "fixed";
        area.style.opacity = "0";
        document.body.appendChild(area);
        try {
          area.select();
          copied = document.execCommand("copy");
        } finally {
          area.remove();
        }
      }
      if (!copied) throw new Error("系统未允许访问剪贴板");
      setFileAction(`已复制 ${label}`);
    } catch (error) {
      setFileAction(`复制 ${label} 失败：${error.message}`);
    }
  };

  const copyFromApi = async (path, label) => {
    setFileAction(`正在读取已验证的 ${label}……`);
    try {
      const response = await api(path);
      const text = await response.text();
      await copyText(label, text);
    } catch (error) {
      setFileAction(`复制 ${label} 失败：${error.message}`);
    }
  };

  const downloadFromApi = async (path, filename) => {
    setFileAction(`正在准备 ${filename}……`);
    try {
      const response = await api(path);
      const blob = await response.blob();
      if (!blob.size) throw new Error("服务返回了空文件");
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      setFileAction(`已请求浏览器下载 ${filename}；桌面版若没有保存，请使用“修复下载”`);
    } catch (error) {
      setFileAction(`下载 ${filename} 失败：${error.message}，请重试`);
    }
  };

  const saveToDownloads = async (artifact, label) => {
    setSavedExport(null);
    setFileAction(`正在将 ${label} 保存到下载文件夹……`);
    try {
      const response = await api(`/api/projects/${pid}/exports/${artifact}/save`, {
        method: "POST",
      });
      const saved = await response.json();
      setSavedExport(saved);
      setFileAction(`已保存 ${saved.filename} 到 ${saved.folder}`);
    } catch (error) {
      setSavedExport(null);
      setFileAction(`保存 ${label} 失败：${error.message}，可重试或使用浏览器备用下载`);
    }
  };

  const openSavedLocation = async () => {
    try {
      await api("/api/exports/open-folder", { method: "POST" });
      setFileAction(`已打开 ${savedExport?.folder || "下载文件夹"}`);
    } catch (error) {
      setFileAction(`打开保存位置失败：${error.message}`);
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
  const rejectedCount = decisions.filter((d) => d.status === "rejected").length;
  const ambiguousCount = decisions.filter((d) => d.status === "ambiguous").length;
  const reviewedCount = applied.filter((d) => reviewed.has(d.candidate_id)).length;
  const lowConfidenceCount = applied.filter((d) => (d.confidence || 0) < 0.9).length;
  const safeToExport = verification?.safe_to_export === true;
  const taskActive = ACTIVE_TASKS.has(job?.status);
  const showingFailedDraft = !taskActive
    && Boolean(livePreview)
    && (job?.status === "blocked" || failedAttempt?.attempt === "blocked");
  const failedAttemptDetails = failedAttempt?.details || {};
  const failureDetails = Array.isArray(job?.result?.failures)
    ? job.result.failures
    : Array.isArray(failedAttemptDetails.failures)
      ? failedAttemptDetails.failures
      : [];
  const reportReady = Boolean(info?.has_result && report && !taskActive && !showingFailedDraft);
  const reviewComplete = applied.length === 0 || reviewedCount === applied.length;
  const canExport = safeToExport && reviewComplete && !taskActive && !showingFailedDraft;
  const reviewLocked = taskActive || showingFailedDraft;
  const displayResult = (taskActive || showingFailedDraft) && livePreview ? livePreview : result;
  const largeDiff = source.length + displayResult.length > 1_000_000;
  const showDiffEditor = view === "side" && !largeDiff;
  const tokenTotal = job?.cost?.total_tokens || 0;
  const estimatedCny = job?.cost?.estimated_cost_cny;
  const processedCandidateCount = Number(job?.processed_candidates || 0);
  const candidateTotal = Number(job?.candidate_total || 0);
  const priceText = estimatedCny == null
    ? (tokenTotal ? "自定义/未知模型，暂不估价" : "尚无模型费用")
    : `约 ¥${estimatedCny < 0.01 ? estimatedCny.toFixed(4) : estimatedCny.toFixed(2)}`;

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
    if (reviewLocked) return;
    setReviewed((prev) => new Set(prev).add(d.candidate_id));
  };

  const acceptSimilar = (d) => {
    if (reviewLocked) return;
    setReviewed((prev) => {
      const next = new Set(prev);
      applied.filter((x) => x.kind === d.kind && x.env === d.env)
        .forEach((x) => next.add(x.candidate_id));
      return next;
    });
  };

  const acceptAll = () => {
    if (reviewLocked) return;
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
    if (reviewLocked) {
      setStatus(showingFailedDraft
        ? "失败草稿仅供检查，不能应用审阅操作；请先重新分析。"
        : "请等待当前处理完成或先取消任务，再修改审阅结论");
      return;
    }
    const ok = await rerun(`/api/projects/${pid}/decisions/${d.candidate_id}/reject`, { method: "POST" });
    if (ok) undoStack.current.push(d.candidate_id);
  };

  const undo = async () => {
    if (reviewLocked) {
      setStatus(showingFailedDraft
        ? "失败草稿仅供检查，不能撤销或应用修改；请先重新分析。"
        : "请等待当前处理完成或先取消任务，再修改审阅结论");
      return;
    }
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
  }, [selected, flat, view, job?.status, showingFailedDraft]);

  if (!pid) return <section className="card">请在「项目」页选择或创建一个项目。</section>;

  const selApplied = selected && selected.status === "applied";
  const selReviewed = selected && reviewed.has(selected.candidate_id);

  return (
    <div className="workspace3">
      <section className="card toolbar">
        <b>{info ? `${info.name}（${info.mode}）` : pid}</b>
        <button className="primary" disabled={taskActive} onClick={runProcess}>
          {taskActive ? "正在处理" : result || failedAttempt ? "重新分析" : "开始分析"}
        </button>
        {job?.status === "paused" ? (
          <button className="primary" onClick={() => controlTask("resume")}>▶ 继续</button>
        ) : taskActive && job?.can_pause ? (
          <button onClick={() => controlTask("pause")}>Ⅱ 暂停</button>
        ) : null}
        {taskActive && job?.can_cancel !== false && (
          <button
            className="danger-button"
            disabled={job?.status === "cancelling"}
            onClick={() => { if (confirm("取消本次处理？已验证的旧结果会保留，当前草稿不会保存。")) controlTask("cancel"); }}
          >
            取消
          </button>
        )}
        <button
          disabled={!canExport}
          className="primary"
          title={canExport ? "保存已验证的 ElegantBook 主 TEX" : "需先通过安全检查并完成审阅"}
          onClick={() => saveToDownloads("result", "ElegantBook TEX")}
        >
          导出 ElegantBook TEX
        </button>
        <button
          className="primary"
          disabled={!canExport}
          title={canExport ? "包含主 TEX、图片/资源、elegantbook.cls、许可证和汇报" : "需先通过安全检查并完成审阅"}
          onClick={() => saveToDownloads("package", "完整工程 ZIP")}
        >
          导出完整工程 ZIP
        </button>
        <button
          disabled={!canExport}
          title={canExport ? "复制已验证结果" : "需先通过安全检查并完成审阅"}
          onClick={() => copyFromApi(`/api/projects/${pid}/export`, "ElegantBook TEX")}
        >
          一键复制 TEX
        </button>
        <details className="export-fallbacks">
          <summary>浏览器备用下载</summary>
          <div className="row">
            <button
              disabled={!canExport}
              onClick={() => downloadFromApi(`/api/projects/${pid}/export`, "ElegantBook.tex")}
            >
              TEX 备用下载
            </button>
            <button
              disabled={!canExport}
              onClick={() => downloadFromApi(`/api/projects/${pid}/export-package`, "ElegantBook-project.zip")}
            >
              ZIP 浏览器下载（备用）
            </button>
          </div>
        </details>
        <button disabled={reviewLocked} onClick={() => { if (confirm("撤销全部拒绝并重新应用所有修改？")) rerun(`/api/projects/${pid}/decisions/reset`, { method: "POST" }); }}>
          撤销全部拒绝
        </button>
        <span className="progress">
          已审阅 {reviewedCount}/{applied.length}
          <button onClick={acceptAll} disabled={!applied.length || reviewLocked}>全部接受</button>
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
        <div className="layout-toggle" role="group" aria-label="审阅布局">
          <button
            className={!focusPreview ? "primary" : ""}
            aria-pressed={!focusPreview}
            onClick={() => setFocusPreview(false)}
          >
            审阅全景
          </button>
          <button
            className={focusPreview ? "primary" : ""}
            aria-pressed={focusPreview}
            onClick={() => setFocusPreview(true)}
          >
            专注预览
          </button>
        </div>
        {graph && (
          <span className="graph-info">
            主文件 {graph.main_rel} · 依赖 {graph.files.length}
            {graph.missing.length > 0 && ` · 缺失 ${graph.missing.length}`}
            {graph.cycles.length > 0 && ` · 循环 ${graph.cycles.length}`}
          </span>
        )}
        <span className="status">{status}</span>
        {fileAction && (
          <div className="file-action-status">
            <span role="status">{fileAction}</span>
            {savedExport && <button onClick={openSavedLocation}>打开保存位置</button>}
          </div>
        )}
        {job && job.status !== "idle" && (
          <div className={`process-card process-${job.status}`}>
            <div className="process-summary">
              <div>
                <b>{job.status === "paused" ? "已暂停" : job.status === "done" ? "处理完成" :
                  job.status === "blocked" ? "安全检查未通过" :
                  job.status === "error" ? "处理未完成" : job.status === "cancelled" ? "已取消" :
                  job.status === "pausing" ? "正在安全暂停" : job.status === "cancelling" ? "正在取消" :
                  job.status === "committing" ? "正在安全保存" : "正在处理"}</b>
                <span>{job.phase_label || job.message}</span>
              </div>
              <strong>{Math.round((job.progress || 0) * 100)}%</strong>
            </div>
            <div
              className="process-track"
              role="progressbar"
              aria-label="项目处理进度"
              aria-valuemin="0"
              aria-valuemax="100"
              aria-valuenow={Math.round((job.progress || 0) * 100)}
            >
              <span style={{ width: `${Math.round((job.progress || 0) * 100)}%` }} />
            </div>
            <div className="process-metrics">
              <span>Token：{tokenTotal.toLocaleString()}</span>
              <span>费用：{priceText}</span>
              <span>实时预览：{job.preview_label || "等待草稿"}</span>
              {candidateTotal > 0 && (
                <span>候选进度：{Math.min(processedCandidateCount, candidateTotal)}/{candidateTotal}</span>
              )}
              {Array.isArray(job.completed_candidates) && (
                <span>已形成建议：{job.completed_candidates.length} 项</span>
              )}
              {(job.preview_revision || 0) > 1 && <span>草稿版本：{job.preview_revision}</span>}
            </div>
            <p className="process-current-action">
              当前动作：{job.phase_label || job.message || "等待下一安全批次"}
            </p>
            {job.events?.length > 0 && (
              <ol className="process-events">
                {job.events.slice(-5).map((event, index) => (
                  <li key={`${event.at}-${index}`} className={index === job.events.slice(-5).length - 1 ? "current" : ""}>
                    {event.message}
                  </li>
                ))}
              </ol>
            )}
            {job.error && (
              <>
                <p className="process-error-message">{job.error}。{processIssueGuidance(job)}</p>
                <div className="failure-action-row">
                  <button className="primary" type="button" disabled={taskActive} onClick={runProcess}>重新分析</button>
                  {needsAiSettings(job) && onOpenSettings && (
                    <button type="button" onClick={onOpenSettings}>打开设置</button>
                  )}
                </div>
              </>
            )}
            {job.status === "blocked" && (
              <>
                <VerificationFailures failures={failureDetails} />
                <div className="failure-action-row">
                  <button className="primary" type="button" onClick={runProcess}>重新分析</button>
                  {onOpenSettings && <button type="button" onClick={onOpenSettings}>打开设置</button>}
                </div>
              </>
            )}
            {job.status === "cancelled" && (
              <p className="muted">{processIssueGuidance(job)}</p>
            )}
          </div>
        )}
        {showingFailedDraft && job?.status !== "blocked" && (
          <div className="process-card process-blocked persisted-failure-card">
            <div className="process-summary">
              <div>
                <b>上次安全检查未通过</b>
                <span>失败草稿已恢复，只能用于定位问题</span>
              </div>
              <strong>未保存</strong>
            </div>
            <p className="process-current-action">
              下一步：查看下方失败位置，修复输入或 AI 设置后点击“重新分析”。
            </p>
            <div className="failure-action-row">
              <button className="primary" type="button" onClick={runProcess}>重新分析</button>
              {onOpenSettings && <button type="button" onClick={onOpenSettings}>打开设置</button>}
            </div>
            <VerificationFailures failures={failureDetails} persisted />
          </div>
        )}
        {verification?.checks && !showingFailedDraft && (
          <span className={`safety ${safeToExport ? "safe" : "unsafe"}`}>
            安全检查：{verification.checks.map((c) =>
              `${c.ok ? "✓" : "✗"}${c.label}${c.skipped ? "（未运行）" : ""}`).join(" · ")}
          </span>
        )}
        {safeToExport && !reviewComplete && (
          <span className="warning">完成全部审阅后才可导出。</span>
        )}
        <span className="kbd-hint">
          {showingFailedDraft
            ? "失败草稿仅供检查：↑↓ 可定位问题；审阅、应用与导出已锁定"
            : "↑↓ 切换 · A 确认保留 · R 拒绝 · Ctrl+Z 撤销上次拒绝"}
        </span>
      </section>
      <div className={`review-main ${focusPreview ? "focus-preview" : ""}`}>
        <aside className="col tree" ref={treeRef}>
          {Object.entries(groups).map(([section, items]) => (
            <div key={section}>
              <div className="group-title">{section}</div>
              {items.map((d) => (
                <button
                  type="button"
                  key={d.candidate_id}
                  data-cid={d.candidate_id}
                  className={`tree-item d-${d.status} ${selected?.candidate_id === d.candidate_id ? "active" : ""}`}
                  onClick={() => select(d)}
                  aria-pressed={selected?.candidate_id === d.candidate_id}
                  style={{ width: "100%", border: 0, textAlign: "left" }}
                >
                  <span className="badge">{d.kind === "theorem-like" ? d.env : d.kind}</span>
                  <span className="t">{d.title}</span>
                  <span className="m">
                    L{d.line} {Math.round((d.confidence || 0) * 100)}%
                    {(d.confidence || 0) < 0.9 && " ⚠"}
                    {reviewed.has(d.candidate_id) && <b className="rev-mark"> ✓</b>}
                  </span>
                </button>
              ))}
            </div>
          ))}
          {!flat.length && <p className="muted">没有匹配当前过滤条件的决策。</p>}
        </aside>
        <main className="col diff">
          {(taskActive || showingFailedDraft) && (
            <div className={`live-preview-label ${showingFailedDraft ? "failed-draft" : ""}`}>
              <span className="live-dot" /> {showingFailedDraft ? "失败草稿（仅供定位问题）" : `实时成果：${job?.preview_label || "正在准备草稿"}`}
              <small>{showingFailedDraft ? "不能导出；原项目保持不变" : "未通过安全检查前仅供查看，不会覆盖正式结果"}</small>
            </div>
          )}
          {showDiffEditor ? (
            <DiffEditor
              original={source}
              modified={displayResult}
              originalModelPath={ORIGINAL_MODEL_PATH}
              modifiedModelPath={MODIFIED_MODEL_PATH}
              keepCurrentOriginalModel
              keepCurrentModifiedModel
              language="latex"
              onMount={(ed) => (editorRef.current = ed)}
              options={{ readOnly: true, minimap: { enabled: false }, renderSideBySide: true,
                maxComputationTime: 5000, ignoreTrimWhitespace: false }}
              height={EDITOR_HEIGHT}
            />
          ) : (
            <Editor
              value={view === "orig" ? source : displayResult}
              path={view === "orig" ? ORIGINAL_MODEL_PATH : MODIFIED_MODEL_PATH}
              keepCurrentModel
              language="latex"
              onMount={(ed) => (editorRef.current = ed)}
              options={{ readOnly: true, minimap: { enabled: false } }}
              height={EDITOR_HEIGHT}
            />
          )}
          {largeDiff && view === "side" && (
            <p className="warning">文档较大，已暂停整本并排 Diff 以避免界面卡顿；可用左侧决策逐条定位，或切换原文/修改后视图。</p>
          )}
        </main>
      </div>
      <section className={`col inspector review-bottom ${focusPreview ? "focus-hidden" : ""}`}>
        <div className="review-bottom-grid">
          <section className="decision-detail" aria-label="当前决策详情">
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
                  <button className="primary" disabled={reviewLocked} onClick={() => accept(selected)}>A 确认保留</button>
                )}
                {selApplied && (
                  <button disabled={reviewLocked} onClick={() => reject(selected)}>R 拒绝此修改</button>
                )}
                {selApplied && (
                  <button disabled={reviewLocked} onClick={() => acceptSimilar(selected)}>同类全部保留</button>
                )}
                {selected.status === "rejected" && (
                  <button disabled={reviewLocked} onClick={() => rerun(`/api/projects/${pid}/decisions/${selected.candidate_id}/unreject`, { method: "POST" })}>
                    撤销拒绝（恢复此修改）
                  </button>
                )}
                {showingFailedDraft && (
                  <span className="warning">失败草稿仅供检查，不能接受、拒绝或应用修改。</span>
                )}
              </div>
            </>
          ) : (
            <p className="muted">点击左侧决策项查看详情并跳转 diff 对应行。</p>
          )}
          </section>
          <section className={`result-overview ${safeToExport ? "safe" : "pending"}`}>
            <div className="result-overview-heading">
              <h3>结果概览</h3>
              <span>{showingFailedDraft ? "本次未通过，正在查看失败草稿" : safeToExport ? "安全检查通过" : verification ? "暂不可导出" : "等待分析"}</span>
            </div>
            <div className="result-overview-grid">
              <span><b>{applied.length}</b> 已应用</span>
              <span><b>{rejectedCount}</b> 已拒绝</span>
              <span><b>{ambiguousCount}</b> 待确认</span>
              <span><b>{reviewedCount}/{applied.length}</b> 已审阅</span>
            </div>
            {showingFailedDraft ? (
              <p className="warning">本次失败详情显示在进度卡中；当前编辑器是未保存的诊断草稿，不能导出。</p>
            ) : verification?.checks?.length ? (
              <ul className="safety-check-list" aria-label="安全检查清单">
                {verification.checks.map((check) => (
                  <li key={check.id} className={check.ok ? "ok" : "failed"}>
                    <span aria-hidden="true">{check.ok ? "✓" : "✗"}</span>
                    {check.label}{check.skipped ? "（未运行）" : ""}
                  </li>
                ))}
              </ul>
            ) : <p className="muted">完成分析后，这里会逐项显示公式、引用、图片路径和编译安全检查。</p>}
          </section>
        </div>
        <details className="report-panel">
          <summary>整理汇报（展开查看）</summary>
          <div className="report-heading-row">
            <span className="muted">安全渲染的结果说明与操作记录</span>
            <div className="report-actions">
              <button
                className="primary"
                disabled={!reportReady}
                onClick={() => saveToDownloads("report", "汇报 Markdown")}
              >
                修复下载
              </button>
              <button
                disabled={!reportReady}
                onClick={() => copyFromApi(`/api/projects/${pid}/export-report`, "汇报")}
              >
                一键复制
              </button>
              <button
                disabled={!reportReady}
                title="若桌面保存不可用，可使用浏览器备用下载"
                onClick={() => downloadFromApi(`/api/projects/${pid}/export-report`, "LaTeXStruct-report.md")}
              >
                浏览器下载（备用）
              </button>
            </div>
          </div>
          <MarkdownReport markdown={report} />
          <details className="report-raw">
            <summary>查看原始 Markdown</summary>
            <pre className="report">{report}</pre>
          </details>
        </details>
      </section>
    </div>
  );
}

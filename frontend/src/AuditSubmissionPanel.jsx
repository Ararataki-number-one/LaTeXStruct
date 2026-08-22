import { useEffect, useMemo, useState } from "react";
import { api } from "./api";

const PROFILE_OPTIONS = [
  ["quick", "快速诊断", "当前结果、关键源文件、diff 与报告"],
  ["standard", "标准审计", "完整阶段、编译预览、验证与决策（推荐）"],
  ["full", "完整取证", "再加入页图、公式裁片和项目证据"],
];

function readReviewedIds(pid) {
  if (!pid) return [];
  try {
    const value = JSON.parse(localStorage.getItem(`ls-reviewed-${pid}`) || "[]");
    return Array.isArray(value) ? value.map(String).filter(Boolean).sort() : [];
  } catch {
    return [];
  }
}

function latestPath(pid) {
  const params = new URLSearchParams();
  readReviewedIds(pid).forEach((id) => params.append("reviewed_candidate_id", id));
  const query = params.toString();
  return `/api/projects/${pid}/audit-submission/latest${query ? `?${query}` : ""}`;
}

async function copyText(text) {
  if (!text) throw new Error("当前没有可复制的提交话术");
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const input = document.createElement("textarea");
  input.value = text;
  input.style.position = "fixed";
  input.style.opacity = "0";
  document.body.appendChild(input);
  input.select();
  document.execCommand("copy");
  input.remove();
}

function StatusBadge({ item }) {
  if (!item) return null;
  const stale = Boolean(item.stale);
  return (
    <span className={`audit-status ${stale ? "stale" : ""}`}>
      {stale ? "材料已过期" : (item.verification_status || item.status || "已准备")}
    </span>
  );
}

function AuditDialog({ options, busy, error, onChange, onClose, onSubmit }) {
  return (
    <div className="audit-overlay" role="presentation">
      <section className="audit-dialog" role="dialog" aria-modal="true" aria-labelledby="audit-dialog-title">
        <header>
          <div>
            <span className="audit-kicker">EXTERNAL REVIEW PACKAGE</span>
            <h2 id="audit-dialog-title">生成 AI 审计提交包</h2>
            <p>整理真实源文件、阶段结果、编译证据、验证记录和可直接复制的提示词。</p>
          </div>
          <button type="button" className="audit-close" aria-label="关闭" disabled={busy} onClick={onClose}>×</button>
        </header>

        <div className="audit-dialog-body">
          <fieldset>
            <legend>审计深度</legend>
            <div className="audit-profile-grid">
              {PROFILE_OPTIONS.map(([value, label, description]) => (
                <label key={value} className={options.profile === value ? "selected" : ""}>
                  <input
                    type="radio"
                    name="audit-profile"
                    value={value}
                    checked={options.profile === value}
                    onChange={() => onChange({ profile: value, include_evidence: value === "full" })}
                  />
                  <strong>{label}</strong>
                  <small>{description}</small>
                </label>
              ))}
            </div>
          </fieldset>

          <label className="audit-focus-field">
            <span>重点关注（可选）</span>
            <textarea
              value={options.audit_focus}
              maxLength={4000}
              rows={4}
              placeholder="例如：重点检查定理环境覆盖、公式编号和跨页盒排版。"
              onChange={(event) => onChange({ audit_focus: event.target.value })}
            />
          </label>

          <div className="audit-checks">
            <label><input type="checkbox" checked={options.include_source} onChange={(event) => onChange({ include_source: event.target.checked })} />包含源文件</label>
            <label><input type="checkbox" checked={options.include_compile_logs} onChange={(event) => onChange({ include_compile_logs: event.target.checked })} />包含编译日志</label>
            <label><input type="checkbox" checked={options.include_verification} onChange={(event) => onChange({ include_verification: event.target.checked })} />包含验证与决策记录</label>
            <label><input type="checkbox" checked={options.include_evidence} onChange={(event) => onChange({ include_evidence: event.target.checked })} />包含页图和公式裁片</label>
            <label><input type="checkbox" checked={options.sanitize} onChange={(event) => onChange({ sanitize: event.target.checked })} />自动清理密钥和本机路径</label>
          </div>

          <p className="audit-privacy-note">
            源 PDF 可能包含个人或受版权保护的内容。提交到第三方 AI 前，请确认你有权上传。
          </p>
          {error && <div className="audit-error" role="alert">{error}</div>}
        </div>

        <footer>
          <button type="button" disabled={busy} onClick={onClose}>取消</button>
          <button type="button" className="primary" disabled={busy} onClick={onSubmit}>
            {busy ? "正在建立不可变快照…" : "生成并复制提交话术"}
          </button>
        </footer>
      </section>
    </div>
  );
}

export default function AuditSubmissionPanel({ pid }) {
  const [latest, setLatest] = useState(null);
  const [loading, setLoading] = useState(false);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [options, setOptions] = useState({
    profile: "standard",
    audit_focus: "",
    include_source: true,
    include_compile_logs: true,
    include_verification: true,
    include_evidence: false,
    sanitize: true,
  });

  const reviewedIds = useMemo(() => readReviewedIds(pid), [pid, dialogOpen, latest?.submission_id]);

  useEffect(() => {
    if (!pid) {
      setLatest(null);
      setDialogOpen(false);
      return undefined;
    }
    let stopped = false;
    let timer = null;
    const load = async () => {
      try {
        const response = await api(latestPath(pid));
        const value = await response.json();
        if (!stopped) setLatest(value);
      } catch (requestError) {
        if (!stopped && requestError.status !== 404) setMessage(`审计材料状态读取失败：${requestError.message}`);
      }
      if (!stopped) timer = window.setTimeout(load, 6000);
    };
    load();
    return () => {
      stopped = true;
      if (timer) window.clearTimeout(timer);
    };
  }, [pid]);

  if (!pid) return null;

  const updateOptions = (patch) => setOptions((value) => ({ ...value, ...patch }));

  const generate = async () => {
    setLoading(true);
    setError("");
    setMessage("");
    try {
      const response = await api(`/api/projects/${pid}/audit-submission`, {
        method: "POST",
        body: JSON.stringify({
          ...options,
          force: true,
          reviewed_candidate_ids: reviewedIds,
        }),
      });
      const value = await response.json();
      setLatest(value);
      await copyText(value.prompt_short);
      setDialogOpen(false);
      setMessage("审计提交包已生成，提交话术已复制。ZIP 下载已开始。");
      if (value.download_url) window.location.assign(value.download_url);
    } catch (requestError) {
      setError(requestError.message || "审计提交包生成失败");
    } finally {
      setLoading(false);
    }
  };

  const copyPrompt = async () => {
    try {
      await copyText(latest?.prompt_short);
      setMessage("提交话术已复制。上传 ZIP 后直接粘贴即可。 ");
    } catch (copyError) {
      setMessage(copyError.message);
    }
  };

  const openFolder = async () => {
    try {
      await api(`/api/projects/${pid}/audit-submission/open-folder`, { method: "POST" });
      setMessage("已打开审计提交包所在文件夹。 ");
    } catch (requestError) {
      setMessage(requestError.message);
    }
  };

  const download = () => {
    if (latest?.download_url) window.location.assign(latest.download_url);
  };

  return (
    <>
      <aside className="audit-panel" aria-label="AI 审计提交包">
        <div className="audit-panel-head">
          <div>
            <span className="audit-kicker">AI AUDIT</span>
            <strong>外部独立审计</strong>
          </div>
          <StatusBadge item={latest} />
        </div>
        <p>
          {latest
            ? (latest.stale ? "项目或审阅状态已变化，请重新生成。" : "材料、提示词与 SHA-256 已按本次运行整理。")
            : "一键整理源文件、阶段 TeX、PDF、日志和提示词。"}
        </p>
        <div className="audit-panel-actions">
          <button type="button" className="primary" onClick={() => { setError(""); setDialogOpen(true); }}>
            {latest ? "重新生成" : "生成 AI 审计提交包"}
          </button>
          {latest?.package_ready && !latest.stale && <button type="button" onClick={download}>下载 ZIP</button>}
          {latest?.prompt_short && <button type="button" onClick={copyPrompt}>复制提交话术</button>}
          <button type="button" onClick={openFolder}>打开所在文件夹</button>
        </div>
        {latest?.generated_at_utc && <small>最近生成：{latest.generated_at_utc}</small>}
        {message && <div className="audit-message" role="status">{message}</div>}
      </aside>

      {dialogOpen && (
        <AuditDialog
          options={options}
          busy={loading}
          error={error}
          onChange={updateOptions}
          onClose={() => !loading && setDialogOpen(false)}
          onSubmit={generate}
        />
      )}

      <style>{`
        .audit-panel{position:fixed;right:22px;bottom:22px;z-index:70;width:min(390px,calc(100vw - 44px));padding:16px;border:1px solid rgba(15,23,42,.16);border-radius:18px;background:rgba(255,255,255,.94);box-shadow:0 18px 48px rgba(15,23,42,.18);backdrop-filter:blur(18px)}
        .audit-panel-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px}.audit-panel-head>div{display:grid;gap:2px}.audit-kicker{font-size:10px;font-weight:800;letter-spacing:.14em;color:#64748b}.audit-panel strong{font-size:15px}.audit-panel p{margin:9px 0 12px;color:#475569;font-size:12px;line-height:1.55}.audit-panel-actions{display:flex;flex-wrap:wrap;gap:8px}.audit-panel button,.audit-dialog button{border:1px solid rgba(15,23,42,.16);border-radius:10px;padding:8px 11px;background:#fff;color:#0f172a;font:inherit;font-size:12px;cursor:pointer}.audit-panel button.primary,.audit-dialog button.primary{border-color:#111827;background:#111827;color:#fff}.audit-panel button:disabled,.audit-dialog button:disabled{opacity:.55;cursor:not-allowed}.audit-panel small{display:block;margin-top:10px;color:#64748b}.audit-status{padding:4px 8px;border-radius:999px;background:#ecfdf5;color:#047857;font-size:10px;font-weight:800}.audit-status.stale{background:#fff7ed;color:#c2410c}.audit-message{margin-top:10px;padding:8px 10px;border-radius:10px;background:#f8fafc;color:#334155;font-size:11px;line-height:1.45}
        .audit-overlay{position:fixed;inset:0;z-index:120;display:grid;place-items:center;padding:24px;background:rgba(15,23,42,.45);backdrop-filter:blur(8px)}.audit-dialog{width:min(720px,100%);max-height:min(860px,calc(100vh - 48px));overflow:auto;border:1px solid rgba(255,255,255,.45);border-radius:22px;background:#fff;box-shadow:0 28px 90px rgba(15,23,42,.35)}.audit-dialog>header{display:flex;justify-content:space-between;gap:18px;padding:22px 24px 16px;border-bottom:1px solid #e2e8f0}.audit-dialog h2{margin:3px 0 5px;font-size:22px}.audit-dialog header p{margin:0;color:#64748b;font-size:13px}.audit-close{width:34px;height:34px;padding:0!important;border-radius:999px!important;font-size:22px!important}.audit-dialog-body{display:grid;gap:20px;padding:20px 24px}.audit-dialog fieldset{margin:0;padding:0;border:0}.audit-dialog legend,.audit-focus-field>span{display:block;margin-bottom:9px;font-size:12px;font-weight:800;color:#334155}.audit-profile-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}.audit-profile-grid label{display:grid;gap:5px;padding:13px;border:1px solid #dbe3ee;border-radius:14px;cursor:pointer}.audit-profile-grid label.selected{border-color:#111827;box-shadow:0 0 0 1px #111827}.audit-profile-grid input{position:absolute;opacity:0}.audit-profile-grid strong{font-size:13px}.audit-profile-grid small{color:#64748b;line-height:1.45}.audit-focus-field textarea{box-sizing:border-box;width:100%;resize:vertical;border:1px solid #cbd5e1;border-radius:12px;padding:11px 12px;font:inherit;line-height:1.5}.audit-checks{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:9px 14px}.audit-checks label{display:flex;align-items:center;gap:8px;font-size:12px;color:#334155}.audit-privacy-note{margin:0;padding:10px 12px;border-radius:11px;background:#fff7ed;color:#9a3412;font-size:11px;line-height:1.5}.audit-error{padding:10px 12px;border-radius:11px;background:#fef2f2;color:#b91c1c;font-size:12px}.audit-dialog>footer{display:flex;justify-content:flex-end;gap:9px;padding:15px 24px 20px;border-top:1px solid #e2e8f0}
        @media (max-width:720px){.audit-profile-grid{grid-template-columns:1fr}.audit-checks{grid-template-columns:1fr}.audit-panel{right:12px;bottom:12px;width:calc(100vw - 24px)}}
      `}</style>
    </>
  );
}

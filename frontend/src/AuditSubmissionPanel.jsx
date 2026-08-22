import { useEffect, useId, useState } from "react";
import {
  AUDIT_PROFILES,
  DEFAULT_AUDIT_FORM,
  auditProfileLabel,
  auditRunStatusLabel,
  auditSubmissionActionState,
  auditUnavailableReason,
  auditVerificationStatusLabel,
  auditWorkflowLabel,
  buildAuditSubmissionRequest,
  canOpenAuditSubmissionDialog,
  formatAuditCreatedAt,
  normalizeAuditForm,
  selectableAuditHistory,
} from "./auditSubmission";

const CHECKBOXES = [
  ["include_source_files", "包含源文件"],
  ["include_compile_logs", "包含编译日志"],
  ["include_verification_records", "包含验证和决策记录"],
  ["include_page_images", "包含页图"],
  ["include_formula_crops", "包含公式裁片"],
  ["sanitize_sensitive", "自动清理敏感信息"],
];

function AuditSubmissionDialog({ busy, canGenerateCurrent, error, history, initialValue, onClose, onGenerate }) {
  const titleId = useId();
  const [form, setForm] = useState(() => normalizeAuditForm(initialValue || DEFAULT_AUDIT_FORM));
  const [snapshotId, setSnapshotId] = useState("");
  const selectableHistory = selectableAuditHistory(history);
  const selectedRunReady = snapshotId
    ? selectableHistory.some((item) => item.snapshot_id === snapshotId)
    : canGenerateCurrent;

  useEffect(() => {
    const onKeyDown = (event) => {
      if (event.key === "Escape" && !busy) onClose();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [busy, onClose]);

  const update = (name, value) => setForm((previous) => ({ ...previous, [name]: value }));
  const selectProfile = (profile) => setForm((previous) => ({
    ...previous,
    profile,
    include_page_images: profile === "full",
    include_formula_crops: profile === "full",
  }));
  const submit = async (event) => {
    event.preventDefault();
    if (!selectedRunReady) return;
    if (!form.sanitize_sensitive && !window.confirm(
      "关闭敏感信息清理可能把密钥、Authorization 或本机路径写入材料包。仍要继续吗？",
    )) return;
    await onGenerate(buildAuditSubmissionRequest({ ...form, snapshot_id: snapshotId }));
  };

  return (
    <div className="update-overlay audit-submission-overlay" role="presentation">
      <section
        className="update-dialog audit-submission-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
      >
        <header className="update-dialog-header audit-submission-dialog-header">
          <span className="audit-submission-icon" aria-hidden="true">AI</span>
          <div>
            <h2 id={titleId}>生成 AI 审计提交包</h2>
            <p>文件角色和组成由 LaTeXStruct 根据不可变运行快照确定。</p>
          </div>
          <button
            className="update-dialog-close"
            type="button"
            aria-label="关闭"
            disabled={busy}
            onClick={onClose}
          >
            ×
          </button>
        </header>
        <form onSubmit={submit} className="audit-submission-form">
          <div className="update-dialog-body">
            <label className="audit-run-field">
              <span>审计运行</span>
              <select
                value={snapshotId}
                disabled={busy}
                onChange={(event) => setSnapshotId(event.target.value)}
              >
                <option value="" disabled={!canGenerateCurrent}>
                  当前运行{canGenerateCurrent ? "（默认）" : "（暂不可生成）"}
                </option>
                {selectableHistory.map((item) => (
                  <option key={item.snapshot_id} value={item.snapshot_id}>
                    历史材料 · {auditWorkflowLabel(item.workflow)} · {auditRunStatusLabel(item.status || item.run_terminal_status)} · {formatAuditCreatedAt(item.captured_at)}
                  </option>
                ))}
              </select>
              <small>
                选择历史运行只会打包该不可变快照，不会替换或伪装成当前材料。
              </small>
            </label>

            <fieldset className="audit-depth-fieldset">
              <legend>审计深度</legend>
              <div className="audit-depth-grid">
                {AUDIT_PROFILES.map((item) => (
                  <label key={item.value} className={form.profile === item.value ? "selected" : ""}>
                    <input
                      type="radio"
                      name="audit-profile"
                      value={item.value}
                      checked={form.profile === item.value}
                      disabled={busy}
                      onChange={() => selectProfile(item.value)}
                    />
                    <b>{item.label}</b>
                    <small>{item.hint}</small>
                  </label>
                ))}
              </div>
            </fieldset>

            <label className="audit-focus-field">
              <span>重点关注 <small>（可选，只影响审计表达，不决定包内文件）</small></span>
              <textarea
                value={form.audit_focus}
                disabled={busy}
                rows={4}
                maxLength={4000}
                placeholder="例如：重点检查定理环境边界、目录完整性和公式编号。"
                onChange={(event) => update("audit_focus", event.target.value)}
              />
            </label>

            <fieldset className="audit-options-fieldset">
              <legend>材料选项</legend>
              <div className="audit-options-grid">
                {CHECKBOXES.map(([name, label]) => (
                  <label key={name} className={name === "sanitize_sensitive" ? "privacy-option" : ""}>
                    <input
                      type="checkbox"
                      checked={Boolean(form[name])}
                      disabled={busy}
                      onChange={(event) => update(name, event.target.checked)}
                    />
                    <span>{label}</span>
                  </label>
                ))}
              </div>
            </fieldset>
            <p className="audit-safety-note">
              ZIP 内不会写入本机绝对路径；实际文件清单、角色、哈希、别名和验证状态以 manifest 为准。
            </p>
            {error && <p className="audit-submission-error" role="alert">{error}</p>}
          </div>
          <footer className="update-dialog-footer">
            <button type="button" disabled={busy} onClick={onClose}>取消</button>
            <button type="submit" className="primary update-primary" disabled={busy || !selectedRunReady}>
              {busy ? "正在生成……" : "生成完整 ZIP"}
            </button>
          </footer>
        </form>
      </section>
    </div>
  );
}

function HistoricalAuditSubmissionCard({ submission, busy, onDownload }) {
  const zipReady = String(submission?.bundle_state || "").toUpperCase() === "ZIP_READY"
    || Boolean(submission?.filename && submission?.submission_id);
  const canDownload = !busy && zipReady && Boolean(submission?.submission_id);
  return (
    <section className="audit-submission-card historical" aria-label="刚生成的历史 AI 审计材料">
      <div className="audit-submission-card-heading">
        <div>
          <b>刚生成的历史审计包</b>
          <span>独立历史快照，不会替换当前材料</span>
        </div>
        <span className="audit-freshness-chip historical">历史材料</span>
      </div>
      <dl className="audit-submission-meta">
        <div><dt>工作流</dt><dd>{auditWorkflowLabel(submission?.workflow)}</dd></div>
        <div><dt>运行状态</dt><dd>{auditRunStatusLabel(submission?.run_terminal_status)}</dd></div>
        <div><dt>快照时间</dt><dd>{formatAuditCreatedAt(submission?.captured_at)}</dd></div>
        <div><dt>快照编号</dt><dd title={submission?.snapshot_id || ""}>{submission?.snapshot_id || "未知"}</dd></div>
        <div><dt>生成时间</dt><dd>{formatAuditCreatedAt(submission?.created_at || submission?.generated_at)}</dd></div>
        <div><dt>文件</dt><dd title={submission?.filename || ""}>{submission?.filename || "尚未生成完整 ZIP"}</dd></div>
      </dl>
      <div className="audit-stale-warning historical-note">
        <b>这是显式选择的历史材料，不代表当前 TEX、PDF 或审阅状态。</b>
      </div>
      <div className="audit-submission-actions">
        <button
          type="button"
          disabled={!canDownload}
          title={zipReady ? "下载所选历史快照的完整 ZIP" : "该历史运行尚无完整 ZIP"}
          onClick={() => onDownload(submission)}
        >
          下载历史材料 ZIP
        </button>
      </div>
    </section>
  );
}

function AuditSubmissionCard({ latest, busy, canRegenerate, onCopy, onOpenFolder, onDownload, onRegenerate }) {
  const actions = auditSubmissionActionState(latest, busy);
  const { stale, zipReady } = actions;
  const reasons = Array.isArray(latest?.stale_reasons) ? latest.stale_reasons.filter(Boolean) : [];
  return (
    <section className={`audit-submission-card ${stale ? "stale" : "current"}`} aria-label="最近一次 AI 审计提交包">
      <div className="audit-submission-card-heading">
        <div>
          <b>{stale ? "上一次提交包（已过期）" : "最近一次 AI 审计提交包"}</b>
          <span>{zipReady ? "完整 ZIP 已生成" : "轻量审计材料已准备"}</span>
        </div>
        <span className={`audit-freshness-chip ${stale ? "stale" : "current"}`}>
          {stale ? "已过期" : "当前材料"}
        </span>
      </div>
      <dl className="audit-submission-meta">
        <div><dt>工作流</dt><dd>{auditWorkflowLabel(latest?.workflow)}</dd></div>
        <div><dt>运行状态</dt><dd>{auditRunStatusLabel(latest?.run_terminal_status)}</dd></div>
        <div><dt>验证</dt><dd>{auditVerificationStatusLabel(latest?.verification_status)}</dd></div>
        <div><dt>审计深度</dt><dd>{auditProfileLabel(latest?.profile)}</dd></div>
        <div><dt>生成时间</dt><dd>{formatAuditCreatedAt(latest?.created_at || latest?.generated_at)}</dd></div>
        <div><dt>文件</dt><dd title={latest?.filename || ""}>{latest?.filename || "尚未生成完整 ZIP"}</dd></div>
      </dl>
      {stale && (
        <div className="audit-stale-warning" role="alert">
          <b>当前 TEX、PDF 或审阅状态已改变，请重新生成后再提交。</b>
          {reasons.slice(0, 2).map((reason, index) => <span key={`${reason}-${index}`}>{reason}</span>)}
        </div>
      )}
      <div className="audit-submission-actions">
        <button
          type="button"
          className={!stale && latest?.short_prompt ? "primary" : ""}
          disabled={!actions.canCopy}
          title={stale ? "材料已过期，请先重新生成" : "复制一句可直接发给 ChatGPT/Codex 的话术"}
          onClick={() => onCopy(latest)}
        >
          复制提交话术
        </button>
        <button
          type="button"
          disabled={!actions.canOpenFolder}
          title={stale ? "材料已过期，请先重新生成" : "打开 LaTeXStruct 固定下载文件夹"}
          onClick={() => onOpenFolder(latest)}
        >
          打开所在文件夹
        </button>
        <button type="button" disabled={!actions.canRegenerate || !canRegenerate} onClick={onRegenerate}>重新生成</button>
        {zipReady && (
          <details className="audit-download-fallback">
            <summary>备用下载</summary>
            <button
              type="button"
              disabled={!actions.canDownload}
              title={stale ? "材料已过期，请先重新生成" : "使用浏览器下载完整 ZIP"}
              onClick={() => onDownload(latest)}
            >
              浏览器下载 ZIP
            </button>
          </details>
        )}
      </div>
    </section>
  );
}

export default function AuditSubmissionPanel({
  latest,
  history = [],
  historicalResult,
  available,
  canGenerate,
  reason,
  busy,
  error,
  onClearError,
  onGenerate,
  onCopy,
  onOpenFolder,
  onDownload,
}) {
  const [dialogOpen, setDialogOpen] = useState(false);
  const [lastRequest, setLastRequest] = useState(null);
  const selectableHistory = selectableAuditHistory(history);
  const canOpenDialog = canOpenAuditSubmissionDialog(canGenerate, selectableHistory);
  const openDialog = () => {
    onClearError();
    setDialogOpen(true);
  };
  const closeDialog = () => {
    if (!busy) setDialogOpen(false);
  };
  const generate = async (request) => {
    const completed = await onGenerate(request);
    if (completed) {
      setLastRequest(request);
      setDialogOpen(false);
    }
  };
  const initialValue = lastRequest
    || latest?.effective_options
    || latest?.request
    || DEFAULT_AUDIT_FORM;

  return (
    <>
      <button
        type="button"
        className="audit-generate-button"
        disabled={busy || !canOpenDialog}
        title={!canOpenDialog ? auditUnavailableReason(reason) : "生成可直接提交给 ChatGPT/Codex 的标准审计材料包"}
        onClick={openDialog}
      >
        {busy ? "正在生成审计包" : "生成 AI 审计提交包"}
      </button>
      {!canGenerate && !available && !latest && reason && (
        <span className="audit-unavailable-hint">{auditUnavailableReason(reason)}</span>
      )}
      {latest && (
        <AuditSubmissionCard
          latest={latest}
          busy={busy}
          canRegenerate={canOpenDialog}
          onCopy={onCopy}
          onOpenFolder={onOpenFolder}
          onDownload={onDownload}
          onRegenerate={openDialog}
        />
      )}
      {historicalResult && (
        <HistoricalAuditSubmissionCard
          submission={historicalResult}
          busy={busy}
          onDownload={onDownload}
        />
      )}
      {dialogOpen && (
        <AuditSubmissionDialog
          key={`${latest?.submission_id || "new"}-${latest?.created_at || latest?.generated_at || ""}`}
          busy={busy}
          canGenerateCurrent={canGenerate}
          error={error}
          history={selectableHistory}
          initialValue={initialValue}
          onClose={closeDialog}
          onGenerate={generate}
        />
      )}
    </>
  );
}

import { useEffect, useMemo, useState } from "react";
import { api } from "./api";
import { apiAuthority, sameApiAuthority } from "./providerUrl";
import {
  CODEX_BACKEND,
  buildSettingsPayload,
  effectivePendingKeys,
  hasUsableConfiguredRoleKey,
  matchingPreset,
  modelsForRole,
  normalizeSettingsConfig,
  pendingKeyAfterEndpointChange,
  pendingKeyAfterEndpointEdit,
  sanitizeCodexStatus,
} from "./settingsContract";

const ROLES = [
  { prefix: "decide", label: "结构判断", help: "用于识别哪些文本应变成定理、证明或章节结构", icon: "brain", tone: "blue", note: "适合日常结构整理，可优先选择速度更快的文字模型。" },
  { prefix: "review", label: "AI 复查", help: "用于再次检查修改范围、边界与置信度", icon: "shield", tone: "green", note: "复杂文档建议选择能力更强的模型进行独立复查。" },
  { prefix: "ocr", label: "图片 / PDF OCR", help: "用于读取图片或扫描 PDF，并转写为 LaTeX", icon: "image", tone: "purple", vision: true, note: "必须使用支持图片输入的视觉模型。" },
];

const COMPARE_FIELDS = [
  "analysis_backend", "codex_model", "codex_reasoning_effort",
  "decide_base_url", "decide_model", "review_base_url", "review_model",
  "review_enabled", "ocr_base_url", "ocr_model", "keyring",
];

const normalizeUrl = (value) => String(value || "").trim().replace(/\/+$/, "");
const sameApiHost = (left, right) => sameApiAuthority(left, right);

function providerName(preset, baseUrl) {
  if (preset?.provider_label) return preset.provider_label;
  if (preset?.provider === "deepseek") return "DeepSeek";
  if (preset?.provider === "qwen-cn") return "阿里云百炼 Qwen";
  const authority = apiAuthority(baseUrl);
  if (sameApiAuthority(baseUrl, "https://api.deepseek.com")) return "DeepSeek";
  if (authority.includes("aliyuncs.com")) return "Qwen";
  return "自定义";
}

function statusBoolean(value, loading) {
  if (loading) return "检查中";
  return value === true ? "是" : "否";
}

function displayTime(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return new Intl.DateTimeFormat("zh-CN", { hour: "2-digit", minute: "2-digit", hour12: false }).format(date);
}

function Icon({ name, size = 20 }) {
  const props = { width: size, height: size, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: 1.9, strokeLinecap: "round", strokeLinejoin: "round", "aria-hidden": true };
  if (name === "brain") return <svg {...props}><path d="M9.5 5.2A3.2 3.2 0 0 0 4 7.4a3.5 3.5 0 0 0 .8 6.7A3.2 3.2 0 0 0 9.5 19V5.2ZM14.5 5.2A3.2 3.2 0 0 1 20 7.4a3.5 3.5 0 0 1-.8 6.7 3.2 3.2 0 0 1-4.7 4.9V5.2Z" /><path d="M7.1 9.1c.8 0 1.5.4 1.9 1M16.9 9.1c-.8 0-1.5.4-1.9 1M6.8 14.2c.9-.1 1.8.3 2.3 1M17.2 14.2c-.9-.1-1.8.3-2.3 1" /></svg>;
  if (name === "shield") return <svg {...props}><path d="M12 3 20 6v5.4c0 4.4-3 7.8-8 9.6-5-1.8-8-5.2-8-9.6V6l8-3Z" /><path d="m8.5 12 2.2 2.2 4.8-5" /></svg>;
  if (name === "image") return <svg {...props}><rect x="3" y="4" width="18" height="16" rx="2.4" /><circle cx="8.4" cy="9" r="1.5" /><path d="m5.5 18 5-5 3 3 2-2 3 4" /></svg>;
  if (name === "lock") return <svg {...props}><rect x="5" y="10" width="14" height="10" rx="2" /><path d="M8.5 10V7.5a3.5 3.5 0 0 1 7 0V10" /></svg>;
  if (name === "eye") return <svg {...props}><path d="M2.8 12s3.3-5 9.2-5 9.2 5 9.2 5-3.3 5-9.2 5-9.2-5-9.2-5Z" /><circle cx="12" cy="12" r="2.2" /></svg>;
  if (name === "eye-off") return <svg {...props}><path d="m4 4 16 16M9.7 7.2A9.7 9.7 0 0 1 12 7c5.9 0 9.2 5 9.2 5M14.2 14.2A3.1 3.1 0 0 1 9.8 9.8M6.2 8.2A14 14 0 0 0 2.8 12s3.3 5 9.2 5c.9 0 1.7-.1 2.4-.3" /></svg>;
  if (name === "check") return <svg {...props}><circle cx="12" cy="12" r="9" /><path d="m8 12.2 2.5 2.5 5.7-6" /></svg>;
  if (name === "refresh") return <svg {...props}><path d="M20 7v5h-5M4 17v-5h5" /><path d="M6.1 8.2A7 7 0 0 1 18.6 7L20 12M4 12l1.4 5a7 7 0 0 0 12.5-1.2" /></svg>;
  if (name === "close") return <svg {...props}><path d="m6 6 12 12M18 6 6 18" /></svg>;
  if (name === "key") return <svg {...props}><circle cx="8" cy="15.5" r="3.5" /><path d="m10.5 13 8-8M16 7l2 2M14 9l2 2" /></svg>;
  if (name === "spark") return <svg {...props}><path d="m12 3 1.2 3.8L17 8l-3.8 1.2L12 13l-1.2-3.8L7 8l3.8-1.2L12 3ZM18.5 14l.7 2.3 2.3.7-2.3.7-.7 2.3-.7-2.3-2.3-.7 2.3-.7.7-2.3Z" /></svg>;
  return <svg {...props}><path d="M4 6h7M15 6h5M4 12h3M11 12h9M4 18h9M17 18h3" /><circle cx="13" cy="6" r="2" /><circle cx="9" cy="12" r="2" /><circle cx="15" cy="18" r="2" /></svg>;
}

function StepHeading({ number, title, description, aside }) {
  return <div className="settings-step-heading"><span className="settings-step-number">{number}</span><div><h2>{title}</h2>{description && <p>{description}</p>}</div>{aside && <span className="settings-step-aside">{aside}</span>}</div>;
}

function ToggleCard({ checked, disabled, icon, title, description, onChange }) {
  return <label className={`settings-toggle-card ${disabled ? "disabled" : ""}`}><span className="settings-switch"><input type="checkbox" checked={checked} disabled={disabled} onChange={onChange} /><span aria-hidden="true" /></span><Icon name={icon} size={18} /><span><b>{title}</b><small>{description}</small></span></label>;
}

export default function Settings() {
  const [cfg, setCfg] = useState(null);
  const [savedCfg, setSavedCfg] = useState(null);
  const [providers, setProviders] = useState([]);
  const [advancedKeys, setAdvancedKeys] = useState({});
  const [showKeys, setShowKeys] = useState({});
  const [shareTextKey, setShareTextKey] = useState(true);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [plainKeyConfirmed, setPlainKeyConfirmed] = useState(false);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState("");
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState("");
  const [connectionStates, setConnectionStates] = useState({});
  const [codexStatus, setCodexStatus] = useState(null);
  const [codexStatusLoading, setCodexStatusLoading] = useState(false);
  const [codexStatusError, setCodexStatusError] = useState("");
  const [lastSavedAt, setLastSavedAt] = useState(() => { try { return window.localStorage.getItem("latexstruct.settings.savedAt") || ""; } catch { return ""; } });

  const loadCodexStatus = async () => {
    setCodexStatusLoading(true); setCodexStatusError("");
    try {
      const response = await api("/api/codex/status");
      setCodexStatus(sanitizeCodexStatus(await response.json()));
    } catch (error) { setCodexStatus(null); setCodexStatusError(error.message); }
    finally { setCodexStatusLoading(false); }
  };

  const loadSettings = () => {
    setLoading(true); setLoadError(""); setMsg("");
    return Promise.all([api("/api/config").then((r) => r.json()), api("/api/providers").then((r) => r.json())])
      .then(([config, data]) => {
        const normalized = normalizeSettingsConfig(config);
        const list = Array.isArray(data.providers) ? data.providers : [];
        const suggested = { ...normalized };
        if (normalized.analysis_backend !== CODEX_BACKEND) {
          for (const role of ROLES) {
            if (String(suggested[`${role.prefix}_model`] || "").trim()) continue;
            const fallback = list.find((item) => item.recommended
              && (item.roles || []).includes(role.prefix)
              && (!role.vision || item.vision === true))
              || modelsForRole(list, role)[0];
            if (fallback) {
              suggested[`${role.prefix}_base_url`] = fallback.base_url;
              suggested[`${role.prefix}_model`] = fallback.model;
            }
          }
        }
        setCfg(suggested); setSavedCfg(normalized); setProviders(list);
        setShareTextKey(sameApiHost(suggested.decide_base_url, suggested.review_base_url));
        if (normalized.analysis_backend === CODEX_BACKEND) loadCodexStatus();
      })
      .catch(() => setLoadError("无法加载 AI 设置。请确认本地服务正在运行，然后重试。"))
      .finally(() => setLoading(false));
  };

  useEffect(() => { loadSettings(); }, []);

  const backend = cfg?.analysis_backend === CODEX_BACKEND ? CODEX_BACKEND : "api";
  const canShareTextKey = sameApiHost(cfg?.decide_base_url, cfg?.review_base_url);
  const pendingKeys = effectivePendingKeys(advancedKeys, shareTextKey, cfg);
  const hasPendingKey = Object.values(pendingKeys).some(Boolean);
  const plaintextNeeded = backend !== CODEX_BACKEND && cfg?.keyring !== true && (hasPendingKey || savedCfg?.keyring === true);
  const hasUnsavedChanges = useMemo(() => {
    if (!cfg || !savedCfg) return false;
    if (Object.values(advancedKeys).some((value) => String(value || "").trim())) return true;
    return COMPARE_FIELDS.some((field) => cfg[field] !== savedCfg[field]);
  }, [advancedKeys, cfg, savedCfg]);
  const lastVerifiedAt = useMemo(() => Object.values(connectionStates)
    .map((state) => state?.checkedAt || "")
    .filter(Boolean)
    .sort()
    .at(-1) || "", [connectionStates]);

  const chooseBackend = (value) => {
    const next = value === CODEX_BACKEND ? CODEX_BACKEND : "api";
    setCfg((current) => ({ ...current, analysis_backend: next }));
    setPlainKeyConfirmed(false); setConnectionStates({}); setMsg("");
    if (next === CODEX_BACKEND) loadCodexStatus();
  };

  const selectModel = (role, presetId) => {
    if (presetId === "__custom__") { setShowAdvanced(true); return; }
    const preset = modelsForRole(providers, role).find((item) => item.id === presetId);
    if (!preset) return;
    setAdvancedKeys((current) => ({
      ...current,
      [role.prefix]: pendingKeyAfterEndpointChange(
        cfg?.[`${role.prefix}_base_url`],
        preset.base_url,
        current[role.prefix],
      ),
    }));
    setCfg((current) => ({ ...current, [`${role.prefix}_base_url`]: preset.base_url, [`${role.prefix}_model`]: preset.model }));
    setConnectionStates((current) => ({ ...current, [role.prefix]: null })); setMsg("");
  };

  const setRoleKey = (prefix, value) => {
    setAdvancedKeys((current) => {
      const next = { ...current, [prefix]: value };
      if (shareTextKey && canShareTextKey && ["decide", "review"].includes(prefix)) next[prefix === "decide" ? "review" : "decide"] = value;
      return next;
    });
    setConnectionStates((current) => ({ ...current, [prefix]: null }));
  };

  const hostChanged = (prefix) => !!savedCfg && !!cfg?.[`${prefix}_base_url`] && !sameApiHost(savedCfg[`${prefix}_base_url`], cfg[`${prefix}_base_url`]);
  const usableKey = (prefix) => {
    if (pendingKeys[prefix]) return true;
    return hasUsableConfiguredRoleKey(cfg, savedCfg, prefix);
  };
  const keyPlaceholder = (prefix) => hostChanged(prefix) ? "服务商已改变，请填写新 API Key" : usableKey(prefix) ? "已安全配置；留空保持不变" : "粘贴 API Key";

  const testConnection = async (role) => {
    const prefix = role.prefix;
    const baseUrl = String(cfg?.[`${prefix}_base_url`] || "").trim();
    const model = String(cfg?.[`${prefix}_model`] || "").trim();
    const fail = (message) => setConnectionStates((current) => ({ ...current, [prefix]: { status: "error", message } }));
    if (!baseUrl || !model) { fail("请先填写 Base URL 和模型"); return; }
    if (!usableKey(prefix)) { fail("请先填写该服务商的 API Key"); return; }
    setConnectionStates((current) => ({ ...current, [prefix]: { status: "testing", message: "正在验证……" } }));
    try {
      const body = { role: prefix, base_url: baseUrl, model };
      if (pendingKeys[prefix]) body.api_key = pendingKeys[prefix];
      const response = await api("/api/config/test-connection", { method: "POST", body: JSON.stringify(body) });
      const result = await response.json();
      setConnectionStates((current) => ({ ...current, [prefix]: { status: "ok", message: result.message || "连接成功", checkedAt: result.checked_at || new Date().toISOString() } }));
    } catch (error) { fail(error.message); }
  };

  const save = async () => {
    const { body, missingKeyRoles } = buildSettingsPayload({ config: cfg, savedConfig: savedCfg, pendingKeys: advancedKeys, shareTextKey });
    if (missingKeyRoles.length) {
      const labels = missingKeyRoles.map((prefix) => ROLES.find((role) => role.prefix === prefix)?.label || prefix);
      setMsg(`API Host 已改变；请为${labels.join("、")}填写新服务商的 API Key`); return;
    }
    if (plaintextNeeded && !plainKeyConfirmed) { setMsg("请先确认明文保存风险，或启用 Windows 凭据管理器"); return; }
    setSaving(true); setMsg("正在安全保存……");
    try {
      const response = await api("/api/config", { method: "PUT", body: JSON.stringify(body) });
      const normalized = normalizeSettingsConfig(await response.json());
      const savedAt = new Date().toISOString();
      setCfg(normalized); setSavedCfg(normalized); setAdvancedKeys({}); setPlainKeyConfirmed(false); setLastSavedAt(savedAt);
      try { window.localStorage.setItem("latexstruct.settings.savedAt", savedAt); } catch { /* 非关键状态提示 */ }
      setMsg(backend === CODEX_BACKEND && !codexStatus?.ready ? "设置已保存；本地 Codex 尚未就绪，请按上方提示完成后刷新状态" : "设置已保存，可以开始处理项目了");
    } catch (error) { setMsg("保存失败：" + error.message); }
    finally { setSaving(false); }
  };

  const restoreDefaults = () => {
    const decide = providers.find((item) => item.id === "deepseek-v4-flash") || providers.find((item) => item.recommended && (item.roles || []).includes("decide"));
    const review = providers.find((item) => item.id === "deepseek-v4-pro") || providers.find((item) => item.recommended && (item.roles || []).includes("review"));
    const ocr = providers.find((item) => item.recommended && item.vision === true && (item.roles || []).includes("ocr"));
    setCfg((current) => ({ ...current, analysis_backend: "api", review_enabled: true, keyring: true, ...(decide && { decide_base_url: decide.base_url, decide_model: decide.model }), ...(review && { review_base_url: review.base_url, review_model: review.model }), ...(ocr && { ocr_base_url: ocr.base_url, ocr_model: ocr.model }) }));
    setAdvancedKeys({}); setShareTextKey(true); setPlainKeyConfirmed(false); setShowAdvanced(false); setConnectionStates({});
    setMsg("已恢复推荐值；确认无误后点击保存并应用");
  };

  const cancelEdits = () => {
    const restored = normalizeSettingsConfig(savedCfg || {});
    setCfg(restored); setAdvancedKeys({}); setShowKeys({}); setShareTextKey(sameApiHost(restored.decide_base_url, restored.review_base_url));
    setPlainKeyConfirmed(false); setShowAdvanced(false); setConnectionStates({}); setMsg("已撤销未保存的更改");
  };

  if (loading) return <section className="card" role="status">正在加载 AI 设置……</section>;
  if (!cfg) return <section className="card" role="alert"><h2>AI 设置加载失败</h2><p>{loadError || "暂时无法读取设置，请重试。"}</p><button type="button" className="primary" onClick={loadSettings}>重试</button></section>;

  return <div className="settings-page settings-simple">
    <header className="settings-page-header">
      <div><h1>模型与 API 设置</h1><p>先选择调用方式，再为每个功能配置模型。设置和密钥只保存在本机；处理时所选内容会发送给对应模型服务商。</p></div>
      <span className={`settings-security-pill ${backend === CODEX_BACKEND ? "codex" : cfg.keyring ? "" : "warning"}`}><Icon name="lock" size={17} />{backend === CODEX_BACKEND ? "订阅登录 / 不读取令牌" : cfg.keyring ? "本地配置 / 安全存储" : "本机明文 / 建议开启加密"}</span>
    </header>

    <section className="settings-panel settings-engine-panel">
      <div className="settings-engine-heading"><div><b>选择 AI 引擎</b><small>此选择同时用于结构判断、AI 复查和图片 / PDF OCR。</small></div><span>{backend === CODEX_BACKEND ? "使用订阅额度" : "使用服务商 API"}</span></div>
      <div className="settings-engine-grid" role="group" aria-label="选择 AI 引擎">
        <button type="button" aria-pressed={backend === "api"} className={`settings-engine-choice ${backend === "api" ? "selected" : ""}`} onClick={() => chooseBackend("api")}>
          <span className="settings-engine-choice-title"><b>模型 API</b><em>按量计费 · 灵活配置</em></span>
          <small>分别为三个功能选择兼容模型、Base URL 和 API Key；支持 DeepSeek、Qwen 与自定义接口。</small>
        </button>
        <button type="button" aria-pressed={backend === CODEX_BACKEND} className={`settings-engine-choice ${backend === CODEX_BACKEND ? "selected" : ""}`} onClick={() => chooseBackend(CODEX_BACKEND)}>
          <span className="settings-engine-choice-title"><b>Codex CLI</b><em>ChatGPT / Codex 订阅</em></span>
          <small>复用这台电脑已登录的 Codex；不读取登录令牌，也不会在失败时静默改用付费 API。</small>
        </button>
      </div>
    </section>

    {backend !== CODEX_BACKEND && <>
      <section className="settings-panel">
        <StepHeading number="1" title="为每个功能选择模型" description="文字分析和图片 OCR 可以使用不同平台；切换模型时会自动填写对应地址。" />
        <div className="settings-role-grid settings-model-grid">{ROLES.map((role) => {
          const options = modelsForRole(providers, role);
          const selected = matchingPreset(providers, role, cfg, normalizeUrl);
          const currentModel = cfg[`${role.prefix}_model`] || "";
          return <article className={`settings-role-card tone-${role.tone}`} key={role.prefix}>
            <div className="settings-role-header"><span className="settings-role-icon"><Icon name={role.icon} size={27} /></span><span><b>{role.label}</b><small>{role.help}</small><em>{providerName(selected, cfg[`${role.prefix}_base_url`])}</em></span></div>
            <label className="settings-field-label" htmlFor={`${role.prefix}-model-select`}>选择模型</label>
            <select id={`${role.prefix}-model-select`} aria-label={`${role.label}模型`} value={selected?.id || "__current__"} onChange={(event) => selectModel(role, event.target.value)}>
              {!selected && <option value="__current__">{currentModel ? `当前：${currentModel}（自定义）` : "当前未选择模型"}</option>}
              {options.map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}
              <option value="__custom__">自定义模型 ID……</option>
            </select>
            <p className="settings-role-note"><Icon name="spark" size={15} />{selected?.note || role.note}</p>
          </article>;
        })}</div>
      </section>

      <section className="settings-panel">
        <StepHeading number="2" title="填写对应 API 信息" description="密钥输入框永远不会回显真实 Key；留空会保留已经安全保存的配置。" aside="测试连接会发送一条极短请求，可能产生少量费用" />
        <div className="settings-role-grid settings-api-grid">{ROLES.map((role) => {
          const selected = matchingPreset(providers, role, cfg, normalizeUrl);
          const configured = usableKey(role.prefix);
          const connection = connectionStates[role.prefix];
          return <article className={`settings-api-card tone-${role.tone}`} key={role.prefix}>
            <div className="settings-api-card-heading"><span><b>{role.label}</b><em>{providerName(selected, cfg[`${role.prefix}_base_url`])}</em></span><span className={`settings-config-status ${configured ? "configured" : "missing"}`}><i aria-hidden="true" />{configured ? "已配置" : "待配置"}</span></div>
            <label className="settings-field-label" htmlFor={`${role.prefix}-api-key`}>API Key</label>
            <div className="settings-key-row"><div className="settings-password-field"><input id={`${role.prefix}-api-key`} type={showKeys[role.prefix] ? "text" : "password"} autoComplete="off" aria-label={`${role.label} API Key`} placeholder={keyPlaceholder(role.prefix)} value={advancedKeys[role.prefix] || ""} onChange={(event) => setRoleKey(role.prefix, event.target.value)} /><button type="button" className="settings-eye-button" aria-label={showKeys[role.prefix] ? `隐藏${role.label} API Key` : `显示${role.label} API Key`} onClick={() => setShowKeys((current) => ({ ...current, [role.prefix]: !current[role.prefix] }))}><Icon name={showKeys[role.prefix] ? "eye-off" : "eye"} size={17} /></button></div><button type="button" className="settings-test-button" disabled={connection?.status === "testing"} onClick={() => testConnection(role)}>{connection?.status === "testing" ? "验证中…" : "测试连接"}</button></div>
            <label className="settings-field-label" htmlFor={`${role.prefix}-base-url`}>Base URL <small>（可选）</small></label>
            <input id={`${role.prefix}-base-url`} aria-label={`${role.label} Base URL`} value={cfg[`${role.prefix}_base_url`] || ""} onChange={(event) => { const nextUrl = event.target.value; setAdvancedKeys((current) => ({ ...current, [role.prefix]: pendingKeyAfterEndpointEdit(savedCfg?.[`${role.prefix}_base_url`], cfg[`${role.prefix}_base_url`], nextUrl, current[role.prefix]) })); setCfg({ ...cfg, [`${role.prefix}_base_url`]: nextUrl }); setConnectionStates((current) => ({ ...current, [role.prefix]: null })); }} />
            <p className="settings-local-hint"><Icon name="shield" size={14} />{cfg.keyring ? "密钥将加密存储于本机" : "当前选择本机明文保存"}</p>
            {connection && connection.status !== "testing" && <p className={`settings-connection-result ${connection.status}`} role="status">{connection.status === "ok" ? "✓ " : "! "}{connection.message}{connection.checkedAt && <small> · {displayTime(connection.checkedAt)}</small>}</p>}
          </article>;
        })}</div>
      </section>

      <details className="settings-advanced-disclosure" open={showAdvanced} onToggle={(event) => setShowAdvanced(event.currentTarget.open)}>
        <summary><span><Icon name="sliders" size={18} /><b>高级设置：自定义模型 ID</b></span><small>{showAdvanced ? "收起" : "展开"}</small></summary>
        <div className="settings-advanced-content">
          <p>Base URL 和 API Key 可在上方按角色分别设置。只有明确知道服务商模型 ID 时，才需要修改下面内容。</p>
          <div className="settings-role-grid settings-advanced-grid">{ROLES.map((role) => <label key={role.prefix}><span>{role.label}模型 ID</span><input aria-label={`${role.label}模型 ID`} value={cfg[`${role.prefix}_model`] || ""} onChange={(event) => { setCfg({ ...cfg, [`${role.prefix}_model`]: event.target.value }); setConnectionStates((current) => ({ ...current, [role.prefix]: null })); }} /></label>)}</div>
        </div>
      </details>

      <section className="settings-panel settings-general-panel">
        <StepHeading number="3" title="通用选项" />
        <div className="settings-toggle-grid">
          <ToggleCard checked={cfg.keyring === true} icon="key" title="使用 Windows 凭据管理器" description="推荐；API Key 加密保存在本机" onChange={(event) => { setCfg({ ...cfg, keyring: event.target.checked }); setPlainKeyConfirmed(false); }} />
          <ToggleCard checked={shareTextKey && canShareTextKey} disabled={!canShareTextKey} icon="key" title="结构判断与复查共用 Key" description={canShareTextKey ? "仅在两者 API 域名相同时生效" : "两者地址不同，不能共用密钥"} onChange={(event) => { const checked = event.target.checked; setShareTextKey(checked); if (checked) { const shared = advancedKeys.decide || advancedKeys.review || ""; if (shared) setAdvancedKeys((current) => ({ ...current, decide: shared, review: shared })); } }} />
          <ToggleCard checked={cfg.review_enabled === true} icon="check" title="启用第二遍 AI 复查" description="推荐；提高结构边界判断准确性" onChange={(event) => setCfg({ ...cfg, review_enabled: event.target.checked })} />
        </div>
      </section>

      {!cfg.keyring && <div className="settings-plaintext-warning" role="alert"><Icon name="lock" size={18} /><span><b>当前密钥会以明文保存在这台电脑的本地配置中。</b><small>建议启用 Windows 凭据管理器。</small></span>{plaintextNeeded && <label><input type="checkbox" checked={plainKeyConfirmed} onChange={(event) => setPlainKeyConfirmed(event.target.checked)} />我了解本次保存会写入明文 API Key，并确认继续</label>}</div>}
    </>}

    {backend === CODEX_BACKEND && <>
      <section className="settings-panel codex-settings-card">
        <StepHeading number="1" title="确认本地 Codex 已就绪" description="只检查本机程序、版本和 ChatGPT 登录状态；状态刷新不会发送模型请求。" />
        <div className={`codex-status-card ${codexStatus?.ready === true ? "ready" : "blocked"}`} role="status" aria-live="polite">
          <div className="codex-status-heading"><div><b>{codexStatusLoading ? "正在检查 Codex……" : codexStatus?.ready === true ? "Codex 已就绪" : "Codex 尚未就绪"}</b><small>{codexStatusError || codexStatus?.message || "请刷新以检查这台电脑上的 Codex CLI。"}</small></div><button type="button" disabled={codexStatusLoading} onClick={loadCodexStatus}><Icon name="refresh" size={17} />{codexStatusLoading ? "检查中……" : "刷新状态"}</button></div>
          <dl className="codex-status-grid"><div><dt>CLI 可用</dt><dd>{statusBoolean(codexStatus?.available, codexStatusLoading)}</dd></div><div><dt>已登录</dt><dd>{statusBoolean(codexStatus?.authenticated, codexStatusLoading)}</dd></div><div><dt>可运行</dt><dd>{statusBoolean(codexStatus?.ready, codexStatusLoading)}</dd></div><div><dt>版本</dt><dd>{codexStatusLoading ? "检查中" : codexStatus?.version || "未检测到"}</dd></div></dl>
          {(codexStatus?.action || codexStatusError) && <p className="codex-action"><b>下一步：</b>{codexStatus?.action || "确认已安装并登录 Codex CLI，然后刷新状态。"}</p>}
        </div>
      </section>
      <section className="settings-panel">
        <StepHeading number="2" title="Codex 运行选项" description="分析、复查和图片/PDF OCR 都使用同一套本机 Codex 配置。" />
        <div className="codex-options settings-codex-options"><label><span>Codex 模型</span><input aria-label="Codex 模型" placeholder="留空使用 Codex 默认模型" value={cfg.codex_model || ""} onChange={(event) => setCfg({ ...cfg, codex_model: event.target.value })} /><small>这里只接受模型 ID，不接受命令路径或登录令牌。</small></label><label><span>推理强度</span><select aria-label="Codex 推理强度" value={cfg.codex_reasoning_effort || "medium"} onChange={(event) => setCfg({ ...cfg, codex_reasoning_effort: event.target.value })}><option value="low">低（更快）</option><option value="medium">中（推荐）</option><option value="high">高（更仔细）</option><option value="xhigh">超高（最慢）</option></select></label></div>
        <div className="settings-codex-review-toggle"><ToggleCard checked={cfg.review_enabled === true} icon="check" title="启用第二遍 Codex 复查" description="推荐；会额外消耗订阅额度" onChange={(event) => setCfg({ ...cfg, review_enabled: event.target.checked })} /></div>
        <p className="settings-codex-warning">文档片段和 OCR 页面图像会通过 Codex 发送到 OpenAI 云端，并消耗 ChatGPT/Codex 订阅额度。Codex 不可用时会明确报错，不会静默改用付费 API。</p>
      </section>
    </>}

    <footer className="settings-action-bar">
      <div className="settings-action-buttons"><button className="primary settings-save-button" disabled={saving} onClick={save} aria-label="保存并完成设置"><Icon name="check" size={19} />{saving ? "正在保存……" : "保存并应用设置"}</button><button type="button" onClick={restoreDefaults} disabled={saving}><Icon name="refresh" size={18} />恢复默认</button><button type="button" onClick={cancelEdits} disabled={saving || !hasUnsavedChanges}><Icon name="close" size={18} />取消</button></div>
      <div className="settings-save-status"><span className={hasUnsavedChanges ? "unsaved" : "saved"}>{hasUnsavedChanges ? "有未保存更改" : "配置已保存"}</span><span className="settings-status-times">{lastVerifiedAt && <small>上次验证：{displayTime(lastVerifiedAt)}</small>}{lastSavedAt && <small>上次保存：{displayTime(lastSavedAt)}</small>}</span><i className={hasUnsavedChanges ? "unsaved" : "saved"} aria-hidden="true" /></div>
      <span className="settings-message" role="status">{msg}</span>
    </footer>
  </div>;
}

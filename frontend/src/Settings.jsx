import { useEffect, useMemo, useState } from "react";
import { api } from "./api";
import { apiAuthority, sameApiAuthority } from "./providerUrl";

const PROVIDER_GROUPS = [
  {
    id: "qwen-cn",
    label: "阿里云百炼 Qwen",
    badge: "文字 + OCR · 推荐",
    description: "一个 API Key 同时用于结构判断、复查和图片/PDF OCR。",
  },
  {
    id: "deepseek",
    label: "DeepSeek",
    badge: "仅文字",
    description: "适合已有 DeepSeek Key 的用户；图片 OCR 需另配视觉模型。",
  },
  {
    id: "custom",
    label: "自定义兼容接口",
    badge: "高级",
    description: "仅在你明确知道 Base URL 和模型 ID 时使用。",
  },
];

const ROLES = [
  { prefix: "decide", label: "结构判断", help: "决定哪些文本应变成定理、证明或章节" },
  { prefix: "review", label: "AI 复查", help: "再次检查修改范围，复杂文档可选更强模型" },
  { prefix: "ocr", label: "图片 / PDF OCR", help: "必须选择支持图片输入的视觉模型", vision: true },
];

function normalizeUrl(value) {
  return String(value || "").trim().replace(/\/+$/, "");
}

function sameApiHost(left, right) {
  return sameApiAuthority(left, right);
}

function hasConfiguredKey(value) {
  return String(value || "").startsWith("已配置");
}

function providerOwnsUrl(providerId, value, candidates) {
  const authority = apiAuthority(value);
  return providerId !== "custom" && authority.startsWith("https://")
    && candidates.some((item) => {
      const presetAuthority = apiAuthority(item.base_url);
      return presetAuthority.startsWith("https://") && presetAuthority === authority;
    });
}

function detectProvider(cfg, providers) {
  const authority = apiAuthority(cfg?.decide_base_url);
  if (!authority.startsWith("https://")) return "custom";
  const authorityMatch = providers.find((item) => {
    const presetAuthority = apiAuthority(item.base_url);
    return presetAuthority.startsWith("https://") && presetAuthority === authority;
  });
  if (authorityMatch) return authorityMatch.provider;
  return "custom";
}

export default function Settings() {
  const [cfg, setCfg] = useState(null);
  const [savedCfg, setSavedCfg] = useState(null);
  const [providers, setProviders] = useState([]);
  const [providerId, setProviderId] = useState("qwen-cn");
  const [sharedKey, setSharedKey] = useState("");
  const [advancedKeys, setAdvancedKeys] = useState({});
  const [providerChanged, setProviderChanged] = useState(false);
  const [plainKeyConfirmed, setPlainKeyConfirmed] = useState(false);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState("");
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState("");

  const loadSettings = () => {
    setLoading(true);
    setLoadError("");
    setMsg("");
    return Promise.all([
      api("/api/config").then((r) => r.json()),
      api("/api/providers").then((r) => r.json()),
    ]).then(([config, data]) => {
      const list = data.providers || [];
      const hasAnyKey = ROLES.some(({ prefix }) =>
        hasConfiguredKey(config[prefix + "_api_key"]));
      // 新配置默认使用系统凭据；已有明文配置保持原样，避免无提示迁移。
      setCfg(!config.keyring && !hasAnyKey ? { ...config, keyring: true } : config);
      setSavedCfg(config);
      setProviders(list);
      setProviderId(detectProvider(config, list));
    }).catch(() => {
      setLoadError("无法加载 AI 设置。请确认本地服务正在运行，然后重试。");
    }).finally(() => setLoading(false));
  };

  useEffect(() => {
    loadSettings();
  }, []);

  const groupModels = useMemo(
    () => providers.filter((item) => item.provider === providerId),
    [providers, providerId],
  );

  const modelsFor = (role) => groupModels.filter((item) =>
    (item.roles || []).includes(role.prefix) && (!role.vision || item.vision));

  const chooseProvider = (id) => {
    setProviderId(id);
    setProviderChanged(id !== detectProvider(savedCfg || cfg, providers));
    setSharedKey("");
    setAdvancedKeys({});
    setPlainKeyConfirmed(false);
    if (id === "custom") return;
    const candidates = providers.filter((item) => item.provider === id);
    const recommended = candidates.find((item) => item.recommended) || candidates[0];
    if (!recommended) return;
    const review = candidates.find((item) => item.id === "deepseek-v4-pro") || recommended;
    const vision = candidates.find((item) => item.vision && item.recommended)
      || candidates.find((item) => item.vision);
    setCfg((current) => ({
      ...current,
      decide_base_url: recommended.base_url,
      decide_model: recommended.model,
      review_base_url: review.base_url,
      review_model: review.model,
      ...(vision ? { ocr_base_url: vision.base_url, ocr_model: vision.model } : {}),
    }));
  };

  const selectModel = (role, presetId) => {
    const preset = modelsFor(role).find((item) => item.id === presetId);
    if (!preset) return;
    setCfg((current) => ({
      ...current,
      [role.prefix + "_base_url"]: preset.base_url,
      [role.prefix + "_model"]: preset.model,
    }));
  };

  const save = async () => {
    const changedHostRoles = savedCfg ? ROLES.filter(({ prefix }) => {
      const nextUrl = cfg[prefix + "_base_url"] || "";
      return nextUrl && !sameApiHost(savedCfg[prefix + "_base_url"], nextUrl);
    }) : [];
    const sharedKeyRoles = new Set(ROLES.filter(({ prefix }) =>
      groupModels.some((item) => (item.roles || []).includes(prefix))
      && providerOwnsUrl(providerId, cfg[prefix + "_base_url"], groupModels))
      .map(({ prefix }) => prefix));
    const missingKeyRoles = changedHostRoles.filter(({ prefix }) =>
      !String(advancedKeys[prefix] || "").trim()
      && !(providerId !== "custom" && sharedKey.trim() && sharedKeyRoles.has(prefix)));
    if (missingKeyRoles.length) {
      setMsg(`API Host 已改变；请为${missingKeyRoles.map((role) => role.label).join("、")}填写新服务商的 API Key`);
      return;
    }
    const hasPendingKey = !!sharedKey.trim()
      || Object.values(advancedKeys).some((value) => String(value || "").trim());
    const plaintextConfirmationNeeded = !cfg.keyring
      && (hasPendingKey || !!savedCfg?.keyring);
    if (plaintextConfirmationNeeded && !plainKeyConfirmed) {
      setMsg("请先确认明文保存风险，或启用 Windows 凭据管理器");
      return;
    }
    const body = { review_enabled: !!cfg.review_enabled, keyring: !!cfg.keyring };
    for (const { prefix } of ROLES) {
      body[prefix + "_base_url"] = cfg[prefix + "_base_url"] || "";
      body[prefix + "_model"] = cfg[prefix + "_model"] || "";
      if (advancedKeys[prefix]) body[prefix + "_api_key"] = advancedKeys[prefix].trim();
    }
    if (sharedKey.trim() && providerId !== "custom") {
      for (const { prefix } of ROLES) {
        if (sharedKeyRoles.has(prefix)) body[prefix + "_api_key"] = sharedKey.trim();
      }
    }
    setSaving(true);
    setMsg("正在安全保存……");
    try {
      const response = await api("/api/config", { method: "PUT", body: JSON.stringify(body) });
      const saved = await response.json();
      setCfg(saved);
      setSavedCfg(saved);
      setProviderId(detectProvider(saved, providers));
      setSharedKey("");
      setAdvancedKeys({});
      setProviderChanged(false);
      setPlainKeyConfirmed(false);
      setMsg("设置已保存，可以开始处理项目了");
    } catch (error) {
      setMsg("保存失败：" + error.message);
    } finally {
      setSaving(false);
    }
  };

  if (loading) return <section className="card" role="status">正在加载 AI 设置……</section>;
  if (!cfg) {
    return (
      <section className="card" role="alert">
        <h2>AI 设置加载失败</h2>
        <p>{loadError || "暂时无法读取设置，请重试。"}</p>
        <button type="button" className="primary" onClick={loadSettings}>重试</button>
      </section>
    );
  }

  const providerAuthorities = new Set(groupModels
    .map((item) => apiAuthority(item.base_url))
    .filter((authority) => authority.startsWith("https://")));
  const decideAuthority = apiAuthority(cfg.decide_base_url);
  const reviewAuthority = apiAuthority(cfg.review_base_url);
  const hasReusableTextKey = providerId !== "custom"
    && !!decideAuthority
    && decideAuthority === reviewAuthority
    && providerAuthorities.has(decideAuthority)
    && (hasConfiguredKey(cfg.decide_api_key) || hasConfiguredKey(cfg.review_api_key));
  const hasPendingKey = !!sharedKey.trim()
    || Object.values(advancedKeys).some((value) => String(value || "").trim());
  const plaintextConfirmationNeeded = !cfg.keyring
    && (hasPendingKey || !!savedCfg?.keyring);

  return (
    <div className="settings-simple">
      <section className="card onboarding-card">
        <div className="step-heading">
          <span className="step-number">1</span>
          <div><h2>选择你已有 API Key 的平台</h2><p>不懂 Base URL 没关系，选择后会自动配置。</p></div>
        </div>
        <div className="provider-grid">
          {PROVIDER_GROUPS.map((group) => (
            <button
              type="button"
              key={group.id}
              aria-pressed={providerId === group.id}
              className={`provider-choice ${providerId === group.id ? "selected" : ""}`}
              onClick={() => chooseProvider(group.id)}
            >
              <b>{group.label}</b><span>{group.badge}</span><small>{group.description}</small>
            </button>
          ))}
        </div>
      </section>

      {providerId !== "custom" && (
        <section className="card onboarding-card">
          <div className="step-heading">
            <span className="step-number">2</span>
            <div><h2>填写一次 API Key</h2><p>密钥只保存在这台电脑，不会写进项目或汇报。</p></div>
          </div>
          <div className="key-entry">
            <input
              type="password"
              autoComplete="off"
              placeholder={hasReusableTextKey && !providerChanged
                ? "已配置；留空可保持不变" : "粘贴 API Key"}
              value={sharedKey}
              onChange={(event) => setSharedKey(event.target.value)}
            />
            <span className="key-safety">
              {cfg.keyring ? "🔒 将安全保存并用于该平台支持的模型" : "⚠ 尚未启用安全存储"}
            </span>
          </div>
        </section>
      )}

      {providerId !== "custom" && (
        <section className="card onboarding-card">
          <div className="step-heading">
            <span className="step-number">3</span>
            <div><h2>自由选择模型</h2><p>已给出稳妥默认值，以后可随时切换，不必重新填写 Key。</p></div>
          </div>
          <div className="model-grid">
            {ROLES.map((role) => {
              const options = modelsFor(role);
              const selectedPreset = options.find((item) =>
                normalizeUrl(item.base_url) === normalizeUrl(cfg[role.prefix + "_base_url"])
                && item.model === cfg[role.prefix + "_model"]);
              const currentModel = cfg[role.prefix + "_model"] || "";
              return (
                <label className="model-choice" key={role.prefix}>
                  <span><b>{role.label}</b><small>{role.help}</small></span>
                  {options.length ? (
                    <select
                      value={selectedPreset?.id || "__current__"}
                      onChange={(event) => selectModel(role, event.target.value)}
                    >
                      {!selectedPreset && (
                        <option value="__current__">
                          {currentModel ? `当前：${currentModel}（非预设）` : "当前未选择模型"}
                        </option>
                      )}
                      {options.map((item) => (
                        <option key={item.id} value={item.id}>{item.label}</option>
                      ))}
                    </select>
                  ) : (
                    <span className="unavailable">该平台不支持图片；需要 OCR 时请选择 Qwen</span>
                  )}
                </label>
              );
            })}
          </div>
          <label className="toggle-line">
            <input
              type="checkbox"
              checked={!!cfg.review_enabled}
              onChange={(event) => setCfg({ ...cfg, review_enabled: event.target.checked })}
            />
            启用第二遍 AI 复查（推荐，费用会略有增加）
          </label>
        </section>
      )}

      <details className="card advanced-settings" open={providerId === "custom"}>
        <summary>高级设置：自定义地址、模型 ID 或分别使用不同 Key</summary>
        <p className="hint">普通用户不需要修改这里。留空的 Key 会保持原配置不变。</p>
        {ROLES.map((role) => (
          <div className="advanced-role" key={role.prefix}>
            <b>{role.label}</b>
            <div className="row">
              <input
                aria-label={`${role.label} Base URL`}
                placeholder="Base URL"
                value={cfg[role.prefix + "_base_url"] || ""}
                onChange={(event) => setCfg({ ...cfg, [role.prefix + "_base_url"]: event.target.value })}
              />
              <input
                aria-label={`${role.label}模型 ID`}
                placeholder="模型 ID"
                value={cfg[role.prefix + "_model"] || ""}
                onChange={(event) => setCfg({ ...cfg, [role.prefix + "_model"]: event.target.value })}
              />
              <input
                type="password"
                autoComplete="off"
                aria-label={`${role.label} API Key`}
                placeholder={cfg[role.prefix + "_api_key"] ? "已配置；留空保持不变" : "API Key"}
                value={advancedKeys[role.prefix] || ""}
                onChange={(event) => setAdvancedKeys({ ...advancedKeys, [role.prefix]: event.target.value })}
              />
            </div>
          </div>
        ))}
      </details>

      <section className="card save-settings">
        <label className="toggle-line">
          <input
            type="checkbox"
            checked={!!cfg.keyring}
            onChange={(event) => {
              setCfg({ ...cfg, keyring: event.target.checked });
              setPlainKeyConfirmed(false);
            }}
          />
          使用 Windows 凭据管理器加密保存 API Key（推荐）
        </label>
        {!cfg.keyring && (
          <div className="warning" role="alert">
            当前密钥会以明文保存在这台电脑的本地配置中。建议勾选上方安全保存。
            {plaintextConfirmationNeeded && (
              <label className="plaintext-confirmation">
                <input
                  type="checkbox"
                  checked={plainKeyConfirmed}
                  onChange={(event) => setPlainKeyConfirmed(event.target.checked)}
                />
                我了解本次保存会写入明文 API Key，并确认继续
              </label>
            )}
          </div>
        )}
        <div className="row">
          <button className="primary" disabled={saving} onClick={save}>
            {saving ? "正在保存……" : "保存并完成设置"}
          </button>
          <span className="status" role="status">{msg}</span>
        </div>
      </section>
    </div>
  );
}

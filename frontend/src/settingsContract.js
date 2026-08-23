import { apiAuthority, sameApiAuthority } from "./providerUrl.js";

export const SETTINGS_ROLES = ["decide", "review", "ocr"];
export const CODEX_BACKEND = "codex_cli";

export function hasConfiguredKey(value) {
  return String(value || "").startsWith("已配置");
}

function runtimeFallbackRoles(role) {
  if (role === "decide") return ["review"];
  if (role === "review") return ["decide"];
  if (role === "ocr") return ["decide", "review"];
  return [];
}

export function hasUsableConfiguredRoleKey(config, savedConfig, role) {
  const saved = savedConfig || config || {};
  const current = config || saved;
  const currentUrl = String(
    current?.[`${role}_base_url`]
      || (role === "ocr" ? current?.decide_base_url : ""),
  );
  const savedUrl = String(
    saved?.[`${role}_base_url`]
      || (role === "ocr" ? saved?.decide_base_url : ""),
  );
  if (!sameApiAuthority(currentUrl, savedUrl)) return false;
  if (hasConfiguredKey(saved?.[`${role}_api_key`])) return true;

  // AppConfig's runtime credential fallback is deliberately HTTPS-only.
  // Mirror it here so the UI never promises a stored-key reuse that a real
  // run or the connection probe would reject.
  const targetAuthority = apiAuthority(savedUrl);
  if (!targetAuthority.startsWith("https://")) return false;
  return runtimeFallbackRoles(role).some((sourceRole) => (
    hasConfiguredKey(saved?.[`${sourceRole}_api_key`])
      && sameApiAuthority(savedUrl, saved?.[`${sourceRole}_base_url`])
  ));
}

export function normalizeSettingsConfig(config = {}) {
  return {
    ...config,
    analysis_backend: config.analysis_backend === CODEX_BACKEND ? CODEX_BACKEND : "api",
    codex_reasoning_effort: ["low", "medium", "high", "xhigh"].includes(
      config.codex_reasoning_effort,
    ) ? config.codex_reasoning_effort : "medium",
    // keyring 的显式 false 是用户选择，不能在前端静默改写。
    keyring: config.keyring === true,
  };
}

export function modelsForRole(providers, role) {
  return (providers || []).filter((item) =>
    (item.roles || []).includes(role.prefix) && (!role.vision || item.vision === true));
}

export function matchingPreset(providers, role, config, normalizeUrl) {
  return modelsForRole(providers, role).find((item) =>
    normalizeUrl(item.base_url) === normalizeUrl(config?.[`${role.prefix}_base_url`])
    && item.model === config?.[`${role.prefix}_model`]);
}

export function effectivePendingKeys(pendingKeys, shareTextKey, config) {
  const result = Object.fromEntries(SETTINGS_ROLES.map((role) => [
    role,
    String(pendingKeys?.[role] || "").trim(),
  ]));
  if (shareTextKey && sameApiAuthority(config?.decide_base_url, config?.review_base_url)) {
    const shared = result.decide || result.review;
    if (shared) {
      result.decide = shared;
      result.review = shared;
    }
  }
  return result;
}

export function pendingKeyAfterEndpointChange(previousUrl, nextUrl, pendingKey) {
  const previousAuthority = apiAuthority(previousUrl);
  const nextAuthority = apiAuthority(nextUrl);
  // 路径或模型变化不影响凭据；一旦确认跨 Host，则绝不把旧服务商的
  // 待保存 Key 静默带到新服务商。无效/尚未输完的地址交给保存校验处理。
  if (previousAuthority && nextAuthority && previousAuthority !== nextAuthority) return "";
  return String(pendingKey || "");
}

export function pendingKeyAfterEndpointEdit(
  savedUrl,
  previousUrl,
  nextUrl,
  pendingKey,
) {
  const previousAuthority = apiAuthority(previousUrl);
  const nextAuthority = apiAuthority(nextUrl);
  const savedAuthority = apiAuthority(savedUrl);
  const key = String(pendingKey || "");
  // Manual endpoint edits are stricter than a preset switch: as soon as the
  // URL becomes incomplete we can no longer prove the credential's target,
  // so require the user to re-enter it after the new endpoint is valid.
  if (!nextAuthority) return key ? "" : key;
  // A direct valid-host switch is authoritative.  When typing passed through
  // an incomplete URL, fall back to the last saved authority so a credential
  // cannot ride along merely because the immediately previous value was not
  // parseable yet.
  const credentialAuthority = previousAuthority || savedAuthority;
  if (credentialAuthority && credentialAuthority !== nextAuthority) return "";
  return key;
}

export function changedHostRoles(savedConfig, config) {
  if (!savedConfig) return [];
  return SETTINGS_ROLES.filter((role) => {
    const nextUrl = String(config?.[`${role}_base_url`] || "").trim();
    return nextUrl && !sameApiAuthority(savedConfig?.[`${role}_base_url`], nextUrl);
  });
}

export function buildSettingsPayload({ config, savedConfig, pendingKeys, shareTextKey }) {
  const backend = config?.analysis_backend === CODEX_BACKEND ? CODEX_BACKEND : "api";
  const keys = effectivePendingKeys(pendingKeys, shareTextKey, config);
  const changed = backend === "api" ? changedHostRoles(savedConfig, config) : [];
  const missingKeyRoles = changed.filter((role) => !keys[role]);
  const body = {
    review_enabled: config?.review_enabled === true,
    keyring: config?.keyring === true,
    analysis_backend: backend,
    codex_model: String(config?.codex_model || "").trim(),
    codex_reasoning_effort: config?.codex_reasoning_effort || "medium",
  };
  for (const role of SETTINGS_ROLES) {
    body[`${role}_base_url`] = String(config?.[`${role}_base_url`] || "").trim();
    body[`${role}_model`] = String(config?.[`${role}_model`] || "").trim();
    // Codex 模式保留 API 地址与模型，但绝不提交页面里尚未保存的 API Key。
    if (backend === "api" && keys[role]) body[`${role}_api_key`] = keys[role];
  }
  return { body, keys, missingKeyRoles };
}

export function sanitizeCodexStatus(status) {
  const source = status && typeof status === "object" ? status : {};
  return {
    available: source.available === true,
    authenticated: source.authenticated === true,
    ready: source.ready === true,
    version: typeof source.version === "string" ? source.version : "",
    message: typeof source.message === "string" ? source.message : "",
    action: typeof source.action === "string" ? source.action : "",
  };
}

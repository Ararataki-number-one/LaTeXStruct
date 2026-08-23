import test from "node:test";
import assert from "node:assert/strict";

import {
  buildSettingsPayload,
  effectivePendingKeys,
  hasUsableConfiguredRoleKey,
  modelsForRole,
  normalizeSettingsConfig,
  pendingKeyAfterEndpointChange,
  pendingKeyAfterEndpointEdit,
  sanitizeCodexStatus,
} from "../src/settingsContract.js";

const role = (prefix, vision = false) => ({ prefix, vision });

const config = (overrides = {}) => ({
  analysis_backend: "api",
  codex_model: "",
  codex_reasoning_effort: "medium",
  decide_base_url: "https://api.deepseek.com",
  decide_model: "deepseek-v4-flash",
  review_base_url: "https://api.deepseek.com/v1",
  review_model: "deepseek-v4-pro",
  review_enabled: true,
  ocr_base_url: "https://dashscope.aliyuncs.com/compatible-mode/v1",
  ocr_model: "qwen3.7-flash",
  keyring: false,
  ...overrides,
});

test("显式关闭安全存储不会被前端静默改回开启", () => {
  assert.equal(normalizeSettingsConfig(config()).keyring, false);
  assert.equal(normalizeSettingsConfig(config({ keyring: true })).keyring, true);
});

test("三个角色从全部平台独立筛选，OCR 只显示视觉模型", () => {
  const providers = [
    { id: "deepseek", roles: ["decide", "review"], vision: false },
    { id: "qwen-text", roles: ["decide", "review"], vision: true },
    { id: "qwen-vision", roles: ["ocr"], vision: true },
    { id: "bad-ocr", roles: ["ocr"], vision: false },
  ];
  assert.deepEqual(modelsForRole(providers, role("decide")).map((item) => item.id), ["deepseek", "qwen-text"]);
  assert.deepEqual(modelsForRole(providers, role("ocr", true)).map((item) => item.id), ["qwen-vision"]);
});

test("结构判断与复查仅在相同 API authority 时共用待保存 Key", () => {
  const sameHost = effectivePendingKeys({ decide: "ds-secret" }, true, config());
  assert.equal(sameHost.review, "ds-secret");
  assert.equal(sameHost.ocr, "");

  const differentHost = effectivePendingKeys(
    { decide: "ds-secret" },
    true,
    config({ review_base_url: "https://dashscope.aliyuncs.com/compatible-mode/v1" }),
  );
  assert.equal(differentHost.review, "");
});

test("已保存 Key 的可用状态与真实运行的同 authority 回退一致", () => {
  const saved = config({
    decide_api_key: "已配置(系统凭据)",
    review_api_key: "",
    ocr_base_url: "https://api.deepseek.com/v1",
    ocr_api_key: "",
  });
  assert.equal(hasUsableConfiguredRoleKey(saved, saved, "review"), true);
  assert.equal(hasUsableConfiguredRoleKey(saved, saved, "ocr"), true);

  const changedReview = { ...saved, review_base_url: "https://other.example/v1" };
  assert.equal(hasUsableConfiguredRoleKey(changedReview, saved, "review"), false);

  const loopback = config({
    decide_base_url: "http://127.0.0.1:11434/v1",
    review_base_url: "http://127.0.0.1:11434/v1",
    decide_api_key: "已配置",
    review_api_key: "",
  });
  assert.equal(hasUsableConfiguredRoleKey(loopback, loopback, "review"), false);
});

test("切换服务商会清除旧 Host 的待保存 Key，同 Host 改路径或模型则保留", () => {
  assert.equal(
    pendingKeyAfterEndpointChange(
      "https://api.deepseek.com/v1",
      "https://dashscope.aliyuncs.com/compatible-mode/v1",
      "deepseek-secret",
    ),
    "",
  );
  assert.equal(
    pendingKeyAfterEndpointChange(
      "https://api.deepseek.com",
      "https://api.deepseek.com/v1",
      "same-host-secret",
    ),
    "same-host-secret",
  );
});

test("手工输入跨 Host 地址即使经过无效中间态也不会携带旧 Key", () => {
  assert.equal(
    pendingKeyAfterEndpointEdit(
      "https://api.deepseek.com/v1",
      "https://api.deepseek.com/v1",
      "https://dashscope",
      "deepseek-secret",
    ),
    "",
  );
  assert.equal(
    pendingKeyAfterEndpointEdit(
      "https://api.deepseek.com/v1",
      "https://dashscope.aliyuncs",
      "https://dashscope.aliyuncs.com/compatible-mode/v1",
      "deepseek-secret",
    ),
    "",
  );
  assert.equal(
    pendingKeyAfterEndpointEdit(
      "https://api.deepseek.com/v1",
      "https://api.deepseek.com",
      "https://api.deepseek.com/v1/chat/completions",
      "deepseek-secret",
    ),
    "deepseek-secret",
  );
});

test("DeepSeek 文字 Key 不会进入 Qwen OCR 字段", () => {
  const { body } = buildSettingsPayload({
    config: config(),
    savedConfig: config(),
    pendingKeys: { decide: "ds-secret" },
    shareTextKey: true,
  });
  assert.equal(body.decide_api_key, "ds-secret");
  assert.equal(body.review_api_key, "ds-secret");
  assert.equal("ocr_api_key" in body, false);
});

test("换 API authority 时逐角色要求新 Key", () => {
  const saved = config();
  const changed = config({ ocr_base_url: "https://vision.example.invalid/v1" });
  const missing = buildSettingsPayload({ config: changed, savedConfig: saved, pendingKeys: {}, shareTextKey: true });
  assert.deepEqual(missing.missingKeyRoles, ["ocr"]);
  const supplied = buildSettingsPayload({ config: changed, savedConfig: saved, pendingKeys: { ocr: "new-secret" }, shareTextKey: true });
  assert.deepEqual(supplied.missingKeyRoles, []);
});

test("Codex 保存保留 API 模型配置但绝不携带尚未保存的 API Key", () => {
  const { body } = buildSettingsPayload({
    config: config({ analysis_backend: "codex_cli", codex_model: "gpt-5.6" }),
    savedConfig: config(),
    pendingKeys: { decide: "do-not-send", review: "do-not-send", ocr: "do-not-send" },
    shareTextKey: true,
  });
  assert.equal(body.analysis_backend, "codex_cli");
  assert.equal(body.decide_model, "deepseek-v4-flash");
  assert.equal(body.ocr_model, "qwen3.7-flash");
  assert.equal(Object.keys(body).some((key) => key.endsWith("_api_key")), false);
});

test("畸形 Codex 状态按未就绪处理并只保留公开字段", () => {
  const status = sanitizeCodexStatus({
    available: "true",
    authenticated: 1,
    ready: "false",
    version: ["bad"],
    message: "state",
    action: "login",
    local_path: "C:/secret/codex.exe",
  });
  assert.deepEqual(status, {
    available: false,
    authenticated: false,
    ready: false,
    version: "",
    message: "state",
    action: "login",
  });
});

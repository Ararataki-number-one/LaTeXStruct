import { useEffect, useState } from "react";
import { api } from "./api";

const ROLES = [
  { prefix: "decide", label: "决策模型" },
  { prefix: "review", label: "复查模型（默认最强，可改）" },
  { prefix: "ocr", label: "OCR 视觉模型（需支持图片输入）" },
];

export default function Settings() {
  const [cfg, setCfg] = useState(null);
  const [keys, setKeys] = useState({});
  const [providers, setProviders] = useState([]);
  const [presetId, setPresetId] = useState("");
  const [msg, setMsg] = useState("");

  useEffect(() => {
    api("/api/config")
      .then((r) => r.json())
      .then(setCfg)
      .catch(() => {});
    api("/api/providers")
      .then((r) => r.json())
      .then((d) => setProviders((d.providers || []).filter((p) => p.vision)))
      .catch(() => {});
  }, []);

  const save = async () => {
    const body = {};
    for (const { prefix } of ROLES) {
      body[prefix + "_base_url"] = cfg[prefix + "_base_url"] || "";
      body[prefix + "_model"] = cfg[prefix + "_model"] || "";
      if (keys[prefix]) body[prefix + "_api_key"] = keys[prefix];
    }
    body.review_enabled = !!cfg.review_enabled;
    body.keyring = !!cfg.keyring;
    try {
      await api("/api/config", { method: "PUT", body: JSON.stringify(body) });
      setKeys({});
      setMsg("已保存");
      setTimeout(() => setMsg(""), 2000);
    } catch (e) {
      setMsg("保存失败：" + e.message);
    }
  };

  if (!cfg) return <section className="card">加载中……</section>;

  return (
    <div className="settings">
      {ROLES.map(({ prefix, label }) => (
        <section className="card" key={prefix}>
          <h2>{label}</h2>
          {prefix === "ocr" && providers.length > 0 && (
            <>
              <div className="row">
                <select
                  value={presetId}
                  onChange={(e) => {
                    const id = e.target.value;
                    setPresetId(id);
                    const preset = providers.find((p) => p.id === id);
                    if (preset) {
                      setCfg({
                        ...cfg,
                        ocr_base_url: preset.base_url,
                        ocr_model: preset.model,
                      });
                    }
                  }}
                >
                  <option value="">选择已验证的视觉模型预设……</option>
                  {providers.map((p) => <option key={p.id} value={p.id}>{p.label}</option>)}
                </select>
              </div>
              {presetId && (
                <p className="hint">{providers.find((p) => p.id === presetId)?.note}</p>
              )}
            </>
          )}
          <div className="row">
            <input
              placeholder="base_url"
              value={cfg[prefix + "_base_url"] || ""}
              onChange={(e) => setCfg({ ...cfg, [prefix + "_base_url"]: e.target.value })}
            />
            <input
              placeholder="model"
              value={cfg[prefix + "_model"] || ""}
              onChange={(e) => setCfg({ ...cfg, [prefix + "_model"]: e.target.value })}
            />
            <input
              type="password"
              placeholder={cfg[prefix + "_api_key"] ? `${cfg[prefix + "_api_key"]}（留空保持不变）` : "API Key（仅存本机）"}
              value={keys[prefix] || ""}
              onChange={(e) => setKeys({ ...keys, [prefix]: e.target.value })}
            />
          </div>
          {prefix === "ocr" && (
            <p className="hint">
              推荐用 DASHSCOPE_API_KEY / LATEXSTRUCT_OCR_KEY，或开启下方系统凭据管理器。
            </p>
          )}
        </section>
      ))}
      <section className="card">
        <label>
          <input
            type="checkbox"
            checked={!!cfg.review_enabled}
            onChange={(e) => setCfg({ ...cfg, review_enabled: e.target.checked })}
          />
          启用 AI 复查
        </label>
        <label>
          <input
            type="checkbox"
            checked={!!cfg.keyring}
            onChange={(e) => setCfg({ ...cfg, keyring: e.target.checked })}
          />
          使用系统凭据管理器保存密钥（Windows 凭据管理器，配置文件不再存明文）
        </label>
        {!cfg.keyring && (
          <p className="warning">
            当前未启用系统凭据管理器：新输入的密钥会保存在本机配置文件中。Windows 用户建议开启；
            如果系统凭据写入失败，保存会停止并显示原因，不会静默改存明文。
          </p>
        )}
        <div className="row">
          <button className="primary" onClick={save}>保存设置</button>
          <span className="status">{msg}</span>
        </div>
      </section>
    </div>
  );
}

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
  const [msg, setMsg] = useState("");

  useEffect(() => {
    api("/api/config")
      .then((r) => r.json())
      .then(setCfg)
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
    await api("/api/config", { method: "PUT", body: JSON.stringify(body) });
    setMsg("已保存");
    setTimeout(() => setMsg(""), 2000);
  };

  if (!cfg) return <section className="card">加载中……</section>;

  return (
    <div className="settings">
      {ROLES.map(({ prefix, label }) => (
        <section className="card" key={prefix}>
          <h2>{label}</h2>
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
              placeholder={cfg[prefix + "_api_key"] ? "已配置（留空保持不变）" : "API Key（仅存本机）"}
              value={keys[prefix] || ""}
              onChange={(e) => setKeys({ ...keys, [prefix]: e.target.value })}
            />
          </div>
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
        <div className="row">
          <button className="primary" onClick={save}>保存设置</button>
          <span className="status">{msg}</span>
        </div>
      </section>
    </div>
  );
}

const BASE = "";

async function errorMessage(res) {
  try {
    const body = await res.json();
    const detail = typeof body.detail === "string" ? body.detail : res.statusText;
    return body.action ? `${detail}；${body.action}` : detail;
  } catch {
    return res.statusText || `请求失败（HTTP ${res.status}）`;
  }
}

async function request(path, opts = {}) {
  try {
    return await fetch(BASE + path, opts);
  } catch {
    throw new Error("无法连接本地服务，请稍后重试或重新启动 LaTeXStruct");
  }
}

export async function api(path, opts = {}) {
  const res = await request(path, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  if (!res.ok) {
    throw new Error(await errorMessage(res));
  }
  return res;
}

export async function apiText(path) {
  const res = await request(path);
  if (!res.ok) throw new Error(await errorMessage(res));
  return res.text();
}

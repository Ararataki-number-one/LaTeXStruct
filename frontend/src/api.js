const BASE = "";

export async function api(path, opts = {}) {
  const res = await fetch(BASE + path, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  if (!res.ok) {
    let msg = res.statusText;
    try {
      msg = (await res.json()).detail || msg;
    } catch {
      /* ignore */
    }
    throw new Error(msg);
  }
  return res;
}

export async function apiText(path) {
  const res = await fetch(BASE + path);
  if (!res.ok) throw new Error(res.statusText);
  return res.text();
}

/* LaTeXStruct 前端逻辑（原生 JS，无构建步骤） */
"use strict";

let currentPid = null;

const $ = (id) => document.getElementById(id);

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  if (!res.ok) {
    let msg = res.statusText;
    try { msg = (await res.json()).detail || msg; } catch (_) {}
    throw new Error(msg);
  }
  return res;
}

/* ---------- 页签 ---------- */
document.querySelectorAll("nav button").forEach((b) =>
  b.addEventListener("click", () => {
    document.querySelectorAll("nav button").forEach((x) => x.classList.remove("active"));
    document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
    b.classList.add("active");
    $("tab-" + b.dataset.tab).classList.add("active");
    if (b.dataset.tab === "projects") loadProjects();
  })
);

/* ---------- 项目 ---------- */
async function loadProjects() {
  const data = await (await api("/api/projects")).json();
  const tbody = document.querySelector("#project-table tbody");
  tbody.innerHTML = "";
  for (const p of data) {
    const tr = document.createElement("tr");
    tr.innerHTML =
      `<td>${esc(p.name)}</td><td>${esc(p.mode)}</td><td>${esc(p.created)}</td>` +
      `<td>${p.has_result ? "已处理" : "未处理"}</td>` +
      `<td><button data-open="${p.id}">打开</button> <button data-del="${p.id}">删除</button></td>`;
    tbody.appendChild(tr);
  }
  tbody.querySelectorAll("[data-open]").forEach((b) =>
    b.addEventListener("click", () => openProject(b.dataset.open))
  );
  tbody.querySelectorAll("[data-del]").forEach((b) =>
    b.addEventListener("click", async () => {
      if (!confirm("删除该项目？")) return;
      await api("/api/projects/" + b.dataset.del, { method: "DELETE" });
      loadProjects();
    })
  );
}

$("p-file").addEventListener("change", async (e) => {
  const f = e.target.files[0];
  if (!f) return;
  $("p-text").value = await f.text();
});

$("btn-create").addEventListener("click", async () => {
  const text = $("p-text").value;
  if (!text.trim()) return alert("请粘贴内容或选择文件");
  $("btn-create").disabled = true;
  try {
    const r = await api("/api/projects", {
      method: "POST",
      body: JSON.stringify({
        text,
        name: $("p-name").value,
        mode: $("p-mode").value,
        template: $("p-template").checked ? "elegantbook" : "",
      }),
    });
    const { id } = await r.json();
    currentPid = id;
    $("btn-create").disabled = false;
    await openProject(id);
    document.querySelector('nav button[data-tab="review"]').click();
  } catch (err) {
    $("btn-create").disabled = false;
    alert("创建失败：" + err.message);
  }
});

async function openProject(pid) {
  currentPid = pid;
  const p = await (await api("/api/projects/" + pid)).json();
  $("review-title").textContent = `项目：${p.name}（${p.mode} 模式）`;
  $("process-status").textContent = p.has_result ? "已有处理结果" : "尚未处理";
  try {
    const rep = await api("/api/projects/" + pid + "/report");
    $("report-view").textContent = await rep.text();
    const d = await api("/api/projects/" + pid + "/diff");
    renderDiff(await d.json());
    await loadDecisions();
  } catch (_) {
    $("report-view").textContent = "尚未处理。点击「运行结构化整理」。";
    $("diff-view").innerHTML = "";
    $("decision-list").innerHTML = "";
  }
}

/* ---------- 决策审阅 ---------- */
let decisionsCache = [];
let currentFilter = "all";

async function loadDecisions() {
  if (!currentPid) return;
  try {
    const d = await (await api(`/api/projects/${currentPid}/decisions`)).json();
    decisionsCache = d.items || [];
    renderDecisionList();
  } catch (_) {
    decisionsCache = [];
  }
}

function renderDecisionList() {
  const el = $("decision-list");
  el.innerHTML = "";
  for (const item of decisionsCache) {
    if (currentFilter === "proof" && item.env !== "proof" && item.kind !== "proof") continue;
    if (currentFilter === "ambiguous" && item.status !== "ambiguous") continue;
    if (currentFilter === "high" && item.confidence < 0.9) continue;
    const li = document.createElement("li");
    li.className = "d-status-" + item.status;
    li.dataset.cid = item.candidate_id;
    const kind = item.kind === "theorem-like" ? item.env : item.kind;
    li.innerHTML =
      `<span class="d-kind">${esc(kind || "?")}</span>` +
      `<span class="d-title">${esc(item.title)}</span>` +
      `<span class="d-section">${esc(item.section || "§ " + item.line)} · L${item.line} · ` +
      `${Math.round((item.confidence || 0) * 100)}% · ${esc(item.status)}</span>`;
    li.addEventListener("click", () => showDecision(item, li));
    el.appendChild(li);
  }
}

function showDecision(item, li) {
  document.querySelectorAll("#decision-list li").forEach((x) => x.classList.remove("active"));
  li.classList.add("active");
  $("dd-title").textContent = `[${item.kind === "theorem-like" ? item.env : item.kind}] ${item.title}`;
  $("dd-meta").textContent =
    `${item.section || "§ " + item.line} · 第 ${item.line} 行 · ` +
    `置信度 ${Math.round((item.confidence || 0) * 100)}% · 来源 ${item.source} · 状态 ${item.status}\n原因：${item.reason || "—"}`;
  $("dd-actions").style.display = item.status === "applied" ? "flex" : "none";
  $("dd-reject").dataset.cid = item.candidate_id;
  // 跳转 diff 对应行
  const row = document.querySelector(`.diff-row[data-old="${item.line}"]`);
  if (row) row.scrollIntoView({ behavior: "smooth", block: "center" });
}

document.querySelectorAll(".filter-btn").forEach((b) =>
  b.addEventListener("click", () => {
    document.querySelectorAll(".filter-btn").forEach((x) => x.classList.remove("primary"));
    b.classList.add("primary");
    currentFilter = b.dataset.filter;
    renderDecisionList();
  })
);

$("dd-reject").addEventListener("click", async () => {
  const cid = $("dd-reject").dataset.cid;
  if (!currentPid || !cid) return;
  if (!confirm(`拒绝修改 ${cid}？该处将恢复原文，其余修改不受影响。`)) return;
  $("process-status").textContent = "重新整理中……";
  try {
    await api(`/api/projects/${currentPid}/decisions/${cid}/reject`, { method: "POST" });
    await openProject(currentPid);
    $("process-status").textContent = "已拒绝该修改并重新校验";
  } catch (e) {
    $("process-status").textContent = "拒绝失败：" + e.message;
  }
});

function renderDiff(data) {
  const el = $("diff-view");
  el.innerHTML = "";
  for (const row of data.rows) {
    const div = document.createElement("div");
    div.className = "diff-row " + row.type;
    if (row.old != null) div.dataset.old = row.old;
    if (row.new != null) div.dataset.new = row.new;
    const oldSide = row.type === "ins" ? "" : `<span class="num">${row.old ?? ""}</span>${esc(row.text)}`;
    const newSide = row.type === "del" ? "" : `<span class="num">${row.new ?? ""}</span>${esc(row.text)}`;
    div.innerHTML = `<div class="side old-side">${oldSide}</div><div class="side new-side">${newSide}</div>`;
    el.appendChild(div);
  }
  const applied = (data.applied || []).length;
  const amb = (data.ambiguous || []).length;
  $("diff-legend").innerHTML =
    `<span class="lg ins">新增行</span><span class="lg del">删除行</span>` +
    `<span class="status">补丁 ${applied} 项 · 歧义 ${amb} 项 · 内容不变校验：` +
    `${data.verification && data.verification.content_invariant ? "通过" : "失败（已回退）"}</span>`;
}

/* ---------- 处理 ---------- */
$("btn-process").addEventListener("click", async () => {
  if (!currentPid) return alert("请先在项目页选择项目");
  $("btn-process").disabled = true;
  $("process-status").textContent = "处理中……（长文档可能耗时，请耐心等待）";
  try {
    const r = await api("/api/projects/" + currentPid + "/process", { method: "POST" });
    const s = await r.json();
    $("process-status").textContent =
      `完成：应用补丁 ${s.applied}，拒绝 ${s.rejected}，歧义 ${s.ambiguous}` +
      (s.degraded ? "（AI 不可用，已降级规则模式）" : "");
    await openProject(currentPid);
  } catch (err) {
    $("process-status").textContent = "失败：" + err.message;
  } finally {
    $("btn-process").disabled = false;
  }
});

/* ---------- 导出 ---------- */
$("btn-download").addEventListener("click", async () => {
  if (!currentPid) return alert("请先选择项目");
  const a = document.createElement("a");
  a.href = "/api/projects/" + currentPid + "/export";
  a.download = "result.tex";
  a.click();
});

$("btn-report").addEventListener("click", async () => {
  if (!currentPid) return alert("请先选择项目");
  const rep = await (await api("/api/projects/" + currentPid + "/report")).text();
  const blob = new Blob([rep], { type: "text/markdown" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "report.md";
  a.click();
  URL.revokeObjectURL(a.href);
});

/* ---------- OCR ---------- */
let ocrJobId = null;
let ocrTimer = null;

$("btn-ocr-start").addEventListener("click", async () => {
  const f = $("ocr-file").files[0];
  if (!f) return alert("请选择 PDF 或图片文件");
  const fd = new FormData();
  fd.append("file", f);
  fd.append("pages", $("ocr-pages").value);
  fd.append("dpi", $("ocr-dpi").value);
  fd.append("model", $("ocr-model").value);
  $("btn-ocr-start").disabled = true;
  $("ocr-status").textContent = "上传中……";
  try {
    const r = await fetch("/api/ocr/jobs", { method: "POST", body: fd });
    if (!r.ok) throw new Error((await r.json()).detail || r.statusText);
    ocrJobId = (await r.json()).id;
    $("ocr-status").textContent = "任务已启动，转写中……";
    pollOcr();
  } catch (e) {
    $("ocr-status").textContent = "失败：" + e.message;
    $("btn-ocr-start").disabled = false;
  }
});

async function pollOcr() {
  if (!ocrJobId) return;
  try {
    const j = await (await api("/api/ocr/jobs/" + ocrJobId)).json();
    if (j.status === "running") {
      $("ocr-status").textContent =
        `转写中：第 ${j.page || 0}/${j.total} 页（${Math.round((j.progress || 0) * 100)}%）`;
      ocrTimer = setTimeout(pollOcr, 2000);
    } else if (j.status === "done") {
      $("ocr-status").textContent =
        `完成：${j.total} 页，错误 ${(j.errors || []).length}，tokens ${(j.usage || {}).total_tokens || 0}`;
      $("btn-ocr-start").disabled = false;
      const tex = await (await api(`/api/ocr/jobs/${ocrJobId}/result`)).text();
      $("ocr-preview").textContent = tex.slice(0, 3000);
      $("btn-ocr-import").disabled = false;
    } else {
      $("ocr-status").textContent = "失败：" + (j.error || "未知错误");
      $("btn-ocr-start").disabled = false;
    }
  } catch (e) {
    ocrTimer = setTimeout(pollOcr, 3000);
  }
}

$("btn-ocr-import").addEventListener("click", async () => {
  if (!ocrJobId) return;
  const r = await api(`/api/ocr/jobs/${ocrJobId}/import`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({}),
  });
  const { id } = await r.json();
  currentPid = id;
  await openProject(id);
  document.querySelector('nav button[data-tab="review"]').click();
});

/* ---------- 设置 ---------- */
async function loadConfig() {
  const cfg = await (await api("/api/config")).json();
  $("s-decide-url").value = cfg.decide_base_url || "";
  $("s-decide-model").value = cfg.decide_model || "";
  $("s-decide-key").value = "";
  $("s-decide-key").placeholder = cfg.decide_api_key ? "已配置（留空保持不变）" : "API Key（仅存本机）";
  $("s-review-url").value = cfg.review_base_url || "";
  $("s-review-model").value = cfg.review_model || "";
  $("s-review-key").value = "";
  $("s-review-key").placeholder = cfg.review_api_key ? "已配置（留空保持不变）" : "API Key（仅存本机）";
  $("s-review-enabled").checked = !!cfg.review_enabled;
  $("s-ocr-url").value = cfg.ocr_base_url || "";
  $("s-ocr-model").value = cfg.ocr_model || "";
  $("s-ocr-key").value = "";
  $("s-ocr-key").placeholder = cfg.ocr_api_key ? "已配置（留空保持不变）" : "API Key（仅存本机，留空用决策 Key）";
}

$("btn-save-config").addEventListener("click", async () => {
  const body = {
    decide_base_url: $("s-decide-url").value,
    decide_model: $("s-decide-model").value,
    review_base_url: $("s-review-url").value,
    review_model: $("s-review-model").value,
    review_enabled: $("s-review-enabled").checked,
    ocr_base_url: $("s-ocr-url").value,
    ocr_model: $("s-ocr-model").value,
  };
  if ($("s-decide-key").value) body.decide_api_key = $("s-decide-key").value;
  if ($("s-review-key").value) body.review_api_key = $("s-review-key").value;
  if ($("s-ocr-key").value) body.ocr_api_key = $("s-ocr-key").value;
  await api("/api/config", { method: "PUT", body: JSON.stringify(body) });
  $("config-status").textContent = "已保存";
  setTimeout(() => ($("config-status").textContent = ""), 2000);
});

function esc(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

/* ---------- 版本与更新 ---------- */
async function checkUpdates(silent) {
  try {
    const r = await api("/api/update/check");
    const info = await r.json();
    $("app-version").textContent = "v" + info.current;
    if (info.available) {
      $("update-text").textContent =
        `发现新版本 v${info.latest}（当前 v${info.current}）${info.notes ? "：" + info.notes.slice(0, 120) : ""}`;
      $("update-banner").style.display = "flex";
    } else if (!silent) {
      $("app-version").textContent += info.error ? `（${info.error}）` : "（已是最新）";
    }
  } catch (e) {
    if (!silent) $("app-version").textContent += "（检查更新失败）";
  }
}

$("btn-update-now").addEventListener("click", async () => {
  $("btn-update-now").disabled = true;
  $("update-text").textContent = "正在下载并启动安装器……";
  try {
    await api("/api/update/install", { method: "POST" });
    $("update-text").textContent = "安装器已启动，安装完成后应用将自动重启。";
  } catch (e) {
    $("update-text").textContent = "更新失败：" + e.message;
    $("btn-update-now").disabled = false;
  }
});

$("btn-update-dismiss").addEventListener("click", () => {
  $("update-banner").style.display = "none";
});

loadProjects();
loadConfig();
checkUpdates(true);

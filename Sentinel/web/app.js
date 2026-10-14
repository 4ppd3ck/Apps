// Sentinel dashboard — vanilla JS, SSE live updates, no build step.
"use strict";

const $ = (s) => document.querySelector(s);
const SEVS = ["critical", "high", "medium", "low", "info"];
let status = null;
let alerts = [];
let alertFilter = { sev: "", hideAcked: true };
let seenIds = new Set();

// theme ------------------------------------------------------------------
(() => {
  let t = localStorage.getItem("sentinel.theme");
  if (!t) t = matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  document.documentElement.dataset.theme = t;
  $("#themeBtn").textContent = t === "dark" ? "☀️" : "🌙";
})();
$("#themeBtn").addEventListener("click", () => {
  const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = next;
  localStorage.setItem("sentinel.theme", next);
  $("#themeBtn").textContent = next === "dark" ? "☀️" : "🌙";
});

// helpers ----------------------------------------------------------------
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const timeOf = (ts) => {
  if (!ts) return "—";
  const d = new Date(ts * 1000);
  const today = new Date().toDateString() === d.toDateString();
  return today ? d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })
    : d.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
};

async function api(path, opts) {
  const r = await fetch(path, opts);
  if (!r.ok) throw new Error(path + " -> " + r.status);
  return r.json();
}

// beeper -----------------------------------------------------------------
let audioCtx = null;
function beep(sev) {
  if (sev !== "critical" && sev !== "high") return;
  try {
    audioCtx = audioCtx || new (window.AudioContext || window.webkitAudioContext)();
    const o = audioCtx.createOscillator(), g = audioCtx.createGain();
    o.type = "sine"; o.frequency.value = sev === "critical" ? 880 : 660;
    g.gain.setValueAtTime(0.12, audioCtx.currentTime);
    g.gain.exponentialRampToValueAtTime(0.0001, audioCtx.currentTime + 0.7);
    o.connect(g).connect(audioCtx.destination);
    o.start(); o.stop(audioCtx.currentTime + 0.7);
  } catch { /* autoplay restrictions */ }
}

// rendering ----------------------------------------------------------------
function renderTiles() {
  const by = (status.alerts && status.alerts.by_severity) || {};
  const unacked = status.alerts ? status.alerts.unacked : 0;
  $("#tiles").innerHTML = SEVS.map((s) => {
    const n = by[s] || 0;
    return `<div class="tile ${s}" data-sev="${s}">
      <h3>${s}</h3><div class="n">${n}</div></div>`;
  }).join("") + `<div class="tile info" data-sev="">
      <h3>unacked</h3><div class="n">${unacked}</div></div>`;
  document.querySelectorAll(".tile").forEach((t) =>
    t.addEventListener("click", () => {
      const sev = t.dataset.sev;
      $("#sevFilter").value = ["critical", "high", "medium", "low"].includes(sev) ? sev : "";
      alertFilter.sev = $("#sevFilter").value;
      renderAlerts();
    }));
}

function renderStatus() {
  $("#platform").textContent = `${status.os}/${status.arch} · uptime ${Math.floor(status.uptime_s / 60)}m`;
  const mon = status.monitor || {};
  const m = $("#monitorState");
  m.textContent = `monitor: ${mon.up ? "connected" : "offline"}`;
  m.className = "pill " + (mon.up ? "on" : "off");
  $("#scanState").textContent = `scans every ${status.tick_s || "?"}s`;
  renderChecks();
  renderFindings();
  renderMonitor();
}

function renderChecks() {
  $("#checkList").innerHTML = (status.checks || []).map((c) => `
    <div class="check">
      <span class="dot ${c.status}" title="${esc(c.status)}"></span>
      <div><span class="name">${esc(c.name)}</span>
        ${c.status === "unavailable" ? `<div class="desc">${esc(c.reason || "")}</div>` : `<div class="desc">${esc(c.description)}</div>`}
      </div>
      <span class="ms">${c.last_ms != null ? c.last_ms + "ms" : ""}</span>
    </div>`).join("");
}

function renderFindings() {
  const scan = status.scan || {};
  const rows = [];
  for (const [check, fs] of Object.entries(scan)) {
    for (const f of fs) rows.push(f);
  }
  if (!rows.length) {
    $("#findingList").innerHTML = `<p class="muted">Nothing on this scan — quiet machine.</p>`;
    return;
  }
  rows.sort((a, b) => SEVS.indexOf(a.severity) - SEVS.indexOf(b.severity));
  $("#findingList").innerHTML = rows.slice(0, 40).map((f) => `
    <div class="finding">
      <span class="tag sev-${esc(f.severity)}">${esc(f.severity)}</span><span class="tag">${esc(f.check)}</span>
      <span class="t">${esc(f.title)}</span>
      <div class="d">${esc(f.detail)}</div>
    </div>`).join("");
}

function renderMonitor() {
  const m = status.monitor || {};
  $("#monitorPanel").innerHTML = `
    <div class="row"><span class="k">URL</span><span class="mono">${esc(m.url || "")}</span></div>
    <div class="row"><span class="k">state</span><span>${m.up ? "🟢 connected" : "🔴 " + esc(m.last_error || "offline")}</span></div>
    <div class="row"><span class="k">recent events</span><span>${m.events ?? 0}</span></div>
    <div class="row"><span class="k">connections</span><span>${m.connections ?? 0}</span></div>
    <div class="row"><span class="k">last poll</span><span>${timeOf(m.last_poll)}</span></div>`;
}

function renderAlerts() {
  const list = alerts.filter((a) =>
    (!alertFilter.sev || SEVS.indexOf(a.severity) <= SEVS.indexOf(alertFilter.sev)) &&
    (!alertFilter.hideAcked || !a.acked));
  if (!list.length) {
    $("#alertList").innerHTML = `<p class="muted">No alerts${alertFilter.sev ? " at this severity" : ""} — Sentinel is watching.</p>`;
    return;
  }
  $("#alertList").innerHTML = list.map((a) => `
    <div class="alert ${esc(a.severity)} ${a.acked ? "acked" : ""}" data-id="${a.id}">
      <button class="btn ghost small ack" data-id="${a.id}">${a.acked ? "✓" : "ack"}</button>
      <button class="btn ghost small del" data-id="${a.id}" title="delete this alert">🗑</button>
      <div class="row1">
        <span class="sev">${esc(a.severity)}</span>
        <span class="title">${esc(a.title)}</span>
      </div>
      <div class="detail">${esc(a.detail)}</div>
      <div class="meta">
        <span>#${a.id}</span><span>${esc(a.check)}</span>
        <span>×${a.count}</span><span>${timeOf(a.first_ts)} → ${timeOf(a.ts)}</span>
      </div>
      ${a.evidence ? `<pre class="evid">${esc(JSON.stringify(a.evidence, null, 1))}</pre>` : ""}
    </div>`).join("");
  document.querySelectorAll(".alert button.ack").forEach((b) =>
    b.addEventListener("click", async () => {
      await api("/api/ack", { method: "POST", body: JSON.stringify({ id: Number(b.dataset.id) }) });
      loadAlerts();
    }));
  document.querySelectorAll(".alert button.del").forEach((b) =>
    b.addEventListener("click", async () => {
      await api("/api/alerts", { method: "DELETE", body: JSON.stringify({ id: Number(b.dataset.id) }) });
      loadAlerts();
    }));
}

// data loading -------------------------------------------------------------
async function loadStatus() {
  status = await api("/api/status");
  renderTiles();
  renderStatus();
}

async function loadAlerts() {
  const d = await api("/api/alerts");
  alerts = d.alerts || [];
  renderAlerts();
}

// events --------------------------------------------------------------------
$("#sevFilter").addEventListener("change", (e) => { alertFilter.sev = e.target.value; renderAlerts(); });
$("#hideAcked").addEventListener("change", (e) => { alertFilter.hideAcked = e.target.checked; renderAlerts(); });
$("#scanBtn").addEventListener("click", async () => {
  await api("/api/scan", { method: "POST" });
  setTimeout(() => { loadStatus(); loadAlerts(); }, 1200);
});
$("#ackAll").addEventListener("click", async () => {
  await api("/api/ack", { method: "POST", body: JSON.stringify({ all: true }) });
  loadAlerts();
});
$("#delAcked").addEventListener("click", async () => {
  if (!confirm("Delete every acked alert? This cannot be undone (export first if needed).")) return;
  await api("/api/alerts", { method: "DELETE", body: JSON.stringify({ allAcked: true }) });
  loadStatus();
  loadAlerts();
});
$("#exportBtn").addEventListener("click", () => location.href = "/api/export");
$("#resetBase").addEventListener("click", async () => {
  if (!confirm("Forget all learned baselines (gateway, DNS, endpoints, persistence, TCC grants)?")) return;
  await api("/api/baseline", { method: "POST" });
  loadStatus();
});
$("#editRules").addEventListener("click", async () => {
  const rules = await api("/api/rules");
  $("#rulesText").value = JSON.stringify(rules, null, 2);
  $("#rulesDlg").showModal();
});
$("#rulesClose").addEventListener("click", () => $("#rulesDlg").close());
$("#rulesSave").addEventListener("click", async () => {
  try {
    const parsed = JSON.parse($("#rulesText").value);
    await api("/api/rules", { method: "POST", body: JSON.stringify(parsed) });
    $("#rulesDlg").close();
    loadStatus();
  } catch (e) { alert("Invalid JSON: " + e.message); }
});

// SSE -----------------------------------------------------------------------
function connectSSE() {
  const es = new EventSource("/api/stream");
  es.onmessage = (ev) => {
    let msg;
    try { msg = JSON.parse(ev.data); } catch { return; }
    if (msg.type === "alert") {
      if (!seenIds.has(msg.alert.id)) {
        seenIds.add(msg.alert.id);
        if (msg.alert.count === 1) beep(msg.alert.severity);
      }
      loadAlerts();
      loadStatus();
    } else if (msg.type === "scan" || msg.type === "ack") {
      loadStatus();
      if (msg.type === "ack") loadAlerts();
    }
  };
  es.onerror = () => { es.close(); setTimeout(connectSSE, 4000); };
}

// boot ----------------------------------------------------------------------
(async () => {
  await loadStatus();
  await loadAlerts();
  connectSSE();
  setInterval(loadStatus, 30000);
})().catch((e) => {
  document.body.innerHTML = `<p style="padding:40px">Sentinel API unreachable: ${esc(e.message)}</p>`;
});

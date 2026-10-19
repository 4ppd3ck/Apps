/* AppScope Monitor dashboard */
"use strict";

const $ = (id) => document.getElementById(id);
const state = {
  paused: false,
  lastPrivacy: null,   // {ts, text} for the camera/mic card
  eventCount: 0,
  histMinutes: 60,     // default/global history window
  panelMinutes: {},    // per event panel override
  dirConns: "",        // "" | "in" | "out"  (live connections filter)
  appConns: "",        // app-name filter for live connections
  dirNetwork: "",      // same, for network events
  filters: {},         // per event table: {app, kind, user}
};

const RANGE_OPTS = [[5, "5 min"], [15, "15 min"], [30, "30 min"],
                    [60, "1 hr"], [720, "12 hrs"], [1440, "24 hrs"]];
const RANGE_LABELS = Object.fromEntries(RANGE_OPTS);

// app / kind / user dropdowns for the event tables (columns are consistent:
// 0 time, 1 kind, 2 app, 3 user)
const FILTER_DEFS = [
  { key: "app", col: 2, label: "All apps" },
  { key: "kind", col: 1, label: "All kinds" },
  { key: "user", col: 3, label: "All users" },
];
const FILTER_TABLES = ["privacy", "file", "network", "system"];

function panelMinutes(t) {
  return state.panelMinutes[t] || state.histMinutes;
}

function initFilterSelects() {
  for (const t of FILTER_TABLES) {
    state.filters[t] = { app: "", kind: "", user: "" };
    const holder = $("fc-" + t);
    if (!holder) continue;
    const hist = document.createElement("select");
    hist.className = "filter";
    hist.id = `hist-${t}`;
    hist.title = "history range for this panel";
    hist.innerHTML = RANGE_OPTS.map(([v, l]) =>
      `<option value="${v}"${v === panelMinutes(t) ? " selected" : ""}>${l}</option>`).join("");
    hist.addEventListener("change", () => {
      state.panelMinutes[t] = parseInt(hist.value, 10) || 60;
      loadPanel(t);
    });
    holder.prepend(hist);
    for (const def of FILTER_DEFS.slice().reverse()) {
      const sel = document.createElement("select");
      sel.className = "filter";
      sel.id = `f-${t}-${def.key}`;
      sel.title = `filter by ${def.key}`;
      sel.innerHTML = `<option value="">${def.label}</option>`;
      sel.addEventListener("change", () => {
        state.filters[t][def.key] = sel.value;
        for (const tr of $(`tbl-${t}`).tBodies[0].rows) applyFilter(`tbl-${t}`, tr);
      });
      holder.prepend(sel);
    }
  }
}

function refreshFilterOptions() {
  for (const t of FILTER_TABLES) {
    const tbody = $(`tbl-${t}`)?.tBodies[0];
    if (!tbody) continue;
    for (const def of FILTER_DEFS) {
      const sel = $(`f-${t}-${def.key}`);
      if (!sel) continue;
      const values = new Set();
      for (const tr of tbody.rows) {
        const v = tr.children[def.col] ? tr.children[def.col].textContent.trim() : "";
        if (v && v !== "–" && v !== "-") values.add(v);
        if (values.size > 200) break;
      }
      const current = state.filters[t][def.key];
      if (current) values.add(current);
      const sorted = [...values].sort((a, b) => a.localeCompare(b));
      sel.innerHTML = `<option value="">${def.label}</option>` +
        sorted.map((v) =>
          `<option value="${esc(v)}"${v === current ? " selected" : ""}>${esc(v)}</option>`).join("");
    }
  }
}

/* ------------------------------------------------------------- format -- */
function fmtBytes(n) {
  if (n == null || isNaN(n)) return "–";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  n = Number(n);
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n.toFixed(0) : n.toFixed(1)) + " " + units[i];
}
function fmtRate(n) { return fmtBytes(n) + "/s"; }
function fmtTime(ts) {
  const d = new Date(ts * 1000);
  const time = d.toLocaleTimeString(undefined, { hour12: false });
  if (d.toDateString() === new Date().toDateString()) return time;
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric" })
    + " " + time;
}
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

/* ------------------------------------------------------------- tables -- */
const MAX_ROWS = 300;
function addRow(tblId, cells) {
  const tbody = $(tblId).tBodies[0];
  const tr = document.createElement("tr");
  tr.innerHTML = cells.map((c) => `<td${c.cls ? ` class="${c.cls}"` : ""}>${c.html}</td>`).join("");
  tbody.prepend(tr);
  while (tbody.rows.length > MAX_ROWS) tbody.deleteRow(-1);
  applyFilter(tblId, tr);
}
function badge(category, kind) {
  const cls = { privacy: "b-priv", file: "b-file", network: "b-net",
                devices: "b-dev", logins: "b-login", appfocus: "b-sys",
                system: "b-sys" }[category] || "b-sys";
  return `<span class="badge ${cls}">${esc(kind)}</span>`;
}
function rowDirection(tblId, tr) {
  // returns "in" | "out" | null depending on the table's direction column
  if (tblId === "tbl-conns") {
    return tr.children[2] && tr.children[2].textContent.includes("in") ? "in"
      : "out";
  }
  if (tblId === "tbl-network") {
    const txt = tr.children[5] ? tr.children[5].textContent : "";
    if (txt.includes("inbound")) return "in";
    if (txt.includes("outbound")) return "out";
  }
  return null;
}
function applyFilter(tblId, tr) {
  const q = $("filter-" + tblId.replace("tbl-", "")).value.toLowerCase();
  let ok = !q || tr.textContent.toLowerCase().includes(q);
  if (ok) {
    const dir = rowDirection(tblId, tr);
    const want = tblId === "tbl-conns" ? state.dirConns
      : tblId === "tbl-network" ? state.dirNetwork : "";
    if (want && dir) ok = dir === want;
    if (ok && tblId === "tbl-conns" && state.appConns &&
        tr.children[0].textContent.trim() !== state.appConns) {
      ok = false;
    }
  }
  if (ok) {
    const t = tblId.replace("tbl-", "");
    const f = state.filters[t];
    if (f) {
      for (const def of FILTER_DEFS) {
        const want = f[def.key];
        if (want && tr.children[def.col].textContent.trim() !== want) {
          ok = false;
          break;
        }
      }
    }
  }
  tr.style.display = ok ? "" : "none";
}
for (const name of ["privacy", "file", "network", "conns", "system"]) {
  $("filter-" + name).addEventListener("input", () => {
    const tblId = "tbl-" + name;
    for (const tr of $(tblId).tBodies[0].rows) applyFilter(tblId, tr);
  });
}

/* -------------------------------------------------------- event route -- */
function blockBtnHtml(remote) {
  if (!remote || typeof remote !== "string") return "";
  const ip = remote.split(":")[0];
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return "";
  return ` <button class="mini-btn" data-bip="${esc(ip)}"
    title="block all traffic to/from ${esc(ip)}">&#9940;</button>`;
}

function handleEvent(ev) {
  state.eventCount++;
  const t = { cls: "dim", html: fmtTime(ev.ts) };
  if (ev.category === "privacy") {
    addRow("tbl-privacy", [
      t, { html: badge("privacy", ev.kind) },
      { html: esc(ev.app ?? "") }, { html: esc(ev.user ?? "") },
      { html: esc(ev.device ?? "") },
      { html: esc(ev.detail ?? ""), cls: "dim" },
    ]);
    if (/camera|mic/.test(ev.kind)) {
      state.lastPrivacy = { ts: ev.ts, kind: ev.kind, app: ev.app, user: ev.user };
      updatePrivacyCard();
    }
  } else if (ev.category === "file") {
    addRow("tbl-file", [
      t, { html: badge("file", ev.kind) },
      { html: esc(ev.app || "unknown app") }, { html: esc(ev.user || "") },
      { html: `<span class="mono">${esc(ev.path || "path unavailable")}</span>` },
      { html: esc(ev.detail ?? ""), cls: "dim" },
    ]);
  } else if (ev.category === "network") {
    addRow("tbl-network", [
      t, { html: badge("network", ev.kind) },
      { html: esc(ev.app ?? "") }, { html: esc(ev.user ?? "") },
      { html: `<span class="mono">${esc(ev.remote ?? "")}</span>${blockBtnHtml(ev.remote)}` },
      { html: esc(ev.direction ?? "") },
      { html: esc(ev.detail ?? ""), cls: "dim" },
    ]);
  } else if (["devices", "logins", "system", "appfocus"].includes(ev.category)) {
    addRow("tbl-system", [
      t, { html: badge(ev.category, ev.kind) },
      { html: esc(ev.app ?? "") }, { html: esc(ev.user ?? "") },
      { html: `<span class="mono">${esc(ev.device ?? ev.path ?? "")}</span>` },
      { html: esc(ev.detail ?? ""), cls: "dim" },
    ]);
  }
}
function fmtAgo(ts) {
  const s = Math.max(0, Math.round(Date.now() / 1000 - ts));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s ago`;
  const h = Math.floor(s / 3600);
  return `${h}h ${Math.floor((s % 3600) / 60)}m ago`;
}
function updatePrivacyCard() {
  const p = state.lastPrivacy;
  if (!p) return;
  const what = p.kind.startsWith("camera") ? "Camera" : "Microphone";
  $("card-privacy").textContent = what;
  $("card-privacy").style.color = p.kind.endsWith("_start")
    ? "var(--red)" : p.kind.endsWith("_access") ? "var(--amber)" : "var(--text)";
  $("card-privacy-sub").textContent = `${p.app || "unknown app"} · ${fmtAgo(p.ts)}` +
    (p.user ? ` · ${p.user}` : "");
}

/* ------------------------------------------------------------ loaders -- */
async function getJSON(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`${url}: ${r.status}`);
  return r.json();
}

async function loadStatus() {
  try {
    const s = await getJSON("/api/status");
    $("hostline").innerHTML =
      `<b>${esc(s.hostname)}</b> · ${esc(s.platform)} · user <b>${esc(s.user)}</b>` +
      (s.root ? ' · <span style="color:var(--amber)">elevated</span>' : "");
    const chips = s.collectors.map((c) => {
      const st = c.status.state;
      const dot = st === "active" ? "dot-on" : st === "degraded" ? "dot-deg"
        : st === "idle" ? "dot-deg" : st === "error" ? "dot-err" : "dot-off";
      const title = `${c.description}\n${c.status.detail || ""}` +
        (c.enabled ? "\n\nclick to turn OFF" : "\n\nclick to turn ON");
      // a privilege-blocked files chip offers the one-time grant instead of
      // a plain toggle (clicking it again would just fail the same way)
      const unpriv = s.platform === "darwin" && c.name === "files-macos" &&
        st === "unavailable" && /fs_usage|needs root/.test(c.status.detail || "");
      return `<span class="chip ${c.enabled ? "" : "chip-off"}" role="button" ` +
        `data-category="${esc(c.category)}" data-enabled="${c.enabled}" ` +
        (unpriv ? `data-files-grant="1" ` : "") +
        `title="${esc(title)}">` +
        `<span class="dot ${dot}"></span><b>${esc(c.name)}</b> ${esc(st)}</span>`;
    });
    for (const d of s.android_devices || []) {
      chips.push(`<span class="chip"><span class="dot dot-on"></span><b>android</b> ${esc(d)}</span>`);
    }
    $("status-chips").innerHTML = chips.join("");
    for (const el of document.querySelectorAll("#status-chips .chip[data-category]")) {
      el.addEventListener("click", () => {
        if (el.dataset.filesGrant === "1") {
          grantFileTracing(el.dataset.category);
          return;
        }
        toggleCollector(el.dataset.category, el.dataset.enabled !== "true");
      });
    }
    const allOn = s.collectors.every((c) => c.enabled);
    // on-demand file tracing padlock (File access panel head)
    const fl = $("file-lock-btn");
    if (fl) {
      const g = s.files_grant;
      if (g && g.supported) {
        fl.style.display = "";
        fl.dataset.installed = g.installed ? "1" : "0";
        fl.textContent = g.installed ? "\u{1F512}" : "\u{1F513}";
        fl.title = g.installed
          ? "file tracing is ON (fs_usage via a passwordless grant)\n" +
            "click to make it on-demand — tracing stops and the grant is removed"
          : "file tracing is OFF (no fs_usage grant)\n" +
            "click to grant — macOS asks for your password once, tracing starts";
      } else {
        fl.style.display = "none";
      }
    }
    const master = $("master-toggle");
    master.textContent = allOn ? "\u25A4 pause all" : "\u25B6 resume all";
    master.classList.toggle("master-off", !allOn);
    master.onclick = () => toggleCollector("all", !allOn);
  } catch (e) { console.warn("status", e); }
}

async function toggleCollector(target, enabled) {
  try {
    await fetch("/api/collectors", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, enabled }),
    });
  } catch (e) { console.warn("toggle", e); }
  loadStatus();
}

// one-time grant for file tracing on macOS: installs the read-only
// fs_usage sudoers entry via the OS password dialog, then enables the chip
async function grantFileTracing(category) {
  if (!confirm("File tracing needs one narrow grant: permission to run " +
      "/usr/bin/fs_usage as root (read-only tracing, nothing else).\n\n" +
      "Grant it now? macOS will ask for your password once.")) {
    toggleCollector(category, false);
    return;
  }
  try {
    const r = await fetch("/api/files/grant", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "grant" }),
    });
    const d = await r.json();
    if (!d.ok) {
      if (!d.canceled) alert("Grant failed: " + (d.error || "unknown"));
    }
  } catch (e) {
    alert("Grant failed: " + e);
  }
  toggleCollector(category, true);
}

// the File access panel's padlock: grant = start tracing (password once),
// revoke = stop tracing and remove the grant (on-demand)
$("file-lock-btn").addEventListener("click", async () => {
  const btn = $("file-lock-btn");
  const installed = btn.dataset.installed === "1";
  const action = installed ? "revoke" : "grant";
  if (installed && !confirm("Make file tracing on-demand?\n\nTracing stops " +
      "now and the passwordless fs_usage grant is removed. The padlock " +
      "grants it again any time (one password prompt).")) {
    return;
  }
  btn.disabled = true;
  try {
    const r = await fetch("/api/files/grant", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action }),
    });
    const d = await r.json();
    if (!d.ok && !d.canceled) {
      alert((installed ? "Revoke" : "Grant") + " failed: " + (d.error || "unknown"));
    }
  } catch (e) {
    alert((installed ? "Revoke" : "Grant") + " failed: " + e);
  }
  btn.disabled = false;
  loadStatus();
});

async function loadConnections() {
  try {
    const data = await getJSON("/api/connections");
    const keep = new Set(["ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT_1",
      "FIN_WAIT_2", "LAST_ACK"]);
    const conns = (data.connections || [])
      .filter((c) => keep.has(c.state));
    $("card-conns").textContent = conns.length;
    const tbody = $("tbl-conns").tBodies[0];
    tbody.innerHTML = "";
    for (const c of conns) {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${esc(c.app ?? "–")}</td>
        <td>${esc(c.user ?? "–")}</td>
        <td>${c.direction === "outbound" ? "↓ out" : "↑ in"}</td>
        <td class="mono">${esc(c.remote_ip)}:${esc(c.remote_port)}
          <span class="scope scope-${esc(c.scope)}">${esc(c.scope)}</span></td>
        <td class="dim">${esc(c.service || "")} ${c.host ? "· " + esc(c.host) : ""}</td>
        <td class="mono dim">${esc(c.local_ip)}:${esc(c.local_port)}</td>
        <td class="dim">${esc(c.state ?? "")}</td>
        <td class="blockcell">
          <button class="mini-btn" data-btype="ip" data-bip="${esc(c.remote_ip)}"
            title="block all traffic to/from ${esc(c.remote_ip)}">&#9940;</button>
          <button class="mini-btn" data-btype="app" data-bapp="${esc(c.app || "")}"
            data-bpid="${c.pid ?? ""}"
            title="block the app ${esc(c.app || "")}">&#128683;</button>
        </td>`;
      tbody.appendChild(tr);
    }
    refreshAppOptions(conns);
    applyConnFilter();
  } catch (e) { console.warn("conns", e); }
}
function refreshAppOptions(conns) {
  const sel = $("app-conns");
  if (!sel) return;
  const apps = [...new Set(conns.map((c) => c.app).filter(Boolean))]
    .sort((a, b) => a.localeCompare(b));
  if (state.appConns && !apps.includes(state.appConns)) {
    apps.push(state.appConns);   // keep the chosen app visible even if idle
  }
  sel.innerHTML = '<option value="">All apps</option>' +
    apps.slice(0, 200).map((a) =>
      `<option value="${esc(a)}"${a === state.appConns ? " selected" : ""}>` +
      `${esc(a)}</option>`).join("");
}

function applyConnFilter() {
  const q = $("filter-conns").value.toLowerCase();
  for (const tr of $("tbl-conns").tBodies[0].rows) applyFilter("tbl-conns", tr);
}
$("filter-conns").addEventListener("input", applyConnFilter);
$("dir-conns").addEventListener("change", (e) => {
  state.dirConns = e.target.value;
  applyConnFilter();
});
$("app-conns").addEventListener("change", (e) => {
  state.appConns = e.target.value;
  applyConnFilter();
});
$("dir-network").addEventListener("change", (e) => {
  state.dirNetwork = e.target.value;
  const q = $("filter-network").value.toLowerCase();
  for (const tr of $("tbl-network").tBodies[0].rows) applyFilter("tbl-network", tr);
});

async function loadTraffic() {
  try {
    const t = await getJSON("/api/traffic");
    const hist = t.history || [];
    if (hist.length >= 2) {
      const last = hist[hist.length - 1];
      $("card-rx").textContent = fmtRate(last.in);
      $("card-tx").textContent = fmtRate(last.out);
    }
    drawChart(hist);
    renderTopApps(t.app_rates || {}, t.app_connections || {});
  } catch (e) { console.warn("traffic", e); }
}

function renderTopApps(rates, appConnections) {
  const rows = Object.entries(rates)
    .map(([app, r]) => [app, (r.in || 0) + (r.out || 0), r])
    .sort((a, b) => b[1] - a[1]).slice(0, 10);
  if (!rows.length && Object.keys(appConnections).length) {
    const connectionRows = Object.entries(appConnections)
      .sort((a, b) => b[1] - a[1]).slice(0, 10);
    $("top-apps").innerHTML =
      '<div class="empty">per-process byte counters are unavailable on Windows; ' +
      'showing apps by active connections</div>' +
      connectionRows.map(([app, count]) => `
        <div class="row">
          <div class="name"><span>${esc(app)}</span>
            <span>${count} active connection${count === 1 ? "" : "s"}</span></div>
          <div class="bar"><i class="in" style="width:0%"></i></div>
        </div>`).join("");
    return;
  }
  const max = Math.max(...rows.map((r) => r[1]), 1);
  const el = $("top-apps");
  if (!rows.length) { el.innerHTML = '<div class="empty">no per-process traffic data on this platform</div>'; return; }
  el.innerHTML = rows.map(([app, total, r]) => `
    <div class="row">
      <div class="name"><span>${esc(app)}</span>
        <span>↓${fmtRate(r.in || 0)} ↑${fmtRate(r.out || 0)}</span></div>
      <div class="bar">
        <i class="in" style="width:${((r.in || 0) / max) * 100}%"></i>
        <i class="out" style="width:${((r.out || 0) / max) * 100}%"></i>
      </div>
    </div>`).join("");
}

async function loadSummary() {
  try {
    const s = await getJSON(`/api/summary?minutes=${state.histMinutes}`);
    let n = 0;
    for (const kinds of Object.values(s.counts)) for (const v of Object.values(kinds)) n += v;
    $("card-events").textContent = n;
    $("card-events-label").textContent =
      `Events (last ${RANGE_LABELS[state.histMinutes] || state.histMinutes + " min"})`;
    const top = s.top_apps.slice(0, 3).map(([a]) => a).join(", ");
    $("card-events-sub").textContent = top ? `top: ${top}` : "privacy + files + network";
  } catch (e) { console.warn("summary", e); }
}

/* -------------------------------------------------------------- chart -- */
function drawChart(hist) {
  const cv = $("chart");
  const dpr = window.devicePixelRatio || 1;
  const w = cv.clientWidth, h = 130;
  cv.width = w * dpr; cv.height = h * dpr;
  const g = cv.getContext("2d");
  g.scale(dpr, dpr);
  g.clearRect(0, 0, w, h);
  if (hist.length < 2) return;
  const max = Math.max(...hist.map((p) => Math.max(p.in, p.out)), 1);
  const pad = { l: 46, r: 8, t: 8, b: 14 };
  const X = (i) => pad.l + (i / (hist.length - 1)) * (w - pad.l - pad.r);
  const Y = (v) => h - pad.b - (v / max) * (h - pad.t - pad.b);
  // grid
  g.strokeStyle = "#263041"; g.fillStyle = "#8494ab";
  g.font = "10px sans-serif"; g.textAlign = "right";
  for (let i = 0; i <= 3; i++) {
    const v = (max / 3) * i, y = Y(v);
    g.beginPath(); g.moveTo(pad.l, y); g.lineTo(w - pad.r, y); g.stroke();
    g.fillText(fmtRate(v), pad.l - 6, y + 3);
  }
  const line = (key, color) => {
    g.strokeStyle = color; g.lineWidth = 1.6; g.beginPath();
    hist.forEach((p, i) => i ? g.lineTo(X(i), Y(p[key])) : g.moveTo(X(0), Y(p[key])));
    g.stroke();
  };
  line("in", "#4da3ff");
  line("out", "#3fd68f");
  g.textAlign = "left"; g.fillStyle = "#4da3ff"; g.fillText("↓ in", pad.l + 4, pad.t + 8);
  g.fillStyle = "#3fd68f"; g.fillText("↑ out", pad.l + 44, pad.t + 8);
}

/* ---------------------------------------------------------------- SSE -- */
let sse = null;
function connectSSE() {
  if (sse) sse.close();
  sse = new EventSource("/api/stream");
  sse.onopen = () => { $("sse-state").className = "dot dot-on"; $("footer-text").textContent = "live"; };
  sse.onmessage = (m) => {
    try {
      const msg = JSON.parse(m.data);
      if (msg.type === "event") {
        if (!state.paused) handleEvent(msg.data);
        else state.eventCount++;
      }
    } catch (e) { /* ignore */ }
  };
  sse.onerror = () => { $("sse-state").className = "dot dot-off"; $("footer-text").textContent = "reconnecting…"; };
}
$("pause").addEventListener("change", (e) => { state.paused = e.target.checked; });

/* ------------------------------------------------------------- battery -- */
function levelClass(pct, lowAt) {
  // battery-style thresholds pass lowAt as "batt" (20), utilization uses 60/85
  if (lowAt === "batt") return pct > 50 ? "ok" : pct > 20 ? "warn" : "low";
  return pct < 60 ? "ok" : pct < 85 ? "warn" : "low";
}

function setGauge(id, pct) {
  const val = $(`g-${id}-v`);
  if (pct == null) {
    $(`vg-${id}`).classList.add("hidden");
    return;
  }
  $(`vg-${id}`).classList.remove("hidden");
  const fill = $(`g-${id}`);
  fill.style.height = Math.max(2, Math.min(100, pct)) + "%";
  fill.className = "vfill " + levelClass(
    pct, id === "batt" ? "batt" : "util");
  val.textContent = Math.round(pct) + "%";
}

async function loadBattery() {
  try {
    const b = await getJSON("/api/battery");
    const panel = $("battery-panel");
    if (!b.available) { panel.style.display = "none"; return; }
    panel.style.display = "";
    setGauge("batt", b.percent);
    setGauge("cpu", b.cpu_percent);
    setGauge("mem", b.mem_percent);
    setGauge("disk", b.disk_percent);
    const vgBatt = $("vg-batt");
    vgBatt.title = b.percent != null
      ? `battery ${b.percent}% · ${b.state || "?"}` +
        (b.time_remaining ? ` · ${b.time_remaining}` : "")
      : "no battery on this machine";
    $("g-disk").title = b.disk_used
      ? `${b.disk_used} of ${b.disk_total} used` : "";
    $("g-mem").title = b.mem_used ? `${b.mem_used} of ${b.mem_total} in use` : "";
    const battLine = b.percent != null
      ? `${b.percent}% ${b.state || "?"}` +
        (b.time_remaining ? ` · ${b.time_remaining}` : "") +
        (b.low_power_mode ? " · low power" : "")
      : "none";
    $("vd-batt").textContent = battLine;
    $("vd-ram").textContent = b.mem_used ? `${b.mem_used} / ${b.mem_total}` : "–";
    $("vd-disk").textContent = b.disk_used ? `${b.disk_used} / ${b.disk_total}` : "–";
    // mounted volumes (external drives, USB, other partitions)
    const vols = b.volumes || [];
    $("volumes-list").innerHTML = vols.map((v) => {
      const lvl = v.percent < 60 ? "ok" : v.percent < 85 ? "warn" : "low";
      return `<div class="vol-row" title="${esc(v.path)}">
        <div class="vol-top"><span class="vol-name">${esc(v.name)}` +
        `${v.boot ? ' <span class="vol-boot">boot</span>' : ""}</span>` +
        `<span class="vol-pct">${v.percent}%</span></div>
        <div class="vol-bar"><div class="vol-fill ${lvl}" style="width:${v.percent}%"></div></div>
        <div class="vol-sub dim">${esc(v.used)} / ${esc(v.total)}</div>
      </div>`;
    }).join("") || '<div class="dim" style="font-size:11px">no volumes</div>';
    const summary = [battLine !== "none" ? `battery ${battLine}` : null,
                     b.mem_percent != null ? `RAM ${b.mem_percent}%` : null,
                     b.disk_percent != null ? `disk ${b.disk_percent}%` : null]
      .filter(Boolean).join(" · ");
    $("battery-summary").textContent = summary;
    $("battery-assertions").innerHTML = (b.assertions || []).map((a) =>
      `<span class="chip chip-mini" title="${esc(a.detail || "")}">` +
      `<b>${esc(a.app)}</b> ${esc(a.type)}</span>`).join("") ||
      '<span class="dim" style="font-size:11px">no sleep-prevention assertions active</span>';
    const tb = $("tbl-power").tBodies[0];
    tb.innerHTML = (b.top_apps || []).map((a) =>
      `<tr><td>${esc(a.app)}</td><td>${a.cpu}</td>` +
      `<td class="mono dim">${esc(a.runtime || "-")}</td></tr>`).join("") ||
      '<tr><td colspan="3" class="dim">no significant power consumers right now</td></tr>';
  } catch (e) { console.warn("battery", e); }
}

// gauge style selector (persisted per browser)
const gaugeStyleSel = $("gauge-style");
function applyGaugeStyle(s) {
  $("vgauges").className = "vgauges " + s;
}
// Gauge style persists in the app's config.json (inside the deck data
// folder) via /api/gauge-style — localStorage does not survive the launcher
// reopening app windows.
getJSON("/api/gauge-style").then(function (s) {
  if (s && s.style) {
    gaugeStyleSel.value = s.style;
    applyGaugeStyle(s.style);
  }
}).catch(function () {});
gaugeStyleSel.addEventListener("change", () => {
  applyGaugeStyle(gaugeStyleSel.value);
  fetch("/api/gauge-style", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ style: gaugeStyleSel.value }),
  }).catch(function () {});
});

/* ---------------------------------------------------------------- init -- */
async function loadPanel(t) {
  const since = Date.now() / 1000 - panelMinutes(t) * 60;
  try {
    const data = await getJSON(
      `/api/events?category=${t}&limit=500&since=${since.toFixed(3)}`);
    $(`tbl-${t}`).tBodies[0].innerHTML = "";
    for (const ev of data.events.slice().reverse()) handleEvent(ev);
  } catch (e) { console.warn(t, e); }
  refreshFilterOptions();
}

async function loadHistory() {
  for (const cat of FILTER_TABLES) await loadPanel(cat);
}

$("hist-range").addEventListener("change", (e) => {
  state.histMinutes = parseInt(e.target.value, 10) || 60;
  // global range: applies to every panel and syncs their dropdowns
  for (const t of FILTER_TABLES) {
    state.panelMinutes[t] = state.histMinutes;
    const sel = $(`hist-${t}`);
    if (sel) sel.value = String(state.histMinutes);
  }
  loadHistory();
  loadSummary();
});

$("purge-btn").addEventListener("click", async () => {
  const choice = $("purge-range").value;
  const labels = { 1: "1 hour", 6: "6 hours", 24: "24 hours", 168: "7 days",
                   all: "EVERYTHING" };
  const label = labels[choice] || choice;
  if (!confirm(`Permanently delete ${choice === "all"
      ? "ALL stored events" : `events older than ${label}`}?`)) return;
  const body = choice === "all" ? { all: true } : { hours: parseInt(choice, 10) };
  try {
    const r = await fetch("/api/data/delete", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const d = await r.json();
    const msg = $("purge-msg");
    msg.textContent = d.ok ? `deleted ${d.deleted} events` : `error: ${d.error}`;
    msg.style.color = d.ok ? "var(--green)" : "var(--red)";
    setTimeout(() => { msg.textContent = ""; }, 6000);
    loadHistory();
    loadSummary();
  } catch (e) {
    $("purge-msg").textContent = `error: ${e}`;
  }
});

/* ------------------------------------------------------------- blocking -- */
async function loadBlocks() {
  try {
    const d = await getJSON("/api/blocks");
    const st = $("blocks-status");
    const mode = d.enforcement?.mode;
    const lockBtn = $("block-lock-btn");
    lockBtn.dataset.enforcing = mode ? "1" : "0";
    if (mode) {
      st.textContent = "enforcing";
      st.style.color = "var(--green)";
      st.title = d.enforcement.reason || "";
      // closed padlock: the firewall is actually dropping traffic; click
      // to revoke the grant and stop enforcing
      lockBtn.textContent = "\u{1F512}";
      lockBtn.title = "blocking is ENFORCED (" + (d.enforcement.reason || "") +
        ")\n\nclick to remove the grant \u2014 applied rules are lifted and " +
        "stored rules go back to queued";
      lockBtn.style.display = "";
    } else {
      const reason = d.enforcement?.reason || "no privilege";
      st.textContent = "queued only";
      st.style.color = "var(--amber)";
      st.title = reason;
      // open padlock: rules are stored but nothing is dropped yet; click
      // to run the one-time grant (password once)
      lockBtn.textContent = "\u{1F513}";
      lockBtn.title = reason + "\n\nclick to enforce \u2014 one-time privileged " +
        "install, the OS asks for your password once";
      lockBtn.style.display =
        d.enforcement?.grant_supported === false ? "none" : "";
    }
    const tb = $("tbl-blocks").tBodies[0];
    tb.innerHTML = (d.rules || []).map((r) => `
      <tr>
        <td class="dim">${fmtTime(r.ts)}</td>
        <td>${badge("network", r.type)}</td>
        <td class="mono">${esc(r.value)}</td>
        <td><span class="badge ${r.status === "enforced" ? "b-login" :
          r.status === "queued" ? "b-file" : "b-priv"}">${esc(r.status)}</span></td>
        <td class="dim">${esc(r.status_detail || "")}</td>
        <td><button class="mini-btn" data-unblock="${r.id}"
              title="remove this rule">&#10006;</button></td>
      </tr>`).join("") ||
      '<tr><td colspan="6" class="dim">no block rules — use the ⛔ buttons ' +
      'on connections or the form above</td></tr>';
  } catch (e) { console.warn("blocks", e); }
}

async function addBlock(payload) {
  try {
    const r = await fetch("/api/blocks", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "add", ...payload }),
    });
    const d = await r.json();
    if (!d.ok) { alert("Block failed: " + (d.error || d.detail || "unknown")); return; }
    if (d.status !== "enforced") {
      alert(`Rule saved but not yet enforced (${d.status}).\n${d.detail || ""}`);
    }
    loadBlocks();
  } catch (e) { alert("Block failed: " + e); }
}

// row buttons (live connections + network events) use event delegation
$("tbl-conns").addEventListener("click", (e) => {
  const btn = e.target.closest("button[data-btype]");
  if (!btn) return;
  if (btn.dataset.btype === "ip") {
    if (confirm(`Block ALL traffic to/from ${btn.dataset.bip}?`))
      addBlock({ type: "ip", ip: btn.dataset.bip });
  } else {
    if (confirm(`Block the app "${btn.dataset.bapp || "this app"}" (all its ` +
        `network traffic)?`))
      addBlock({ type: "app", pid: btn.dataset.bpid, app: btn.dataset.bapp });
  }
});
$("tbl-network").addEventListener("click", (e) => {
  const btn = e.target.closest("button.mini-btn[data-bip]");
  if (!btn) return;
  if (confirm(`Block ALL traffic to/from ${btn.dataset.bip}?`))
    addBlock({ type: "ip", ip: btn.dataset.bip });
});

$("block-type").addEventListener("change", (e) => {
  const t = e.target.value;
  $("block-ip").style.display = t === "app" ? "none" : "";
  $("block-port").style.display = t === "connection" ? "" : "none";
  $("block-app").style.display = t === "app" ? "" : "none";
});
$("block-add").addEventListener("click", () => {
  const type = $("block-type").value;
  const payload = { type };
  if (type !== "app") {
    payload.ip = $("block-ip").value.trim();
    if (type === "connection") payload.port = $("block-port").value.trim();
  } else {
    payload.app = $("block-app").value.trim();
  }
  addBlock(payload);
});
$("block-reapply").addEventListener("click", async () => {
  await fetch("/api/blocks", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action: "reconcile" }),
  });
  loadBlocks();
});
// the lock icon is both the state display and the enforce/remove control
$("block-lock-btn").addEventListener("click", async () => {
  const btn = $("block-lock-btn");
  const enforcing = btn.dataset.enforcing === "1";
  const action = enforcing ? "revoke" : "grant";
  if (enforcing && !confirm("Remove the blocking grant?\n\nThe installed " +
      "helper, its passwordless entry and every applied firewall rule are " +
      "removed; stored rules go back to queued until you enforce again.")) {
    return;
  }
  btn.disabled = true;
  const label = btn.textContent;
  btn.textContent = "\u2026";
  try {
    const r = await fetch("/api/block/grant", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action }),
    });
    const d = await r.json();
    if (!d.ok) {
      if (d.canceled) { /* password sheet dismissed -- nothing to say */ }
      else alert((enforcing ? "Revoke" : "Grant") + " failed: " +
        (d.error || "unknown"));
    } else if (!enforcing && !d.mode) {
      alert("Privilege was granted but blocking is still not active:\n" +
        (d.reason || d.warning || "unknown"));
    }
    loadBlocks();
  } catch (e) {
    alert((enforcing ? "Revoke" : "Grant") + " failed: " + e);
  }
  btn.disabled = false;
  btn.textContent = label;
});
$("tbl-blocks").addEventListener("click", (e) => {
  const btn = e.target.closest("button[data-unblock]");
  if (!btn) return;
  if (confirm("Remove this block rule?")) {
    fetch("/api/blocks", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "remove", id: parseInt(btn.dataset.unblock, 10) }),
    }).then(loadBlocks);
  }
});

initFilterSelects();
loadStatus();
loadConnections();
loadTraffic();
loadSummary();
loadBattery();
loadBlocks();
loadHistory();
connectSSE();
setInterval(updatePrivacyCard, 1000);   // keep "Xs ago" ticking between events
setInterval(loadConnections, 3000);
setInterval(loadTraffic, 3000);
setInterval(loadBattery, 5000);
setInterval(loadBlocks, 5000);
setInterval(refreshFilterOptions, 30000);
setInterval(loadSummary, 10000);
setInterval(loadStatus, 15000);

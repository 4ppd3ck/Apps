// Sentinel dashboard — vanilla JS, SSE live updates, no build step.
"use strict";

const $ = (s) => document.querySelector(s);
const SEVS = ["critical", "high", "medium", "low", "info"];
let status = null;
let alerts = [];
let alertFilter = { sev: "", hideAcked: true, state: "", check: "" };
let seenIds = new Set();
let permissionData = null;
let sensitiveData = null;
let exclusions = []; // [{app, watchdog, live, app_access}] — server-persisted
let alertAppFilter = "";
let guardrailsOff = false; // 🛡 Guardrails toggle: when true, remediation
// actions skip the Apple/system target checks server-side (expert mode).

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
const guardrailsOffWarning =
  "🛡 Guardrails are OFF — Sentinel will no longer refuse actions against " +
  "Apple-owned launchd items, macOS system firewall entries, or com.apple.* " +
  "TCC grants. Deleting or changing those can break macOS; re-enable " +
  "Guardrails when the expert operation is done.";

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
  const intel = status.intel || {};
  const i = $("#intelState");
  i.hidden = !intel.up;
  i.textContent = `ipolice: ${intel.up ? `${intel.networks} nets` : "offline"}`;
  i.className = "pill " + (intel.up ? "on" : "off");
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
    <div class="row"><span class="k">last poll</span><span>${timeOf(m.last_poll)}</span></div>
    ${intelRow()}`;
}

// intelRow renders the IPolice line (known-IP intelligence) under the
// monitor summary; hidden while the optional app is not running.
function intelRow() {
  const intel = status.intel || {};
  if (!intel.up) return "";
  const provs = (intel.providers || []).join(", ");
  return `<div class="row"><span class="k">ipolice</span>
    <span title="Known-IP intelligence: ${esc(provs)}">🚔 ${intel.networks} networks ·
    ${(intel.providers || []).length} providers · ${timeOf(intel.updated_at)}</span></div>`;
}

// evidenceApp is the app an alert is about (matching the server's findingApp).
function evidenceApp(a) {
  return String(a.evidence?.app || a.evidence?.name || "");
}

// silencingOf classifies an alert by how its app is currently silenced:
//   excluded — watchdog exclusion: future findings are never recorded
//   autoack  — auto-ack exclusion: recorded but pre-acked, never a popup
//   notify   — nothing silenced; this app's alerts will notify
// Appless alerts (mitm, firewall) have no app to silence → notify.
function silencingOf(a) {
  const app = evidenceApp(a);
  if (!app) return "notify";
  const x = exclusionFor(app);
  if (x?.watchdog) return "excluded";
  if (x?.auto_ack) return "autoack";
  return "notify";
}

function renderAlerts() {
  // app dropdown: distinct alert apps, current selection preserved across
  // the frequent SSE-triggered reloads
  const apps = [...new Set(alerts.map(evidenceApp).filter(Boolean))]
    .sort((a, b) => a.localeCompare(b, undefined, { sensitivity: "base" }));
  const sel = $("#alertApp");
  sel.innerHTML = `<option value="">all apps</option>` +
    apps.map((a) => `<option value="${esc(a)}">${esc(a)}</option>`).join("");
  if (apps.includes(alertAppFilter)) sel.value = alertAppFilter;
  else { alertAppFilter = sel.value; }

  // check dropdown: distinct detector names, selection preserved likewise
  const checks = [...new Set(alerts.map((a) => a.check).filter(Boolean))].sort();
  const checkSel = $("#alertCheck");
  checkSel.innerHTML = `<option value="">all checks</option>` +
    checks.map((c) => `<option value="${esc(c)}">${esc(c)}</option>`).join("");
  if (checks.includes(alertFilter.check)) checkSel.value = alertFilter.check;
  else { alertFilter.check = checkSel.value; }

  const needle = alertAppFilter.toLowerCase();
  const list = alerts.filter((a) =>
    (!alertFilter.sev || SEVS.indexOf(a.severity) <= SEVS.indexOf(alertFilter.sev)) &&
    (!alertFilter.check || a.check === alertFilter.check) &&
    (!alertFilter.state || silencingOf(a) === alertFilter.state) &&
    (!needle || evidenceApp(a).toLowerCase().includes(needle)) &&
    (!alertFilter.hideAcked || !a.acked));
  if (!list.length) {
    $("#alertList").innerHTML = `<p class="muted">No alerts${alertFilter.sev ? " at this severity" : ""} — Sentinel is watching.</p>`;
    return;
  }

  $("#alertList").innerHTML = list.map((a) => `
    <div class="alert ${esc(a.severity)} ${a.acked ? "acked" : ""}" data-id="${a.id}">
      <button class="btn ghost small ack" data-id="${a.id}">${a.acked ? "✓" : "ack"}</button>
      <button class="btn ghost small del" data-id="${a.id}" title="delete this alert">🗑</button>
      ${evidenceApp(a) ? alertExcludeBtn(evidenceApp(a)) + alertAutoAckBtn(evidenceApp(a)) : ""}
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
  document.querySelectorAll(".alert button.excl").forEach((b) =>
    b.addEventListener("click", async () => {
      const app = b.dataset.app;
      const on = !!(exclusionFor(app)?.watchdog);
      try {
        const d = await api("/api/exclusions", {
          method: "POST",
          body: JSON.stringify({ app, field: "watchdog", value: !on }),
        });
        exclusions = d.exclusions || [];
        renderAlerts(); // button flips to its new state
        loadAlerts();   // excluded apps stop alerting server-side — refresh rows
      } catch (e) {
        alert("Could not save exclusion: " + e.message);
      }
    }));
  // auto-ack: future alerts from this app are recorded pre-acked — history
  // and hit counts only, never a popup; existing unacked rows are acked too
  document.querySelectorAll(".alert button.aack").forEach((b) =>
    b.addEventListener("click", async () => {
      const app = b.dataset.app;
      const on = !!(exclusionFor(app)?.auto_ack);
      try {
        const d = await api("/api/exclusions", {
          method: "POST",
          body: JSON.stringify({ app, field: "auto_ack", value: !on }),
        });
        exclusions = d.exclusions || [];
        renderAlerts();
        loadAlerts();
      } catch (e) {
        alert("Could not save auto-ack: " + e.message);
      }
    }));
}

// alertExcludeBtn is the one-click watchdog silence on an alert row: the app
// the alert is about (its evidence) goes straight into the exclusion list —
// no digging through every installed app in the Exclusions tab.
function alertExcludeBtn(app) {
  const on = !!(exclusionFor(app)?.watchdog);
  return `<button class="btn ghost small excl ${on ? "on" : ""}" data-app="${esc(app)}"
    title="${on
      ? `Watchdog exclusion active for ${esc(app)} — click to remove it`
      : `Stop all alerts and notifications for ${esc(app)} (adds a Watchdog exclusion)`}"
    >${on ? "🔕 excluded" : "🔕 exclude"}</button>`;
}

// alertAutoAckBtn sets the auto_ack scope: the app keeps alerting into
// history (counts preserved) but every alert lands pre-acked — no popup,
// and it stops showing under "hide acked".
function alertAutoAckBtn(app) {
  const on = !!(exclusionFor(app)?.auto_ack);
  return `<button class="btn ghost small aack ${on ? "on" : ""}" data-app="${esc(app)}"
    title="${on
      ? `Auto-ack active for ${esc(app)} — its alerts land pre-acked; click to turn it off`
      : `Record future alerts for ${esc(app)} pre-acked (history only, no popup, existing rows acked)`}"
    >${on ? "🤫 auto-ack on" : "🤫 auto-ack"}</button>`;
}

function renderPermissions() {
  if (!permissionData) return;
  updateRemovalHelp(permissionData.platform);
  const apps = (permissionData.apps || []).map((app) => ({
    ...app,
    permissions: (app.permissions || []).filter((p) => !isFirewallPermission(p)),
  }));
  const accesses = apps.flatMap((app) => app.permissions || []);
  const granted = accesses.filter((p) => p.status === "granted").length;
  const declared = accesses.filter((p) => p.status === "declared").length;
  const unknown = accesses.filter((p) => p.status === "unknown").length;
  const stale = accesses.filter((p) => p.stale).length;
  $("#permissionSummary").innerHTML = `
    <button class="permission-stat" type="button" data-permission-status=""><strong>${apps.length}</strong><span>apps found</span></button>
    <button class="permission-stat ${$("#permissionStatus").value === "granted" ? "active" : ""}" type="button" data-permission-status="granted" title="Show apps with reported granted access"><strong>${granted}</strong><span>reported grants</span></button>
    <button class="permission-stat ${$("#permissionStatus").value === "declared" ? "active" : ""}" type="button" data-permission-status="declared"><strong>${declared}</strong><span>declared capabilities</span></button>
    <button class="permission-stat ${$("#permissionStatus").value === "unknown" ? "active" : ""}" type="button" data-permission-status="unknown"><strong>${unknown}</strong><span>unknown states</span></button>
    <button class="permission-stat ${$("#permissionStatus").value === "leftover" ? "active" : ""}" type="button" data-permission-status="leftover" title="Show grants left behind by apps that are no longer installed"><strong>${stale}</strong><span>leftover grants</span></button>
    <span class="muted small">Scanned ${timeOf(permissionData.scanned_at)} · ${esc(permissionData.platform || "")}</span>`;

  const categories = [...new Set(accesses.map((p) => p.category).filter(Boolean))].sort();
  const sources = [...new Set(apps.map((a) => a.source)
    .filter((source) => source && !source.toLowerCase().includes("firewall")))].sort();
  const category = $("#permissionCategory").value;
  const source = $("#permissionSource").value;
  $("#permissionCategory").innerHTML = `<option value="">All categories</option>` +
    categories.map((c) => `<option value="${esc(c)}">${esc(c)}</option>`).join("");
  $("#permissionSource").innerHTML = `<option value="">All sources</option>` +
    sources.map((s) => `<option value="${esc(s)}">${esc(s)}</option>`).join("");
  if (categories.includes(category)) $("#permissionCategory").value = category;
  if (sources.includes(source)) $("#permissionSource").value = source;

  $("#permissionWarnings").innerHTML = (guardrailsOff ? [guardrailsOffWarning] : [])
    .concat((Array.isArray(permissionData.warnings) ? permissionData.warnings : [])
      .filter((warning) => !String(warning || "").toLowerCase().includes("firewall")))
    .map((warning) => `<div class="permission-warning">${esc(warning)}</div>`).join("");
  renderFirewall();

  const query = $("#permissionSearch").value.trim().toLowerCase();
  const selectedCategory = $("#permissionCategory").value;
  const selectedStatus = $("#permissionStatus").value;
  const selectedSource = $("#permissionSource").value;
  const hasFilters = Boolean(query || selectedCategory || selectedStatus || selectedSource);
  $("#clearPermissionFilters").disabled = !hasFilters;
  const filtered = apps.map((app) => {
    const appMatches = !query || [app.name, app.identifier, app.path].some((value) =>
      String(value || "").toLowerCase().includes(query));
    const permissions = (app.permissions || []).filter((p) =>
      (!selectedCategory || p.category === selectedCategory) &&
      (!selectedStatus || (selectedStatus === "leftover" ? p.stale : p.status === selectedStatus) ||
        (selectedStatus === "limited" && p.status === "restricted")) &&
      (!query || appMatches || [p.category, p.name, p.status, p.scope, p.detail]
        .some((value) => String(value || "").toLowerCase().includes(query))));
    return { app, permissions, appMatches };
  }).filter(({ app, permissions, appMatches }) =>
    (!selectedSource || app.source === selectedSource) &&
    (appMatches || permissions.length > 0) &&
    (permissions.length > 0 || (!selectedCategory && !selectedStatus)));

  if (!filtered.length) {
    $("#permissionList").innerHTML = `<p class="muted">No apps match these filters.</p>`;
    return;
  }
  // App Access groups mirror Live Access: start collapsed, remember their
  // open state across re-renders; a fresh filter opens its matches once and
  // collapse/expand stays available afterwards.
  const permAppKey = (app) => String(app.identifier || app.name);
  const filterKey = [query, selectedCategory, selectedStatus, selectedSource].join("\x1f");
  if (filterKey !== lastPermFilterKey) {
    lastPermFilterKey = filterKey;
    openPermissionApps.clear();
    for (const { app, permissions } of filtered) {
      if (permissions.length) openPermissionApps.add(permAppKey(app));
    }
  }
  const collapsible = filtered.filter(({ permissions }) => permissions.length > 0);
  const anyCollapsed = collapsible.some(({ app }) => !openPermissionApps.has(permAppKey(app)));
  const tbtn = $("#togglePermissionGroups");
  if (tbtn) {
    tbtn.disabled = !collapsible.length;
    tbtn.textContent = anyCollapsed ? "Expand all" : "Collapse all";
  }
  $("#permissionList").innerHTML = filtered.map(({ app, permissions }) => {
    const key = permAppKey(app);
    const open = openPermissionApps.has(key);
    const rows = `<div class="permission-rows">${permissions.map((p) => `
        <div class="permission-row">
          <span class="permission-category">${esc(p.category)}</span>
          <span class="permission-name">${esc(p.name)}</span>
          <span class="permission-side">
            <span class="permission-status ${esc(p.status)}">${esc(p.status)}</span>
            ${permissionRowActions(app, p)}
            ${p.stale ? `<span class="permission-stale" title="This app is no longer installed — leftover grant">leftover</span>` : ""}
            ${p.scope ? `<span class="permission-scope">${esc(p.scope)}</span>` : ""}
          </span>
          <span class="permission-last-used">Last accessed: ${p.last_accessed ? esc(timeOf(p.last_accessed)) : "Not reported"}</span>
          ${p.detail ? `<div class="permission-detail">${esc(p.detail)}</div>` : ""}
        </div>`).join("")}</div>`;
    if (!permissions.length) {
      return `
    <article class="permission-app">
      <div class="permission-app-head">
        <div><h3>${esc(app.name)}</h3>
          <div class="permission-app-meta">${esc(app.identifier)}${app.path ? ` · ${esc(app.path)}` : ""}</div></div>
        <span class="tag">${esc(app.source || "unknown source")}</span>
      </div>
      <p class="muted small no-permissions">No permission grants reported by this platform source.</p>
    </article>`;
    }
    return `
    <article class="permission-app">
      <button class="permission-app-head sens-app-toggle perm-app-toggle" type="button"
        data-app="${esc(key)}" aria-expanded="${open}"
        title="${open ? "Collapse" : "Expand"} ${esc(app.name)}'s permissions">
        <span class="sens-head-left">
          <span class="chevron" aria-hidden="true">▸</span>
          <span class="sens-app-title">
            <span class="sens-app-name">${esc(app.name)}</span>
            <span class="permission-app-meta">${esc(app.identifier)}${app.path ? ` · ${esc(app.path)}` : ""}</span>
          </span>
        </span>
        <span class="perm-head-right">
          <span class="tag">${esc(app.source || "unknown source")}</span>
          <span class="tag">${permissions.length} grant${permissions.length > 1 ? "s" : ""}</span>
        </span>
      </button>
      ${open ? rows : ""}
    </article>`;
  }).join("");
  wirePermissionActions("#permissionList");
  wirePermissionGroups();
}

// App Access open/closed groups, remembered across the summary/filter-driven
// re-renders (same pattern as Live Access). lastPermFilterKey re-opens the
// matches whenever the filter combo changes.
const openPermissionApps = new Set();
let lastPermFilterKey = "\x00";

function wirePermissionGroups() {
  document.querySelectorAll("#permissionList .perm-app-toggle").forEach((b) =>
    b.addEventListener("click", () => {
      const key = b.dataset.app;
      if (openPermissionApps.has(key)) openPermissionApps.delete(key);
      else openPermissionApps.add(key);
      renderPermissions();
    }));
}

function isFirewallPermission(permission) {
  return String(permission.source || "").toLowerCase().includes("firewall");
}

function renderFirewall() {
  if (!permissionData) return;
  const apps = (permissionData.apps || []).map((app) => ({
    ...app,
    permissions: (app.permissions || []).filter(isFirewallPermission),
  })).filter((app) => app.permissions.length);
  const accesses = apps.flatMap((app) => app.permissions);
  const statuses = [...new Set(accesses.map((p) => p.status).filter(Boolean))].sort();
  const sources = [...new Set(accesses.map((p) => p.source).filter(Boolean))].sort();
  const selectedStatus = $("#firewallStatus").value;
  const selectedSource = $("#firewallSource").value;
  $("#firewallStatus").innerHTML = `<option value="">All statuses</option>` +
    statuses.map((s) => `<option value="${esc(s)}">${esc(s)}</option>`).join("");
  $("#firewallSource").innerHTML = `<option value="">All sources</option>` +
    sources.map((s) => `<option value="${esc(s)}">${esc(s)}</option>`).join("");
  if (statuses.includes(selectedStatus)) $("#firewallStatus").value = selectedStatus;
  if (sources.includes(selectedSource)) $("#firewallSource").value = selectedSource;

  $("#firewallWarnings").innerHTML = (guardrailsOff ? [guardrailsOffWarning] : [])
    .concat((Array.isArray(permissionData.warnings) ? permissionData.warnings : [])
      .filter((warning) => String(warning || "").toLowerCase().includes("firewall")))
    .map((warning) => `<div class="permission-warning">${esc(warning)}</div>`).join("");

  const query = $("#firewallSearch").value.trim().toLowerCase();
  const statusFilter = $("#firewallStatus").value;
  const sourceFilter = $("#firewallSource").value;
  const directionFilter = $("#firewallDirection").value;
  const hasFilters = Boolean(query || statusFilter || sourceFilter || directionFilter);
  $("#clearFirewallFilters").disabled = !hasFilters;
  const filtered = apps.map((app) => {
    const appMatches = !query || [app.name, app.identifier, app.path].some((value) =>
      String(value || "").toLowerCase().includes(query));
    const permissions = app.permissions.filter((p) =>
      (!statusFilter || p.status === statusFilter) &&
      (!sourceFilter || p.source === sourceFilter) &&
      (!directionFilter || p.dir === directionFilter) &&
      (!query || appMatches || [p.category, p.name, p.status, p.scope, p.detail, p.dir]
        .some((value) => String(value || "").toLowerCase().includes(query))));
    return { app, permissions };
  }).filter(({ permissions }) => permissions.length);

  if (!filtered.length) {
    $("#firewallList").innerHTML = `<p class="muted">${accesses.length ? "No firewall rules match these filters." : "No firewall rules reported for this platform."}</p>`;
    return;
  }
  $("#firewallList").innerHTML = filtered.map(({ app, permissions }) => `
    <article class="permission-app">
      <div class="permission-app-head">
        <div><h3>${esc(app.name)}</h3>
          <div class="permission-app-meta">${esc(app.identifier)}${app.path ? ` · ${esc(app.path)}` : ""}</div></div>
        <span class="tag">${esc(permissions[0].source || app.source || "unknown source")}</span>
      </div>
      <div class="permission-rows">${permissions.map((p) => `
        <div class="permission-row">
          <span class="permission-category">${esc(p.category)}</span>
          <span class="permission-name">${esc(p.name)}</span>
          <span class="permission-side">
            <span class="permission-status ${esc(p.status)}">${esc(p.status)}</span>
            ${p.dir ? `<span class="permission-scope">${p.dir === "out" ? "Outgoing" : "Incoming"}</span>` : ""}
            ${permissionRowActions(app, p)}
            ${p.scope ? `<span class="permission-scope">${esc(p.scope)}</span>` : ""}
          </span>
          ${p.detail ? `<div class="permission-detail">${esc(p.detail)}</div>` : ""}
        </div>`).join("")}</div>
    </article>`).join("");
  wirePermissionActions("#firewallList");
}

// Live Access ---------------------------------------------------------------
const SENS_KINDS = {
  camera: "🎥 camera",
  microphone: "🎤 microphone",
  password_manager: "🔑 password manager",
  sensitive_file: "📄 sensitive file",
};

// App groups start collapsed and remember their open state across the
// fast-tick re-renders (the whole list is re-rendered on every scan).
const openSensitiveApps = new Set();
// last filter combo Live Access rendered with — a change re-opens the
// matches once; the user's collapses then survive scan refreshes
let lastSensFilterKey = "\x00";

const sensKindWord = {
  camera: "camera", microphone: "microphone",
  password_manager: "password manager", sensitive_file: "sensitive file",
};

function groupSummary(items) {
  const byKind = {};
  for (const a of items) byKind[a.kind] = (byKind[a.kind] || 0) + 1;
  return Object.entries(byKind).map(([k, n]) =>
    `${n} ${sensKindWord[k] || k}${n > 1 ? "s" : ""}`).join(" · ");
}

function renderSensitive() {
  if (!sensitiveData) return;
  const access = sensitiveData.access || [];
  const counts = { camera: 0, microphone: 0, password_manager: 0, sensitive_file: 0 };
  let live = 0;
  for (const a of access) {
    if (counts[a.kind] != null) counts[a.kind]++;
    if (a.live) live++;
  }
  const kindSel = $("#sensitiveKind").value;
  const appSel = $("#sensitiveApp").value;
  const apps = [...new Set(access.map((a) => a.app))].sort((a, b) =>
    a.localeCompare(b, undefined, { sensitivity: "base" }));
  // rebuild the app dropdown each refresh, keeping the current selection
  $("#sensitiveApp").innerHTML = `<option value="">All apps</option>` +
    apps.map((a) => `<option value="${esc(a)}">${esc(a)}</option>`).join("");
  if (apps.includes(appSel)) $("#sensitiveApp").value = appSel;
  $("#sensitiveSummary").innerHTML = `
    <button class="permission-stat ${kindSel === "" ? "active" : ""}" type="button" data-sens-kind=""><strong>${new Set(access.map((a) => a.app)).size}</strong><span>apps</span></button>
    <button class="permission-stat ${kindSel === "camera" ? "active" : ""}" type="button" data-sens-kind="camera"><strong>${counts.camera}</strong><span>camera</span></button>
    <button class="permission-stat ${kindSel === "microphone" ? "active" : ""}" type="button" data-sens-kind="microphone"><strong>${counts.microphone}</strong><span>microphone</span></button>
    <button class="permission-stat ${kindSel === "password_manager" ? "active" : ""}" type="button" data-sens-kind="password_manager"><strong>${counts.password_manager}</strong><span>password managers</span></button>
    <button class="permission-stat ${kindSel === "sensitive_file" ? "active" : ""}" type="button" data-sens-kind="sensitive_file"><strong>${counts.sensitive_file}</strong><span>sensitive files</span></button>
    <button class="permission-stat ${liveOnly ? "active" : ""}" type="button" data-sens-live="1"
      title="Show only accesses held right now (toggles the live-only filter)"><strong>${live}</strong><span>live right now</span></button>
    <span class="muted small">Scanned ${timeOf(sensitiveData.scanned_at)} · ${esc(sensitiveData.platform || "")}</span>`;

  const notes = (sensitiveData.unavailable ? [sensitiveData.unavailable] : [])
    .concat(Array.isArray(sensitiveData.notes) ? sensitiveData.notes : []);
  $("#sensitiveNotes").innerHTML = notes
    .map((n) => `<div class="permission-warning">${esc(n)}</div>`).join("");

  const query = $("#sensitiveSearch").value.trim().toLowerCase();
  const kind = $("#sensitiveKind").value;
  const app = $("#sensitiveApp").value;
  const liveOnly = $("#sensitiveLiveOnly").checked;
  $("#clearSensitiveFilters").disabled = !(query || kind || app || liveOnly);
  const rows = access.filter((a) =>
    (!kind || a.kind === kind) &&
    (!app || a.app === app) &&
    (!liveOnly || a.live) &&
    (!query || [a.app, a.target, a.kind, a.detail, a.source]
      .some((v) => String(v || "").toLowerCase().includes(query))));

  if (!rows.length) {
    const tb0 = $("#toggleSensitiveGroups");
    if (tb0) tb0.disabled = true;
    $("#sensitiveList").innerHTML = `<p class="muted">${access.length
      ? "No live access matches these filters."
      : "No app is currently holding a camera/mic device, password-manager data or a sensitive file this scan can see."}</p>`;
    return;
  }
  const byApp = new Map();
  for (const a of rows) {
    if (!byApp.has(a.app)) byApp.set(a.app, []);
    byApp.get(a.app).push(a);
  }
  // A fresh filter opens its matches once; collapse/expand stays available
  // after that — groups the user closes stay closed until filters change.
  const filterKey = [query, kind, app, liveOnly].join("\x1f");
  if (filterKey !== lastSensFilterKey) {
    lastSensFilterKey = filterKey;
    openSensitiveApps.clear();
    for (const a of rows) openSensitiveApps.add(a.app);
  }
  const anyCollapsed = [...byApp.keys()].some((a) => !openSensitiveApps.has(a));
  const tbtn = $("#toggleSensitiveGroups");
  if (tbtn) {
    tbtn.disabled = !rows.length;
    tbtn.textContent = anyCollapsed ? "Expand all" : "Collapse all";
  }
  $("#sensitiveList").innerHTML = [...byApp.entries()].map(([appName, items]) => {
    const open = openSensitiveApps.has(appName);
    return `
    <article class="permission-app">
      <button class="permission-app-head sens-app-toggle" type="button"
        data-app="${esc(appName)}" aria-expanded="${open}"
        title="${open ? "Collapse" : "Expand"} ${esc(appName)}'s accesses">
        <span class="sens-head-left">
          <span class="chevron" aria-hidden="true">▸</span>
          <span class="sens-app-title">
            <span class="sens-app-name">${esc(appName)}</span>
            <span class="permission-app-meta">pid ${items[0].pid || "?"} · ${esc(items[0].source || "")} · ${esc(groupSummary(items))}</span>
          </span>
        </span>
        <span class="tag">${items.length} access${items.length > 1 ? "es" : ""}</span>
      </button>
      ${open ? `<div class="permission-rows">${items.map((a) => `
        <div class="permission-row">
          <span class="permission-category sens-kind-${esc(a.kind)}">${SENS_KINDS[a.kind] || esc(a.kind)}</span>
          <span class="permission-name mono">${esc(a.target || "")}</span>
          <span class="permission-side">
            ${a.live ? `<span class="permission-status granted">live</span>` : `<span class="permission-status">recent</span>`}
            ${a.denied ? `<span class="permission-status denied" title="The app keeps requesting access while the OS answers Deny">denied attempts</span>` : ""}
            ${a.source ? `<span class="permission-scope" title="How Sentinel knows this — the source is the sensor that reported the access, not the app using it">via ${esc(a.source)}</span>` : ""}
            ${a.target ? sensExcludeBtn(a) : ""}
          </span>
          <span class="permission-last-used">${a.live ? "Held at scan time" : a.last_used ? `Last used: ${esc(timeOf(a.last_used))}` : "—"}</span>
          ${a.detail ? `<div class="permission-detail">${esc(a.detail)}</div>` : ""}
        </div>`).join("")}</div>` : ""}
    </article>`;
  }).join("");
  wireSensitiveGroups();
}

function wireSensitiveGroups() {
  document.querySelectorAll("#sensitiveList .sens-app-toggle").forEach((b) =>
    b.addEventListener("click", () => {
      const name = b.dataset.app;
      if (openSensitiveApps.has(name)) openSensitiveApps.delete(name);
      else openSensitiveApps.add(name);
      renderSensitive();
    }));
  wireSensitiveExcludes();
}

// targetExclusionFor finds the per-target exclusion entry (one file/device of
// one app), if any. App matched like exclusionFor; target matched on the full
// string, case-insensitive.
function targetExclusionFor(app, target) {
  const lApp = String(app || "").toLowerCase();
  const lT = String(target || "").toLowerCase();
  if (!lT) return null;
  for (const x of exclusions) {
    const lX = x.app.toLowerCase();
    if (!(lX === lApp || lX.includes(lApp) || lApp.includes(lX))) continue;
    const hit = (x.targets || []).find((t) => String(t.target || "").toLowerCase() === lT);
    if (hit) return hit;
  }
  return null;
}

// sensExcludeBtn is the per-row popup switch: it silences alerts for this one
// app+target pair only — an app holding two sensitive files keeps alerting on
// the other one.
function sensExcludeBtn(a) {
  const on = !!(targetExclusionFor(a.app, a.target)?.watchdog);
  return `<button class="btn ghost small row-action sens-exclude ${on ? "on" : ""}"
    data-app="${esc(a.app)}" data-target="${esc(a.target)}"
    title="${on
      ? "Popups are OFF for this app touching this one target — click to turn them back on"
      : "Turn popups OFF for this app touching this one target only — other targets of the same app still alert"}"
    >${on ? "🔕 popup off" : "🔔 popup on"}</button>`;
}

function wireSensitiveExcludes() {
  document.querySelectorAll("#sensitiveList .sens-exclude").forEach((b) =>
    b.addEventListener("click", async () => {
      const on = !!targetExclusionFor(b.dataset.app, b.dataset.target)?.watchdog;
      try {
        const d = await api("/api/exclusions", {
          method: "POST",
          body: JSON.stringify({ app: b.dataset.app, target: b.dataset.target, field: "watchdog", value: !on }),
        });
        exclusions = d.exclusions || [];
        renderSensitive();
      } catch (e) {
        alert("Could not save the per-file exclusion: " + e.message);
      }
    }));
}

// Exclusions -----------------------------------------------------------------
// The tab lists every app Sentinel has seen anywhere — alert evidence, the
// Live Access snapshot and the App Access inventory — with a checkbox per
// scope. Toggles POST to /api/exclusions; the server persists them and its
// checks enforce them at scan time (watchdog: no alert, no notification).

// prettyAppName collapses raw identifiers (binary paths from lsof/monitor
// evidence, bundle paths) to the name a person recognises: the basename of a
// path, minus a .app extension. Exclusion matching is substring-based on the
// server, so the short form still covers the long one.
function prettyAppName(name) {
  let sName = String(name || "").trim();
  if (sName.startsWith("/")) {
    sName = sName.split("/").filter(Boolean).pop() || sName;
    sName = sName.replace(/\.app$/i, "");
  }
  return sName;
}

function exclusionFor(app) {
  const lApp = app.toLowerCase();
  return exclusions.find((x) => {
    const lX = x.app.toLowerCase();
    return lX === lApp || lX.includes(lApp) || lApp.includes(lX);
  });
}

// namesOverlap mirrors the server's containment match: either name
// containing the other (case-insensitive) counts as the same app.
function namesOverlap(a, b) {
  const la = String(a || "").toLowerCase(), lb = String(b || "").toLowerCase();
  return !!la && !!lb && (la === lb || la.includes(lb) || lb.includes(la));
}

async function loadExclusions() {
  try {
    const d = await api("/api/exclusions");
    exclusions = d.exclusions || [];
  } catch { /* server pre-dating the endpoint */ }
  // the app list needs the inventory + live snapshot; fetch what's missing
  if (!permissionData) {
    try { permissionData = await api("/api/permissions"); } catch { /* optional */ }
  }
  if (!sensitiveData) {
    try { sensitiveData = await api("/api/sensitive"); } catch { /* optional */ }
  }
  renderExclusions();
}

// appSeenNow reports whether an app appears in a CURRENT scan — the Live
// Access snapshot or the App Access inventory (leftover/stale TCC grants of
// uninstalled apps don't count: their permissions are all flagged stale).
// Rows that fail this are likely uninstalled apps whose exclusion rows
// lingered on.
function appSeenNow(name) {
  const ln = String(name || "").toLowerCase();
  if (!ln) return false;
  const overlaps = (v) => {
    const lv = String(v || "").toLowerCase();
    return !!lv && (lv === ln || lv.includes(ln) || ln.includes(lv));
  };
  if ((sensitiveData?.access || []).some((a) => overlaps(a.app))) return true;
  const papp = (permissionData?.apps || []).find((a) => overlaps(a.name) || overlaps(a.identifier));
  if (!papp) return false;
  const perms = papp.permissions || [];
  return perms.length === 0 || perms.some((p) => !p.stale);
}

// uninstalledExcludedApps lists the persisted exclusion rows whose apps no
// current scan sees — the dead weight Remove not-installed deletes. Rows
// hidden by their own live/app_access exclusion are not "uninstalled" (the
// exclusion itself hides them from the scans) and stay out of this list.
function uninstalledExcludedApps() {
  const out = [];
  for (const x of exclusions) {
    const name = prettyAppName(x.app);
    if (!name || x.live || x.app_access || appSeenNow(name)) continue;
    out.push({ name, raw: String(x.app || "").trim() });
  }
  return out;
}

function renderExclusions() {
  const byKey = new Map();
  const add = (raw, scope) => {
    const name = prettyAppName(raw);
    if (!name) return;
    const key = name.toLowerCase();
    const row = byKey.get(key) || { name, full: String(raw || "").trim(), scopes: new Set() };
    if (scope) row.scopes.add(scope);
    if (name.length < row.name.length) row.name = name; // shortest form wins
    byKey.set(key, row);
  };
  for (const a of alerts) add(evidenceApp(a), "watchdog");
  for (const a of (sensitiveData?.access || [])) add(a.app, "live");
  for (const app of (permissionData?.apps || [])) {
    add(app.name, "app_access");
    // path-form identifiers add nothing once the name row exists
    if (app.identifier && !String(app.identifier).startsWith("/") &&
        app.identifier.toLowerCase() !== String(app.name).toLowerCase()) {
      add(app.identifier, "");
    }
  }
  for (const x of exclusions) add(x.app, ""); // keep persisted rows visible

  const query = $("#exclusionSearch").value.trim().toLowerCase();
  const scopeSel = $("#exclusionScope").value;
  const stateSel = $("#exclusionState").value;
  // apps the watchdog is alerting on lead the list — they are the ones the
  // user is here to silence; the full app inventory follows after them
  const firing = (name) => alerts.some((a) => !a.acked && namesOverlap(evidenceApp(a), name));
  const alerted = (name) => alerts.some((a) => namesOverlap(evidenceApp(a), name));
  const rank = (r) => firing(r.name) ? 0 : alerted(r.name) ? 1 : 2;
  // Apps no current scan sees are dead weight here (probably uninstalled):
  // their rows are hidden — the exclusion itself keeps working, and the app's
  // return to a scan brings the row back. Exception: a live/app_access
  // exclusion hides the app from those very scans, so such rows must stay
  // visible or they could never be unticked. The "Not seen (uninstalled)"
  // state filter is the reveal switch for reviewing what's hidden.
  const selfHidden = (name) => {
    const x = exclusionFor(name);
    return !!x && (x.live || x.app_access);
  };
  const notSeenNow = (name) => !selfHidden(name) && !appSeenNow(name);
  const anyTick = (x) => !!x && (x.watchdog || x.auto_ack || x.live || x.app_access ||
    (x.targets || []).some((t) => t.watchdog || t.live));
  const matchesScope = (r) => {
    if (!scopeSel) return true;
    const x = exclusionFor(r.name);
    if (scopeSel === "none") return !anyTick(x);
    if (scopeSel === "watchdog") return !!x?.watchdog || (x?.targets || []).some((t) => t.watchdog);
    if (scopeSel === "auto_ack") return !!x?.auto_ack;
    if (scopeSel === "live") return !!x?.live || (x?.targets || []).some((t) => t.live);
    if (scopeSel === "app_access") return !!x?.app_access;
    return true;
  };
  const matchesState = (r) => {
    if (stateSel === "firing") return firing(r.name);
    if (stateSel === "excluded") return anyTick(exclusionFor(r.name));
    if (stateSel === "unexcluded") return !anyTick(exclusionFor(r.name));
    if (stateSel === "notseen") return notSeenNow(r.name);
    return true;
  };
  const notseenView = stateSel === "notseen";
  const rows = [...byKey.values()]
    .filter(matchesScope)
    .filter(matchesState)
    .filter((r) => !query || r.name.toLowerCase().includes(query))
    .filter((r) => notseenView || selfHidden(r.name) || appSeenNow(r.name))
    .sort((a, b) => rank(a) - rank(b) ||
      a.name.localeCompare(b.name, undefined, { sensitivity: "base" }));
  const hasFilters = Boolean(query || scopeSel || stateSel);
  $("#clearExclusionFilters").disabled = !hasFilters;

  const notSeen = uninstalledExcludedApps();
  const cbtn = $("#exclusionCleanup");
  if (cbtn) {
    cbtn.disabled = !notSeen.length;
    cbtn.textContent = notSeen.length
      ? `🗑 Remove not-installed (${notSeen.length})`
      : "🗑 Remove not-installed";
    cbtn.title = notSeen.length
      ? `Delete the exclusion rows of ${notSeen.length} app(s) no current scan sees — probably uninstalled.`
      : "No exclusion rows for apps that current scans can't see.";
  }

  if (!rows.length) {
    $("#exclusionList").innerHTML = `<p class="muted">${hasFilters
      ? "No apps match these filters."
      : "No apps seen in current scans — anything else here is uninstalled or hidden by exclusions. Purge hidden rows with Remove not-installed."}</p>`;
    return;
  }
  const scopeLabel = (scopes) => [...scopes].map((x) => x === "watchdog" ? "alerts"
    : x === "auto_ack" ? "auto-ack"
    : x === "live" ? "live access" : x === "app_access" ? "app access" : x).join(" · ")
    || "seen in exclusions";
  const box = (app, field, x) => `
    <input type="checkbox" data-app="${esc(app)}" data-field="${field}"
      title="${field === "watchdog" ? "No alerts or notifications for this app"
        : field === "auto_ack" ? "This app's alerts are recorded pre-acked — history only, never a popup"
        : field === "live" ? "Hide this app from the Live Access tab"
        : "Hide this app from the App Access tab"}"
      ${x?.[field === "app_access" ? "app_access" : field] ? "checked" : ""}>`;
  const targetRows = (app, x) => {
    // the row that owns the exclusion renders its targets; overlapping-name
    // rows (e.g. "Code Helper" for a "ZCode Helper" exclusion) only carry
    // the scope checkboxes, not a duplicate target list
    if (!x || !(x.targets || []).length || x.app.toLowerCase() !== app.toLowerCase()) return "";
    const targets = x.targets || [];
    return `<tr class="ex-targets"><td colspan="5">
      <div class="muted small ex-target-head">Per-target exclusions — apply to this app touching this one path only:</div>
      ${targets.map((t) => `
        <div class="ex-target">
          <span class="ex-target-path mono" title="${esc(t.target)}">${esc(t.target)}</span>
          <label class="chk" title="No popup when this app touches this one path">
            <input type="checkbox" class="ex-target-box" data-app="${esc(app)}" data-target="${esc(t.target)}" data-field="watchdog" ${t.watchdog ? "checked" : ""}> no popup</label>
          <label class="chk" title="Hide this one row from the Live Access tab">
            <input type="checkbox" class="ex-target-box" data-app="${esc(app)}" data-target="${esc(t.target)}" data-field="live" ${t.live ? "checked" : ""}> hide row</label>
          <button class="btn ghost small row-action danger ex-target-del" data-app="${esc(app)}"
            data-target="${esc(t.target)}"
            title="Remove this per-target exclusion (the app's other rows are untouched)">🗑</button>
        </div>`).join("")}
    </td></tr>`;
  };
  $("#exclusionList").innerHTML = `
    <table class="exclusion-table">
      <thead><tr><th>App name</th><th>Watchdog</th><th>Auto-ack</th><th>Live Access</th><th>App Access</th></tr></thead>
      <tbody>${rows.map((r) => {
        const x = exclusionFor(r.name);
        return `<tr>
          <td><div class="ex-app-line">
            <div class="ex-app-wrap" title="${esc(r.full)}">
              <div class="ex-app">${esc(r.name)}
                ${firing(r.name) ? `<span class="permission-status denied" title="This app has unacked watchdog alerts right now — ticking Watchdog (or the alert's 🔕 button) silences them">watchdog firing</span>` : ""}</div>
              <div class="ex-sub muted small">${esc(scopeLabel(r.scopes))}</div>
            </div>
            <button class="btn ghost small row-action danger ex-del" data-app="${esc(r.name)}"
              title="Delete this exclusion row entirely (scopes and per-target entries)">🗑</button>
          </div>
            ${notSeenNow(r.name) ? `<div class="permission-stale" title="No current scan sees this app — probably uninstalled, or only present in older alert history. Remove not-installed purges rows that carry a stored exclusion.">not seen in current scans</div>` : ""}</td>
          <td>${box(r.name, "watchdog", x)}</td>
          <td>${box(r.name, "auto_ack", x)}</td>
          <td>${box(r.name, "live", x)}</td>
          <td>${box(r.name, "app_access", x)}</td>
        </tr>${targetRows(r.name, x)}`;
      }).join("")}</tbody>
    </table>`;
  wireExclusions();
}

function wireExclusions() {
  document.querySelectorAll("#exclusionList input[type='checkbox']").forEach((b) =>
    b.addEventListener("change", async () => {
      const body = { app: b.dataset.app, field: b.dataset.field, value: b.checked };
      if (b.classList.contains("ex-target-box")) body.target = b.dataset.target;
      try {
        const d = await api("/api/exclusions", { method: "POST", body: JSON.stringify(body) });
        exclusions = d.exclusions || [];
        renderExclusions();
        // per-target "hide row" changes what Live Access shows — refresh it too
        if (body.target && body.field === "live") loadSensitive();
      } catch (e) {
        alert("Could not save exclusion: " + e.message);
        b.checked = !b.checked;
      }
    }));
  document.querySelectorAll("#exclusionList .ex-del").forEach((b) =>
    b.addEventListener("click", async () => {
      if (!confirm(`Delete the exclusion row for ${b.dataset.app}?\n\nIts scope ticks and per-target entries are removed. This does not change the app itself.`)) return;
      try {
        const d = await api("/api/exclusions", { method: "POST", body: JSON.stringify({ app: b.dataset.app, remove: true }) });
        exclusions = d.exclusions || [];
        renderExclusions();
      } catch (e) {
        alert("Could not delete exclusion: " + e.message);
      }
    }));
  document.querySelectorAll("#exclusionList .ex-target-del").forEach((b) =>
    b.addEventListener("click", async () => {
      try {
        const d = await api("/api/exclusions", {
          method: "POST",
          body: JSON.stringify({ app: b.dataset.app, target: b.dataset.target, remove: true }),
        });
        exclusions = d.exclusions || [];
        renderExclusions();
        loadSensitive();
      } catch (e) {
        alert("Could not delete the per-target exclusion: " + e.message);
      }
    }));
  const cbtn = $("#exclusionCleanup");
  if (cbtn && !cbtn.dataset.wired) {
    cbtn.dataset.wired = "1";
    cbtn.addEventListener("click", async () => {
      const dead = uninstalledExcludedApps();
      if (!dead.length) {
        alert("Nothing to remove — every exclusion row belongs to an app a current scan still sees.\n\n" +
          "Apps that show up only through old alert history carry no exclusion row, so there is nothing " +
          "stored to delete: they are hidden from this list automatically and only reappear if a scan " +
          "sees them again.");
        return;
      }
      const names = dead.map((d) => d.name);
      if (!confirm(`Delete exclusion rows for ${names.length} app(s) no current scan sees (probably uninstalled)?\n\n${names.join(", ")}`)) return;
      let removed = 0;
      for (const d of dead) {
        try {
          const resp = await api("/api/exclusions", { method: "POST", body: JSON.stringify({ app: d.raw, remove: true }) });
          exclusions = resp.exclusions || exclusions;
          removed++;
        } catch { /* keep going through the list */ }
      }
      if (removed < dead.length) alert(`Removed ${removed} of ${dead.length} rows — the rest failed; try again.`);
      renderExclusions();
    });
  }
}


async function loadSensitive() {
  // refreshes (SSE-triggered or manual) must not yank the reader back to
  // the top: remember the scroll position and restore it after re-render
  const refreshing = sensitiveData !== null;
  const scrollY = refreshing ? window.scrollY : 0;
  if (!refreshing) $("#sensitiveList").innerHTML = `<p class="muted">Scanning live access…</p>`;
  try {
    // the per-row popup switches read the exclusion state — keep it fresh
    try { exclusions = (await api("/api/exclusions")).exclusions || exclusions; } catch { /* older server */ }
    sensitiveData = await api("/api/sensitive");
    renderSensitive();
    if (refreshing) window.scrollTo(0, scrollY);
  } catch (e) {
    if (!refreshing) {
      $("#sensitiveList").innerHTML = `<p class="permission-warning">Could not load live access: ${esc(e.message)}</p>`;
    }
  }
}


// permissionRowActions returns the remediation buttons for one permission row:
// Remove for macOS TCC grants, Block/Allow/Remove-rule for firewall rules
// (macOS: incoming only; Windows: incoming + outgoing), and Unload & delete
// for third-party root daemons/helpers.
function permissionRowActions(app, p) {
  if (p.source === "macOS TCC" && p.service) {
    const canRemove = p.db === "system" ||
      (p.db === "user" && permissionData.can_modify_tcc);
    const readOnlyReason = p.db === "system"
      ? "Remove this system grant using the macOS administrator authorization prompt."
      : "This process cannot write to the user TCC database. Grant Sentinel's terminal Full Disk Access to enable removal.";
    const title = p.db === "system"
      ? "Remove this system grant after administrator authorization (backup saved first)"
      : canRemove ? "Remove this grant from the TCC database (backup saved first)" : readOnlyReason;
    return `<button class="btn ghost small row-action danger" data-kind="tcc"
      data-client="${esc(app.identifier)}" data-service="${esc(p.service)}"
      data-label="${esc(p.name)}" title="${title}"
      ${canRemove ? "" : "disabled"}>Remove</button>`;
  }
  if (p.source === "System daemon/helper" && app.path) {
    const target = p.target || app.path;
    const isPlist = target.endsWith(".plist");
    return `<button class="btn ghost small row-action warn" data-kind="daemon"
      data-path="${esc(target)}"
      title="${isPlist ? "Unload from launchd and delete this file" : "Delete this helper file"} — administrator approval required">${isPlist ? "Unload & delete" : "Delete"}</button>`;
  }
  if (p.source === "macOS firewall" && app.path) {
    const guarded = !guardrailsOff && systemPathProtected(app.path);
    return fwBtn(p.status === "block" ? "allow" : "block", "in", app, guarded) +
      fwBtn("remove", "in", app, guarded);
  }
  if (p.source === "Windows firewall" && app.path &&
      app.identifier !== "windows.defender.firewall") {
    const dir = p.dir === "out" ? "out" : "in";
    return fwBtn(p.status === "block" ? "allow" : "block", dir, app, false) +
      fwBtn("remove", dir, app, false);
  }
  return "";
}

function fwBtn(action, dir, app, guarded) {
  const label = { block: "Block", allow: "Allow", remove: "Remove rule" }[action];
  const guardNote = guarded
    ? " — blocked by Guardrails (macOS system software); turn Guardrails off to proceed"
    : "";
  return `<button class="btn ghost small row-action ${action === "remove" ? "danger" : ""}"
    data-kind="fw" data-action="${action}" data-dir="${dir}" data-path="${esc(app.path)}"
    data-name="${esc(app.name)}" title="${esc(label + guardNote)}"
    ${guarded ? "disabled" : ""}>${label}</button>`;
}

// systemPathProtected mirrors remediation.go's systemPathPrefixes so the UI
// can disable firewall buttons for macOS system software before the server
// refuses them.
const SYSTEM_PATH_PREFIXES = ["/System", "/usr", "/bin", "/sbin", "/private/var/db"];
function systemPathProtected(path) {
  const p = String(path || "");
  return SYSTEM_PATH_PREFIXES.some((pre) => p === pre || p.startsWith(pre + "/"));
}

function wirePermissionActions(container) {
  document.querySelectorAll(`${container} .row-action`).forEach((b) =>
    b.addEventListener("click", async () => {
      const kind = b.dataset.kind;
      const url = kind === "tcc" ? "/api/permissions/remove"
        : kind === "daemon" ? "/api/daemon/remove" : "/api/firewall/rule";
      const body = kind === "tcc"
        ? { client: b.dataset.client, service: b.dataset.service }
        : kind === "daemon"
          ? { path: b.dataset.path }
          : { action: b.dataset.action, dir: b.dataset.dir, path: b.dataset.path };
      body.override = guardrailsOff;
      const dirWord = body.dir === "out" ? "outgoing" : "incoming";
      const question = (kind === "tcc"
        ? `Remove the ${b.dataset.label} grant for ${b.dataset.client}?\n\n` +
          "This deletes the row from the TCC database (a backup row is saved first)."
        : kind === "daemon"
          ? `Unload and delete ${b.dataset.path}?\n\n` +
            "Administrator approval will be requested. The file is deleted permanently."
          : `${{ block: "Block", allow: "Allow", remove: "Remove the firewall rule for" }[body.action]} ` +
            `${dirWord} connections for ${b.dataset.name}?\n\n` +
            "You will be prompted for administrator approval (macOS password dialog / Windows UAC).") +
        (guardrailsOff ? "\n\n⚠️ Guardrails are OFF: Apple/system targets will not be refused." : "");
      if (!confirm(question)) return;
      try {
        const resp = await fetch(url, { method: "POST", body: JSON.stringify(body) });
        const data = await resp.json().catch(() => ({}));
        if (!resp.ok || data.error) {
          alert("Failed: " + (data.error || resp.status));
          return;
        }
        alert(data.message || "Done — refresh shows the change.");
        loadPermissions();
      } catch (e) {
        alert("Request failed: " + e.message);
      }
    }));
}

// updateRemovalHelp fills the terminal-commands panel once, per platform —
// every button's equivalent command, so nothing is UI-only.
let removalHelpFilled = false;
function updateRemovalHelp(platform) {
  if (removalHelpFilled || !platform) return;
  removalHelpFilled = true;
  const os = String(platform).split("/")[0];
  const darwin = `Terminal equivalents for every action the buttons take.

REMOVE (TCC grant rows) — deletes the row from the TCC database; the terminal
itself needs Full Disk Access for this:
  sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" \\
    "delete from access where client='<bundle-id>' and service='<kTCCService…>';"
System-wide grants live in the root-owned database:
  sudo sqlite3 "/Library/Application Support/com.apple.TCC/TCC.db" \\
    "delete from access where client='<bundle-id>' and service='<kTCCService…>';"

tccutil — only works for apps LaunchServices still knows (uninstalled apps
fail with -10814; use the sqlite3 commands above for those):
  tccutil reset <ServiceName> <bundle-id>     # e.g. SystemPolicyAllFiles com.example.app
NOTE: reset WITHOUT a bundle id cannot target a single app — it resets ALL
apps' preferences for that service (they re-prompt on next use).
The system TCC database is SIP-protected: the sudo sqlite3 delete above only
works with SIP disabled (Recovery OS), even as root.

BLOCK / ALLOW / REMOVE RULE (firewall rows) — incoming only on macOS:
  sudo /usr/libexec/ApplicationFirewall/socketfilterfw --blockapp "/Applications/App.app"
  sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp "/Applications/App.app"
  sudo /usr/libexec/ApplicationFirewall/socketfilterfw --remove "/Applications/App.app"

UNLOAD & DELETE (LaunchDaemons / LaunchAgents) — unload, then remove the file:
  sudo launchctl bootout system /Library/LaunchDaemons/<name>.plist   # system daemons
  launchctl bootout gui/$(id -u) /Library/LaunchAgents/<name>.plist   # per-user agents
  sudo rm /Library/LaunchDaemons/<name>.plist

DELETE (PrivilegedHelperTools binaries — plain files, nothing to unload):
  sudo rm /Library/PrivilegedHelperTools/<name>`;
  const windows = `Terminal equivalents for every action the buttons take
(elevated PowerShell).

BLOCK / ALLOW / REMOVE RULE (firewall rows):
  New-NetFirewallRule -DisplayName "Sentinel block <name> (in)" -Direction Inbound -Action Block -Program "C:\\path\\app.exe"
  New-NetFirewallRule -DisplayName "Sentinel allow <name> (in)" -Direction Inbound -Action Allow -Program "C:\\path\\app.exe"
  New-NetFirewallRule -DisplayName "Sentinel block <name> (out)" -Direction Outbound -Action Block -Program "C:\\path\\app.exe"
  Remove-NetFirewallRule -DisplayName "Sentinel block <name> (in)","Sentinel allow <name> (out)"

Profiles and their default allow/block policies (the "allow all in/out" switches):
  wf.msc`;
  const other = `Firewall inspection and manual rules — packet filters match ports
and interfaces, not applications, so there are no per-app rules.

Linux:
  ufw status verbose
  sudo ufw deny in from any to any port <port>
  sudo ufw allow out <port>
  sudo nft list ruleset          # or: sudo iptables -L -n -v
BSD:
  sudo pfctl -s info
  sudo pfctl -s rules`;
  const text = os === "darwin" ? darwin : os === "windows" ? windows : other;
  $("#removalHelpBody").textContent = text;
}

async function loadPermissions() {
  $("#permissionList").innerHTML = `<p class="muted">Loading app access inventory…</p>`;
  $("#firewallList").innerHTML = `<p class="muted">Loading firewall rules…</p>`;
  try {
    permissionData = await api("/api/permissions");
    renderPermissions();
  } catch (e) {
    $("#permissionList").innerHTML = `<p class="permission-warning">Could not load app access inventory: ${esc(e.message)}</p>`;
    $("#firewallList").innerHTML = `<p class="permission-warning">Could not load firewall rules: ${esc(e.message)}</p>`;
  }
}

function selectView(view) {
  const permissions = view === "permissions";
  const firewall = view === "firewall";
  const sensitive = view === "sensitive";
  const exclusions = view === "exclusions";
  $("#dashboardView").hidden = permissions || firewall || sensitive || exclusions;
  $("#permissionsView").hidden = !permissions;
  $("#firewallView").hidden = !firewall;
  $("#sensitiveView").hidden = !sensitive;
  $("#exclusionsView").hidden = !exclusions;
  $("#dashboardTab").classList.toggle("selected", !permissions && !firewall && !sensitive && !exclusions);
  $("#permissionsTab").classList.toggle("selected", permissions);
  $("#firewallTab").classList.toggle("selected", firewall);
  $("#sensitiveTab").classList.toggle("selected", sensitive);
  $("#exclusionsTab").classList.toggle("selected", exclusions);
  $("#dashboardTab").setAttribute("aria-selected", String(!permissions && !firewall && !sensitive && !exclusions));
  $("#permissionsTab").setAttribute("aria-selected", String(permissions));
  $("#firewallTab").setAttribute("aria-selected", String(firewall));
  $("#sensitiveTab").setAttribute("aria-selected", String(sensitive));
  $("#exclusionsTab").setAttribute("aria-selected", String(exclusions));
  if ((permissions || firewall) && !permissionData) loadPermissions();
  if (sensitive) loadSensitive();
  if (exclusions) loadExclusions();
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
$("#alertApp").addEventListener("change", (e) => { alertAppFilter = e.target.value; renderAlerts(); });
$("#hideAcked").addEventListener("change", (e) => { alertFilter.hideAcked = e.target.checked; renderAlerts(); });
$("#dashboardTab").addEventListener("click", () => selectView("dashboard"));
$("#sensitiveTab").addEventListener("click", () => selectView("sensitive"));
$("#permissionsTab").addEventListener("click", () => selectView("permissions"));
$("#firewallTab").addEventListener("click", () => selectView("firewall"));
$("#exclusionsTab").addEventListener("click", () => selectView("exclusions"));
  $("#refreshExclusions").addEventListener("click", loadExclusions);
  $("#exclusionSearch").addEventListener("input", renderExclusions);
  $("#exclusionScope").addEventListener("change", renderExclusions);
  $("#exclusionState").addEventListener("change", renderExclusions);
  $("#clearExclusionFilters").addEventListener("click", () => {
    $("#exclusionSearch").value = "";
    $("#exclusionScope").value = "";
    $("#exclusionState").value = "";
    renderExclusions();
  });
$("#refreshPermissions").addEventListener("click", loadPermissions);
$("#refreshFirewall").addEventListener("click", loadPermissions);
$("#refreshSensitive").addEventListener("click", loadSensitive);
$("#sensitiveSearch").addEventListener("input", renderSensitive);
$("#sensitiveApp").addEventListener("change", renderSensitive);
$("#sensitiveKind").addEventListener("change", renderSensitive);
$("#sensitiveLiveOnly").addEventListener("change", renderSensitive);
$("#sensitiveSummary").addEventListener("click", (e) => {
  const liveBtn = e.target.closest("[data-sens-live]");
  if (liveBtn) {
    const box = $("#sensitiveLiveOnly");
    box.checked = !box.checked;
    renderSensitive();
    return;
  }
  const button = e.target.closest("[data-sens-kind]");
  if (!button) return;
  $("#sensitiveKind").value = button.dataset.sensKind || "";
  renderSensitive();
});
$("#clearSensitiveFilters").addEventListener("click", () => {
  $("#sensitiveSearch").value = "";
  $("#sensitiveApp").value = "";
  $("#sensitiveKind").value = "";
  $("#sensitiveLiveOnly").checked = false;
  renderSensitive();
});
$("#toggleSensitiveGroups").addEventListener("click", () => {
  if (!sensitiveData) return;
  const apps = [...new Set((sensitiveData.access || []).map((a) => a.app))];
  if (apps.some((a) => !openSensitiveApps.has(a))) {
    apps.forEach((a) => openSensitiveApps.add(a));
  } else {
    openSensitiveApps.clear();
  }
  renderSensitive();
});
$("#togglePermissionGroups").addEventListener("click", () => {
  if (!permissionData) return;
  const keys = (permissionData.apps || [])
    .filter((a) => (a.permissions || []).some((p) => !isFirewallPermission(p)))
    .map((a) => String(a.identifier || a.name));
  if (keys.some((k) => !openPermissionApps.has(k))) {
    keys.forEach((k) => openPermissionApps.add(k));
  } else {
    openPermissionApps.clear();
  }
  renderPermissions();
});
document.querySelectorAll(".guardrail-toggle").forEach((b) =>
  b.addEventListener("click", () => {
    guardrailsOff = !guardrailsOff;
    document.querySelectorAll(".guardrail-toggle").forEach((t) => {
      t.textContent = guardrailsOff ? "⚠️ Guardrails off" : "🛡 Guardrails on";
      t.classList.toggle("guard-off", guardrailsOff);
      t.setAttribute("aria-pressed", String(!guardrailsOff));
    });
    renderPermissions();
  }));
$("#permissionSearch").addEventListener("input", renderPermissions);
$("#permissionCategory").addEventListener("change", renderPermissions);
$("#permissionStatus").addEventListener("change", renderPermissions);
$("#permissionSource").addEventListener("change", renderPermissions);
$("#firewallSearch").addEventListener("input", renderFirewall);
$("#firewallStatus").addEventListener("change", renderFirewall);
$("#firewallSource").addEventListener("change", renderFirewall);
$("#firewallDirection").addEventListener("change", renderFirewall);
$("#permissionSummary").addEventListener("click", (e) => {
  const button = e.target.closest("[data-permission-status]");
  if (!button) return;
  if (button.dataset.permissionStatus) {
    $("#permissionStatus").value = button.dataset.permissionStatus;
  } else {
    $("#permissionSearch").value = "";
    $("#permissionCategory").value = "";
    $("#permissionStatus").value = "";
    $("#permissionSource").value = "";
  }
  renderPermissions();
  $("#permissionList").scrollIntoView({ behavior: "smooth", block: "start" });
});
$("#clearPermissionFilters").addEventListener("click", () => {
  $("#permissionSearch").value = "";
  $("#permissionCategory").value = "";
  $("#permissionStatus").value = "";
  $("#permissionSource").value = "";
  renderPermissions();
});
$("#clearFirewallFilters").addEventListener("click", () => {
  $("#firewallSearch").value = "";
  $("#firewallStatus").value = "";
  $("#firewallSource").value = "";
  $("#firewallDirection").value = "";
  renderFirewall();
});
$("#alertCheck").addEventListener("change", (e) => { alertFilter.check = e.target.value; renderAlerts(); });
$("#alertState").addEventListener("change", (e) => { alertFilter.state = e.target.value; renderAlerts(); });
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
      // Live Access mirrors the fast scan cadence while its tab is open
      if (msg.type === "scan" && !$("#sensitiveView").hidden) loadSensitive();
    }
  };
  es.onerror = () => { es.close(); setTimeout(connectSSE, 4000); };
}

// boot ----------------------------------------------------------------------
(async () => {
  await loadStatus();
  await loadAlerts();
  // exclusion state for the alert rows' 🔕 buttons (light fetch; the
  // Exclusions tab loads the full inventory on open as before)
  api("/api/exclusions").then((d) => { exclusions = d.exclusions || []; renderAlerts(); }).catch(() => {});
  connectSSE();
  setInterval(loadStatus, 30000);
})().catch((e) => {
  document.body.innerHTML = `<p style="padding:40px">Sentinel API unreachable: ${esc(e.message)}</p>`;
});

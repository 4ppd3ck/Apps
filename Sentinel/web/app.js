// Sentinel dashboard — vanilla JS, SSE live updates, no build step.
"use strict";

const $ = (s) => document.querySelector(s);
const SEVS = ["critical", "high", "medium", "low", "info"];
let status = null;
let alerts = [];
let alertFilter = { sev: "", hideAcked: true };
let seenIds = new Set();
let permissionData = null;

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

  $("#permissionWarnings").innerHTML = (Array.isArray(permissionData.warnings) ? permissionData.warnings : [])
    .filter((warning) => !String(warning || "").toLowerCase().includes("firewall"))
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
  $("#permissionList").innerHTML = filtered.map(({ app, permissions }) => `
    <article class="permission-app">
      <div class="permission-app-head">
        <div><h3>${esc(app.name)}</h3>
          <div class="permission-app-meta">${esc(app.identifier)}${app.path ? ` · ${esc(app.path)}` : ""}</div></div>
        <span class="tag">${esc(app.source || "unknown source")}</span>
      </div>
      ${permissions.length ? `<div class="permission-rows">${permissions.map((p) => `
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
        </div>`).join("")}</div>` : `<p class="muted small no-permissions">No permission grants reported by this platform source.</p>`}
    </article>`).join("");
  wirePermissionActions("#permissionList");
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

  $("#firewallWarnings").innerHTML = (Array.isArray(permissionData.warnings) ? permissionData.warnings : [])
    .filter((warning) => String(warning || "").toLowerCase().includes("firewall"))
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
    return fwBtn(p.status === "block" ? "allow" : "block", "in", app) +
      fwBtn("remove", "in", app);
  }
  if (p.source === "Windows firewall" && app.path &&
      app.identifier !== "windows.defender.firewall") {
    const dir = p.dir === "out" ? "out" : "in";
    return fwBtn(p.status === "block" ? "allow" : "block", dir, app) +
      fwBtn("remove", dir, app);
  }
  return "";
}

function fwBtn(action, dir, app) {
  const label = { block: "Block", allow: "Allow", remove: "Remove rule" }[action];
  return `<button class="btn ghost small row-action ${action === "remove" ? "danger" : ""}"
    data-kind="fw" data-action="${action}" data-dir="${dir}" data-path="${esc(app.path)}"
    data-name="${esc(app.name)}">${label}</button>`;
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
      const dirWord = body.dir === "out" ? "outgoing" : "incoming";
      const question = kind === "tcc"
        ? `Remove the ${b.dataset.label} grant for ${b.dataset.client}?\n\n` +
          "This deletes the row from the TCC database (a backup row is saved first)."
        : kind === "daemon"
          ? `Unload and delete ${b.dataset.path}?\n\n` +
            "Administrator approval will be requested. The file is deleted permanently."
          : `${{ block: "Block", allow: "Allow", remove: "Remove the firewall rule for" }[body.action]} ` +
            `${dirWord} connections for ${b.dataset.name}?\n\n` +
            "You will be prompted for administrator approval (macOS password dialog / Windows UAC).";
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
  $("#dashboardView").hidden = permissions || firewall;
  $("#permissionsView").hidden = !permissions;
  $("#firewallView").hidden = !firewall;
  $("#dashboardTab").classList.toggle("selected", !permissions && !firewall);
  $("#permissionsTab").classList.toggle("selected", permissions);
  $("#firewallTab").classList.toggle("selected", firewall);
  $("#dashboardTab").setAttribute("aria-selected", String(!permissions && !firewall));
  $("#permissionsTab").setAttribute("aria-selected", String(permissions));
  $("#firewallTab").setAttribute("aria-selected", String(firewall));
  if ((permissions || firewall) && !permissionData) loadPermissions();
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
$("#dashboardTab").addEventListener("click", () => selectView("dashboard"));
$("#permissionsTab").addEventListener("click", () => selectView("permissions"));
$("#firewallTab").addEventListener("click", () => selectView("firewall"));
$("#refreshPermissions").addEventListener("click", loadPermissions);
$("#refreshFirewall").addEventListener("click", loadPermissions);
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

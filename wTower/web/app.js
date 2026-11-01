/* wTower dashboard */
"use strict";

const $ = (id) => document.getElementById(id);
/* sort registries shared by every sortable table (declared first: the
   clickSort registrations below run during script evaluation) */
const DEST_COLS = ["name", "ip", "apps", "ips", "connections", "open",
  "seconds", "bytes_in", "bytes_out", "last_seen"];
const NUMERIC_SORT_COLS = new Set(["ips", "connections", "open", "seconds",
  "bytes_in", "bytes_out", "last_seen", "pid", "established", "ok", "closed",
  "internal", "external", "count", "ts", "started", "duration_secs",
  "vstarted", "vended", "span", "active"]);
/* sub-table (detail) column lists: declared with the other sort registries
   because the clickSubSort registrations below run during script evaluation */
const IP_SUB_COLS = [["geo", "Geo"], ["ip", "IP"], ["apps", "Apps"],
  ["connections", "Connections"], ["open", "Active"],
  ["seconds", "Time connected"], ["bytes_in", "↓ In"], ["bytes_out", "↑ Out"],
  ["last_seen", "Last seen"]];
const SITE_SUB_COLS = [["name", "Site"], ["ips", "IPs"],
  ["connections", "Connections"], ["open", "Active"],
  ["seconds", "Time connected"], ["bytes_in", "↓ In"], ["bytes_out", "↑ Out"],
  ["last_seen", "Last seen"]];
const HISTORY_SUB_COLS = [["started", "First observed"], ["status", "Status"],
  ["protocol", "Protocol"], ["state", "State"], ["local", "Local endpoint"],
  ["remote", "Remote endpoint"], ["geo", "Geo"], ["duration_secs", "Duration"],
  ["scope", "Scope"], ["last_seen", "Last seen"]];
const LIVE_SUB_COLS = [["app", "App"], ["pid", "PID"], ["user", "User"],
  ["proto", "Protocol"], ["remote", "Remote"], ["service", "Service / Host"],
  ["local", "Local"], ["geo", "Geo"], ["duration", "Duration"],
  ["bytes_in", "↓ In"], ["bytes_out", "↑ Out"], ["state", "State"], ["", "Block"]];

const state = {
  paused: false,
  lastPrivacy: null,   // {ts, text} for the camera/mic card
  histMinutes: 60,     // default/global history window
  panelMinutes: {},    // per event panel override
  scopeConns: "",
  scopeNetwork: "",
  appConns: "",        // app-name filter for saved connection history
  protocolConns: "",
  statusConns: "",
  liveConnections: [],
  liveGroupBy: "app",  // "app": one expandable row per process, "flat": one row per connection
  expandedLiveGroups: new Set(),
  visibleLiveGroupKeys: [],
  destinations: { countries: [], sites: [], apps: [] },
  destinationsRequest: 0,
  ownCountry: "",
  sitesGroupBy: "site",
  expandedDestGroups: new Set(),
  visibleSiteGroupKeys: [],
  countriesMode: "country",
  expandedCountryGroups: new Set(),
  visibleCountryGroupKeys: [],
  sortGeo: { col: "bytes_in", dir: -1 },
  sortGeoSub: { col: "bytes_in", dir: -1 },    // IP rows inside a country group
  sortSites: { col: "bytes_in", dir: -1 },
  sortSitesSub: { col: "bytes_in", dir: -1 },  // detail rows inside a site/app group
  sortLive: { col: null, dir: 1 },
  sortLiveSub: { col: null, dir: 1 },          // connections inside a live app group
  sortBlocks: { col: "ts", dir: -1 },
  sortDnsRules: { col: "ts", dir: -1 },
  sortVisits: { col: "vstarted", dir: -1 },
  sortConnSummary: { col: null, dir: 1 },
  sortHistory: { col: "last", dir: -1 },
  sortHistorySub: { col: "last_seen", dir: -1 }, // observations inside a process group
  tableVisibility: {},
  dashboardLayout: null,
  trafficTotals: null,
  trafficHistory: [],  // last chart sample set (redrawn on resize/hover)
  connectionHistory: [],
  connectionHistoryRequest: 0,
  expandedConnectionGroups: new Set(),
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

// Detail-only text filters: tables with a `detail-<t>` input, mapped to the
// index of their Detail column (file: time,kind,app,user,path,detail;
// network: time,kind,app,user,protocol,remote,scope,detail).
const DETAIL_FILTER_COLS = { file: 5, network: 7 };

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
    addClearFiltersButton(holder, () => clearEventTableFilters(t));
  }
}

function addClearFiltersButton(holder, onClear) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "purge-btn clear-filters-btn";
  button.textContent = "Clear filters";
  button.title = "clear filters without changing the selected time range";
  button.addEventListener("click", onClear);
  holder.append(button);
}

function clearEventTableFilters(table) {
  state.filters[table] = { app: "", kind: "", user: "" };
  for (const definition of FILTER_DEFS) {
    const select = $(`f-${table}-${definition.key}`);
    if (select) select.value = "";
  }
  const query = $(`filter-${table}`);
  if (query) query.value = "";
  const detail = $(`detail-${table}`);
  if (detail) detail.value = "";
  if (table === "network") {
    state.scopeNetwork = "";
    $("scope-network").value = "";
  }
  const tableId = `tbl-${table}`;
  for (const row of $(`${tableId}`).tBodies[0].rows) applyFilter(tableId, row);
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

/* ------------------------------------------------------------- themes -- */
let appliedThemeKeys = [];
let themeMessageTimer = 0;
let themeList = [];
/* the follow-the-system theme: resolved client-side, re-applied when the
   OS flips light/dark while the dashboard is open */
const autoSchemeMQ = window.matchMedia("(prefers-color-scheme: light)");

function resolveAutoTheme() {
  const auto = themeList.find((t) => t.id === "auto");
  const want = autoSchemeMQ.matches ? "light" : "dark";
  return (themeList.find((t) => t.id === want) ||
    { id: want, color_scheme: want, colors: {} });
}

function applyTheme(theme) {
  let colors = theme.colors || {};
  let scheme = theme.color_scheme || "";
  if (theme.auto || theme.id === "auto") {
    const resolved = resolveAutoTheme();
    colors = resolved.colors || {};
    scheme = resolved.color_scheme || "dark";
  }
  for (const key of appliedThemeKeys) {
    document.documentElement.style.removeProperty(key);
  }
  appliedThemeKeys = [];
  for (const [key, value] of Object.entries(colors)) {
    document.documentElement.style.setProperty(key, value);
    appliedThemeKeys.push(key);
  }
  document.documentElement.dataset.theme = theme.id;
  // native controls (selects, checkboxes, scrollbars) must match the
  // palette — the old hardcoded "dark" left them dark on the Light theme
  document.documentElement.style.colorScheme = scheme || "dark";
}

autoSchemeMQ.addEventListener("change", () => {
  if (state.activeTheme === "auto") applyTheme({ id: "auto", auto: true });
});

function showThemeMessage(message, isError = false) {
  const msg = $("theme-msg");
  clearTimeout(themeMessageTimer);
  msg.classList.toggle("error", isError);
  msg.textContent = message;
  if (!isError) {
    themeMessageTimer = setTimeout(() => {
      msg.textContent = "";
    }, 2200);
  }
}

async function loadThemes() {
  const data = await getJSON("/api/themes");
  themeList = data.themes || [];
  const active = data.active;
  const select = $("theme-select");
  select.innerHTML = themeList.map((theme) =>
    `<option value="${esc(theme.id)}"${theme.id === active ? " selected" : ""}>` +
    `${esc(theme.name)}</option>`).join("");
  const theme = themeList.find((item) => item.id === active);
  if (theme) {
    state.activeTheme = theme.id;
    applyTheme(theme);
  }
}

$("theme-select").addEventListener("change", async (event) => {
  const select = event.currentTarget;
  const previousTheme = state.activeTheme;
  select.disabled = true;
  showThemeMessage("Applying theme…");
  try {
    const response = await fetch("/api/theme", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ theme: event.target.value }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || `Theme change failed (${response.status})`);
    applyTheme(result.theme);
    state.activeTheme = result.theme.id;
    showThemeMessage(`${result.theme.name} theme applied`);
  } catch (error) {
    showThemeMessage(error.message, true);
    if (previousTheme) select.value = previousTheme;
    console.warn("theme change", error);
  } finally {
    select.disabled = false;
  }
});

/* ------------------------------------------------------------- tables -- */
const MAX_ROWS = 300;
function addRow(tblId, cells, scope = "") {
  const tbody = $(tblId).tBodies[0];
  const tr = document.createElement("tr");
  if (scope) tr.dataset.scope = scope;
  tr.innerHTML = cells.map((c) => `<td${c.cls ? ` class="${c.cls}"` : ""}>${c.html}</td>`).join("");
  tbody.prepend(tr);
  while (tbody.rows.length > MAX_ROWS) tbody.deleteRow(-1);
  applyFilter(tblId, tr);
}
const VISIBILITY_LABELS = {
  "traffic-panel": "Traffic chart",
  "traffic-totals-panel": "Data transferred",
  "live-connections-panel": "Live connections",
  "geo-countries-panel": "Connections by country",
  "sites-panel": "Sites & apps",
  "connections-panel": "Connection history",
  "top-apps-panel": "Top apps by traffic",
  "connection-summary-panel": "Connections by protocol & state",
  "heatmap-panel": "Activity by hour",
  "visits-panel": "Site visits",
  "battery-panel": "Battery & power",
  "privacy-panel": "Privacy events",
  "files-panel": "File access",
  "network-panel": "Network events",
  "system-panel": "System & devices",
  "blocks-panel": "Firewall rules (block / allow)",
  "dns-panel": "DNS shield",
};

async function loadTableVisibility() {
  try {
    const data = await getJSON("/api/table-visibility");
    state.tableVisibility = data.visibility || {};
    const holder = $("table-visibility-options");
    holder.innerHTML = `<label class="visibility-all"><input type="checkbox" data-all="true"> All</label>` +
      Object.entries(VISIBILITY_LABELS).map(([id, label]) =>
      `<label><input type="checkbox" data-panel="${id}" ` +
      `${state.tableVisibility[id] !== false ? "checked" : ""}> ${label}</label>`).join("");
    const updateAll = () => {
      const inputs = [...holder.querySelectorAll("input[data-panel]")];
      const all = holder.querySelector("[data-all]");
      all.checked = inputs.length > 0 &&
        inputs.every((input) => input.checked);
      all.indeterminate =
        inputs.some((input) => input.checked) && inputs.some((input) => !input.checked);
    };
    updateAll();
    holder.querySelectorAll("input").forEach((input) => {
      input.addEventListener("change", async () => {
        const changes = input.dataset.all === "true"
          ? Object.fromEntries(Object.keys(VISIBILITY_LABELS).map((id) => [id, input.checked]))
          : { [input.dataset.panel]: input.checked };
        const previous = { ...state.tableVisibility };
        Object.assign(state.tableVisibility, changes);
        for (const checkbox of holder.querySelectorAll("input[data-panel]")) {
          checkbox.checked = state.tableVisibility[checkbox.dataset.panel] !== false;
        }
        applyTableVisibility();
        updateAll();
        try {
          const response = await fetch("/api/table-visibility", {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ visibility: changes }),
          });
          const result = await response.json();
          if (!response.ok) throw new Error(result.error || "Could not save table visibility");
          $("visibility-msg").textContent = "";
        } catch (error) {
          console.warn("table visibility", error);
          $("visibility-msg").textContent = `Could not save visibility: ${error.message}`;
          state.tableVisibility = previous;
          for (const checkbox of holder.querySelectorAll("input[data-panel]")) {
            checkbox.checked = state.tableVisibility[checkbox.dataset.panel] !== false;
          }
          applyTableVisibility();
          updateAll();
        }
      });
    });
    applyTableVisibility();
  } catch (error) {
    console.warn("table visibility", error);
    $("visibility-msg").textContent = `Could not load visibility: ${error.message}`;
  }
}

function applyTableVisibility() {
  for (const [id] of Object.entries(VISIBILITY_LABELS)) {
    const panel = $(id);
    if (panel) panel.hidden = state.tableVisibility[id] === false;
  }
}

const LAYOUT_WIDTHS = ["full", "half", "third"];

async function saveDashboardLayout() {
  const panels = [...$("dashboard-layout").querySelectorAll(":scope > .panel")];
  const layout = {
    order: panels.map((panel) => panel.id),
    widths: Object.fromEntries(panels.map((panel) =>
      [panel.id, panel.dataset.layoutWidth || "full"])),
    heights: Object.fromEntries(panels.filter((panel) => panel.dataset.layoutHeight)
      .map((panel) => [panel.id, Number(panel.dataset.layoutHeight)])),
    locked: state.dashboardLayout?.locked === true,
    panel_locks: Object.fromEntries(panels.map((panel) =>
      [panel.id, panel.dataset.layoutLocked === "true"])),
    collapsed: Object.fromEntries(panels.map((panel) =>
      [panel.id, panel.classList.contains("panel-collapsed")])),
  };
  state.dashboardLayout = layout;
  try {
    const response = await fetch("/api/dashboard-layout", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ layout }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "Could not save dashboard layout");
    $("visibility-msg").textContent = "";
  } catch (error) {
    console.warn("dashboard layout", error);
    $("visibility-msg").textContent = `Could not save dashboard layout: ${error.message}`;
  }
}

function applyDashboardLayout(layout) {
  const container = $("dashboard-layout");
  const validPanels = [...container.querySelectorAll(":scope > .panel")];
  const byId = new Map(validPanels.map((panel) => [panel.id, panel]));
  // desired order: saved order first, any unlisted panels keep DOM order after
  const seen = new Set();
  const ordered = [];
  for (const id of layout.order || []) {
    const panel = byId.get(id);
    if (panel && !seen.has(id)) { ordered.push(panel); seen.add(id); }
  }
  for (const panel of validPanels) {
    if (!seen.has(panel.id)) ordered.push(panel);
  }
  // only touch the DOM when something actually moves — re-appending would
  // restart the panel entrance animation on every lock/apply call
  if (ordered.some((panel, i) => container.children[i] !== panel)) {
    for (const panel of ordered) container.append(panel);
  }
  for (const panel of validPanels) {
    const width = LAYOUT_WIDTHS.includes(layout.widths?.[panel.id])
      ? layout.widths[panel.id] : "full";
    panel.dataset.layoutWidth = width;
    panel.classList.remove("layout-full", "layout-half", "layout-third");
    panel.classList.add(`layout-${width}`);
    const height = Number(layout.heights?.[panel.id]);
    if (Number.isFinite(height) && height >= 180 && height <= 1200) {
      panel.dataset.layoutHeight = String(height);
      panel.style.height = `${height}px`;
      panel.style.overflow = "auto";
    }
  }
  state.dashboardLayout = {
    ...layout,
    locked: layout.locked === true,
    panel_locks: layout.panel_locks || {},
  };
  $("layout-lock-all").textContent = layout.locked ? "Unlock layout" : "Lock layout";
  $("layout-lock-all").setAttribute("aria-pressed", String(layout.locked === true));
  for (const panel of validPanels) {
    panel.dataset.layoutLocked = String(layout.panel_locks?.[panel.id] === true);
    const controls = panel.querySelector(".layout-controls");
    if (controls) {
      controls.querySelectorAll("button, select").forEach((control) => {
        control.disabled = layout.locked === true || panel.dataset.layoutLocked === "true";
      });
      const lock = controls.querySelector(".panel-lock");
      if (lock) {
        lock.textContent = panel.dataset.layoutLocked === "true" ? "Unlock" : "Lock";
        lock.setAttribute("aria-pressed", panel.dataset.layoutLocked);
        lock.disabled = layout.locked === true;
      }
    }
    const handle = panel.querySelector(".panel-resize-handle");
    if (handle) {
      handle.hidden = layout.locked === true || panel.dataset.layoutLocked === "true";
      handle.setAttribute("aria-disabled", String(handle.hidden));
    }
    setPanelCollapsed(panel, layout.collapsed?.[panel.id] === true);
  }
}

/* Per-panel collapse toggle: a chevron inside the panel title hides the
   body and keeps the head as a one-line strip. Collapse is a viewing aid,
   so it works even while the layout is locked; the state persists in the
   dashboard layout's "collapsed" map. */
function setupPanelCollapse(panel, head) {
  const title = head.querySelector("h2");
  if (!title || title.querySelector(".panel-collapse")) return;
  const button = document.createElement("button");
  button.type = "button";
  button.className = "panel-collapse";
  button.title = "Collapse / expand panel";
  button.setAttribute("aria-expanded", "true");
  button.setAttribute("aria-controls", panel.id);
  button.textContent = "▾";
  button.addEventListener("click", () => {
    const collapsed = !panel.classList.contains("panel-collapsed");
    setPanelCollapsed(panel, collapsed);
    saveDashboardLayout();
  });
  title.prepend(button);
}

function setPanelCollapsed(panel, collapsed) {
  panel.classList.toggle("panel-collapsed", collapsed);
  const button = panel.querySelector(".panel-collapse");
  if (button) button.setAttribute("aria-expanded", String(!collapsed));
}

function setupDashboardLayoutControls() {
  const container = $("dashboard-layout");
  for (const panel of container.querySelectorAll(":scope > .panel")) {
    const head = panel.querySelector(".panel-head");
    if (!head) continue;
    setupPanelCollapse(panel, head);
    const controls = document.createElement("div");
    controls.className = "layout-controls";
    controls.innerHTML = `<button type="button" class="layout-drag" draggable="true" ` +
      `title="Drag to rearrange panel" aria-label="Drag to rearrange panel">Move</button>` +
      `<button type="button" class="layout-step" data-step="left" title="Move left">←</button>` +
      `<button type="button" class="layout-step" data-step="right" title="Move right">→</button>` +
      `<button type="button" class="layout-step" data-step="up" title="Move up">↑</button>` +
      `<button type="button" class="layout-step" data-step="down" title="Move down">↓</button>` +
      `<select class="filter panel-width" title="panel width">` +
      `<option value="full">Full</option><option value="half">Half</option>` +
      `<option value="third">Third</option></select>` +
      `<button type="button" class="panel-lock" aria-pressed="false" title="lock this panel arrangement">Lock</button>`;
    head.append(controls);
    const select = controls.querySelector("select");
    select.value = panel.dataset.layoutWidth || "full";
    select.addEventListener("change", () => {
      panel.dataset.layoutWidth = select.value;
      panel.classList.remove("layout-full", "layout-half", "layout-third");
      panel.classList.add(`layout-${select.value}`);
      saveDashboardLayout();
    });
    controls.querySelectorAll(".layout-step").forEach((button) => {
      button.addEventListener("click", () => movePanel(panel, button.dataset.step));
    });
    controls.querySelector(".panel-lock").addEventListener("click", () => {
      state.dashboardLayout = state.dashboardLayout || {};
      state.dashboardLayout.panel_locks = state.dashboardLayout.panel_locks || {};
      state.dashboardLayout.panel_locks[panel.id] = !panelLocked(panel);
      applyDashboardLayout(state.dashboardLayout || {});
      saveDashboardLayout();
    });
    const handle = document.createElement("div");
    handle.className = "panel-resize-handle";
    handle.title = "Drag to resize panel height";
    handle.setAttribute("role", "separator");
    handle.setAttribute("aria-label", "Resize panel height");
    panel.append(handle);
    handle.addEventListener("pointerdown", (event) => {
      event.preventDefault();
      const startY = event.clientY;
      const startHeight = panel.getBoundingClientRect().height;
      handle.setPointerCapture(event.pointerId);
      const move = (moveEvent) => {
        const height = Math.max(180, Math.min(1200, startHeight + moveEvent.clientY - startY));
        panel.style.height = `${height}px`;
        panel.style.overflow = "auto";
        panel.dataset.layoutHeight = String(Math.round(height));
      };
      const end = () => {
        handle.removeEventListener("pointermove", move);
        handle.removeEventListener("pointerup", end);
        saveDashboardLayout();
      };
      handle.addEventListener("pointermove", move);
      handle.addEventListener("pointerup", end, { once: true });
    });
    const drag = controls.querySelector(".layout-drag");
    drag.addEventListener("dragstart", (event) => {
      if (layoutLocked() || panelLocked(panel)) {
        event.preventDefault();
        return;
      }
      event.dataTransfer.setData("text/plain", panel.id);
      event.dataTransfer.effectAllowed = "move";
      panel.classList.add("panel-dragging");
    });
    drag.addEventListener("dragend", () => {
      panel.classList.remove("panel-dragging");
      saveDashboardLayout();
    });
    panel.addEventListener("dragover", (event) => event.preventDefault());
    panel.addEventListener("drop", (event) => {
      event.preventDefault();
      const dragged = byPanelId(event.dataTransfer.getData("text/plain"));
      if (!dragged || dragged === panel || layoutLocked() ||
          panelLocked(dragged) || panelLocked(panel)) return;
      const rect = panel.getBoundingClientRect();
      const horizontal = Math.abs(event.clientX - (rect.left + rect.width / 2)) >
        Math.abs(event.clientY - (rect.top + rect.height / 2));
      const before = horizontal
        ? event.clientX < rect.left + rect.width / 2
        : event.clientY < rect.top + rect.height / 2;
      if (horizontal) {
        dragged.dataset.layoutWidth = "half";
        panel.dataset.layoutWidth = "half";
        for (const item of [dragged, panel]) {
          item.classList.remove("layout-full", "layout-half", "layout-third");
          item.classList.add("layout-half");
          item.querySelector(".panel-width").value = "half";
        }
      }
      container.insertBefore(dragged, before ? panel : panel.nextElementSibling);
    });
  }
}

function layoutLocked() {
  return state.dashboardLayout?.locked === true;
}

function panelLocked(panel) {
  return panel?.dataset.layoutLocked === "true";
}

function movePanel(panel, direction) {
  if (layoutLocked() || panelLocked(panel)) return;
  const container = $("dashboard-layout");
  const panels = [...container.querySelectorAll(":scope > .panel")];
  const index = panels.indexOf(panel);
  // Every step is one panel position. The dashboard is a 12-column grid with
  // mixed panel widths (full/half/third), so "one row" has no fixed size in
  // DOM order — a ±2 jump just skipped a panel. Up/down reorder by one; only
  // left/right additionally pair the two panels at half width.
  const offset = direction === "left" || direction === "up" ? -1 : 1;
  const targetIndex = Math.max(0, Math.min(panels.length - 1, index + offset));
  const target = panels[targetIndex];
  if (!target || target === panel || panelLocked(target)) return;
  if (direction === "left" || direction === "right") {
    for (const item of [panel, target]) {
      item.dataset.layoutWidth = "half";
      item.classList.remove("layout-full", "layout-half", "layout-third");
      item.classList.add("layout-half");
      item.querySelector(".panel-width").value = "half";
    }
  }
  panels.splice(index, 1);
  panels.splice(targetIndex, 0, panel);
  panels.forEach((item) => container.append(item));
  saveDashboardLayout();
}

function byPanelId(id) {
  return [...$("dashboard-layout").querySelectorAll(":scope > .panel")]
    .find((panel) => panel.id === id) || null;
}

async function loadDashboardLayout() {
  try {
    const layout = await getJSON("/api/dashboard-layout");
    applyDashboardLayout(layout);
    for (const panel of $("dashboard-layout").querySelectorAll(":scope > .panel")) {
      const select = panel.querySelector(".panel-width");
      if (select) select.value = panel.dataset.layoutWidth || "full";
    }
  } catch (error) {
    console.warn("dashboard layout", error);
    $("visibility-msg").textContent = `Could not load dashboard layout: ${error.message}`;
  }
}

$("layout-lock-all").addEventListener("click", () => {
  state.dashboardLayout = state.dashboardLayout || defaultDashboardLayout();
  state.dashboardLayout.locked = !state.dashboardLayout.locked;
  applyDashboardLayout(state.dashboardLayout);
  saveDashboardLayout();
});

$("layout-default").addEventListener("click", () => {
  const layout = defaultDashboardLayout();
  applyDashboardLayout(layout);
  for (const panel of $("dashboard-layout").querySelectorAll(":scope > .panel")) {
    const select = panel.querySelector(".panel-width");
    if (select) select.value = panel.dataset.layoutWidth || "full";
    if (!layout.heights[panel.id]) {
      delete panel.dataset.layoutHeight;
      panel.style.removeProperty("height");
      panel.style.removeProperty("overflow");
    }
  }
  saveDashboardLayout();
});

function defaultDashboardLayout() {
  const widths = Object.fromEntries(Object.keys(VISIBILITY_LABELS).map((id) => [id, "full"]));
  widths["top-apps-panel"] = "half";
  widths["connection-summary-panel"] = "half";
  return {
    order: defaultPanelOrder(),
    widths,
    heights: { "connection-summary-panel": 461 },
    locked: false,
    panel_locks: Object.fromEntries(Object.keys(VISIBILITY_LABELS).map((id) => [id, false])),
    collapsed: Object.fromEntries(Object.keys(VISIBILITY_LABELS).map((id) => [id, false])),
  };
}

function defaultPanelOrder() {
  return ["traffic-totals-panel", "traffic-panel", "live-connections-panel",
    "geo-countries-panel", "sites-panel",
    "connections-panel", "top-apps-panel", "connection-summary-panel",
    "heatmap-panel", "visits-panel", "battery-panel",
    "privacy-panel", "files-panel", "network-panel", "system-panel", "blocks-panel",
    "dns-panel"];
}

function badge(category, kind) {
  const cls = { privacy: "b-priv", file: "b-file", network: "b-net",
                devices: "b-dev", logins: "b-login", appfocus: "b-sys",
                system: "b-sys" }[category] || "b-sys";
  return `<span class="badge ${cls}">${esc(kind)}</span>`;
}
function applyFilter(tblId, tr) {
  const q = $("filter-" + tblId.replace("tbl-", "")).value.toLowerCase();
  let ok = !q || tr.textContent.toLowerCase().includes(q);
  if (ok) {
    const t = tblId.replace("tbl-", "");
    const detailCol = DETAIL_FILTER_COLS[t];
    if (detailCol != null) {
      const dq = ($(`detail-${t}`)?.value || "").trim().toLowerCase();
      if (dq && !(tr.children[detailCol]?.textContent || "").toLowerCase().includes(dq)) ok = false;
    }
    const scope = t === "network" ? state.scopeNetwork : "";
    if (scope && tr.dataset.scope !== scope) ok = false;
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
for (const name of ["privacy", "file", "network", "system"]) {
  $("filter-" + name).addEventListener("input", () => {
    const tblId = "tbl-" + name;
    for (const tr of $(tblId).tBodies[0].rows) applyFilter(tblId, tr);
  });
}
for (const name of Object.keys(DETAIL_FILTER_COLS)) {
  $(`detail-${name}`).addEventListener("input", () => {
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
    title="block all traffic to/from ${esc(ip)}" aria-label="block all traffic to/from ${esc(ip)}">&#9940;</button>`;
}

// allowIpBtnHtml is blockBtnHtml's green twin: an allow exception for the
// IP (overrides any broader block rule it would match, e.g. a country)
function allowIpBtnHtml(remote) {
  if (!remote || typeof remote !== "string") return "";
  const ip = remote.split(":")[0];
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return "";
  return ` <button class="mini-btn allow-btn" data-aip="${esc(ip)}"
    title="allow all traffic to/from ${esc(ip)} (overrides block rules)"
    aria-label="allow all traffic to/from ${esc(ip)}">&#9989;</button>`;
}

// dnsBlockBtnHtml renders the name-layer twin of the IP block button: the
// host is fed to the DNS shield's custom blocklist, so every lookup for it
// answers NXDOMAIN (ads/trackers die at the name — no IP snapshot churn).
function dnsBlockBtnHtml(connection) {
  const host = connection && connection.host;
  if (!host || typeof host !== "string" || !host.includes(".") ||
      /^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return "";
  const blocked = (state.dnsCustomDomains || []).includes(host.toLowerCase());
  return ` <button class="mini-btn${blocked ? " allow-btn" : ""}" data-dnsblock="${esc(host)}"
    title="${blocked ? "remove" : "add"} ${esc(host)} ${blocked ? "from" : "in"} the DNS shield's custom blocklist (lookups answer NXDOMAIN)"
    aria-label="block the domain ${esc(host)} via DNS">${blocked ? "&#9989;" : "&#127760;"}</button>`;
}

// freshBadge marks destinations first seen within the last week — "is this
// new?" at a glance in the live and destination tables.
function freshBadge(ts) {
  if (!ts) return "";
  const age = Date.now() / 1000 - Number(ts);
  if (age > 7 * 86400) return "";
  const when = age < 90 ? "just now"
    : age < 3600 ? `${Math.max(1, Math.round(age / 60))} min ago`
    : age < 86400 ? `${Math.round(age / 3600)} h ago`
    : `${Math.round(age / 86400)} d ago`;
  return ` <span class="badge b-allow" title="first seen ${esc(when)} — this destination is new this week">new</span>`;
}

function handleEvent(ev) {
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
    const scope = eventScope(ev.remote);
    addRow("tbl-network", [
      t, { html: badge("network", ev.kind) },
      { html: esc(ev.app ?? "") }, { html: esc(ev.user ?? "") },
      { html: esc(ev.proto ?? "") },
      { html: `<span class="mono">${esc(ev.remote ?? "")}</span>${blockBtnHtml(ev.remote)}${allowIpBtnHtml(ev.remote)}` },
      { html: esc(scope) },
      { html: esc(ev.detail ?? ""), cls: "dim" },
    ], scope);
  } else if (["devices", "logins", "system", "appfocus"].includes(ev.category)) {
    addRow("tbl-system", [
      t, { html: badge(ev.category, ev.kind) },
      { html: esc(ev.app ?? "") }, { html: esc(ev.user ?? "") },
      { html: `<span class="mono">${esc(ev.device ?? ev.path ?? "")}</span>` },
      { html: esc(ev.detail ?? ""), cls: "dim" },
    ]);
  }
  function eventScope(remote) {
    if (!remote) return "unknown";
    let host = String(remote).trim();
    if (host.startsWith("[")) host = host.slice(1, host.indexOf("]"));
    else if ((host.match(/:/g) || []).length === 1) host = host.slice(0, host.lastIndexOf(":"));
    const octets = host.split(".").map(Number);
    if (octets.length === 4 && octets.every((n) => Number.isInteger(n) && n >= 0 && n <= 255)) {
      const [a, b] = octets;
      if (a === 10 || a === 127 || (a === 169 && b === 254) ||
          (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return "internal";
      if (a >= 224 || a === 0) return "other";
      return "external";
    }
    const ipv6 = host.toLowerCase();
    if (ipv6 === "::1" || ipv6.startsWith("fc") || ipv6.startsWith("fd") ||
        ipv6.startsWith("fe80:") || ipv6.startsWith("::ffff:127.")) return "internal";
    if (ipv6.includes(":")) return "external";
    return "unknown";
  }
}
function fmtAgo(ts) {
  const s = Math.max(0, Math.round(Date.now() / 1000 - ts));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s ago`;
  const h = Math.floor(s / 3600);
  return `${h}h ${Math.floor((s % 3600) / 60)}m ago`;
}
/* "4m 12s" / "2h" — seconds span between two epoch timestamps */
function fmtDuration(seconds) {
  const s = Math.max(0, Math.floor(seconds));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  const h = Math.floor(m / 60);
  if (h < 24) return m % 60 === 0 ? `${h}h` : `${h}h ${m % 60}m`;
  const d = Math.floor(h / 24);
  return `${d}d ${h % 24}h`;
}
/* ISO alpha-2 -> emoji flag via regional-indicator symbol pairs. Kept as a
   text fallback (and for tooltips): Windows renders the pair as plain
   letters, so every flag SPOT in the UI uses the bundled SVG sprite
   (web/flags/<cc>.svg — flag-icons, MIT, vendored; see flags/LICENSE)
   through flagImgHTML instead. */
function ccToFlag(cc) {
  if (!/^[a-z]{2}$/i.test(cc)) return "";
  const base = 0x1f1e6; // REGIONAL INDICATOR SYMBOL LETTER A
  return String.fromCodePoint(
    base + cc.toUpperCase().charCodeAt(0) - 65,
    base + cc.toUpperCase().charCodeAt(1) - 65);
}

/* Inline flag image for the SVG sprite served from /flags/<cc>.svg. All
   ISO 3166-1 alpha-2 codes are bundled; a miss (a geo source handing out a
   non-ISO code) falls back to the emoji pair / bare letters. */
const flagImgCache = new Set();

function flagImgHTML(cc) {
  if (!/^[a-z]{2}$/i.test(cc)) return "";
  const low = cc.toLowerCase();
  if (!flagImgCache.size) {
    // Probe once per page load: on a miss, hide the broken <img> and keep
    // the ISO code text that every call site renders next to the flag.
    const probe = new Image();
    probe.onerror = () => flagImgCache.add("!");
    probe.src = `web/flags/us.svg`;
    flagImgCache.add("ok");
  }
  const hide = flagImgCache.has("!") ? ` style="display:none"` : "";
  return `<img class="flag" src="web/flags/${low}.svg" alt="" width="21" height="15" loading="lazy"${hide}>`;
}
/* flag + ISO code + country for an external connection; "…" while the async
   geo lookup is pending, "—" for anything that isn't external */
function geoCellHTML(connection) {
  if (connectionScope(connection) !== "external") return '<span class="dim">—</span>';
  if (connection.geo_cc) {
    const place = [connection.geo_country, connection.geo_city].filter(Boolean).join(", ");
    return `<span class="geo-cell" title="${esc(place || connection.geo_cc)}">` +
      `${flagImgHTML(connection.geo_cc)} ${esc(connection.geo_cc)}` +
      (connection.geo_country ? ` ${esc(connection.geo_country)}` : "") + "</span>";
  }
  return '<span class="geo-cell dim" title="geo lookup pending">…</span>';
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
      return `<span class="chip ${c.enabled ? "" : "chip-off"}" role="button" tabindex="0" ` +
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
        fl.textContent = g.installed
          ? "\u{1F512} TRACING ON" : "\u{1F513} TRACING OFF";
        fl.className = "state-pill " + (g.installed ? "state-on" : "state-off");
        fl.title = g.installed
          ? "file tracing is ON (fs_usage via a passwordless grant)\n" +
            "click to make it on-demand — tracing stops and the grant is removed"
          : "file tracing is OFF (no fs_usage grant)\n" +
            "click to grant — macOS asks for your password once, tracing starts";
        fl.setAttribute("aria-label", "file tracing is " +
          (g.installed ? "on" : "off") + " — click to toggle");
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

// chips act as buttons: let Enter/Space activate them from the keyboard
// (delegated on the container — chips are re-rendered on every status poll)
$("status-chips").addEventListener("keydown", (event) => {
  if (event.key !== "Enter" && event.key !== " ") return;
  const chip = event.target.closest(".chip[role='button']");
  if (!chip) return;
  event.preventDefault();
  chip.click();
});

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

async function loadConnectionHistory() {
  const requestId = ++state.connectionHistoryRequest;
  try {
    const minutes = parseInt($("connections-range").value, 10) || 15;
    const since = Date.now() / 1000 - minutes * 60;
    const data = await getJSON(`/api/connection-history?since=${since.toFixed(3)}&limit=2000`);
    if (requestId !== state.connectionHistoryRequest) return;
    state.connectionHistory = data.connections || [];
    refreshConnectionAppOptions();
    renderConnectionHistory();
  } catch (e) {
    if (requestId !== state.connectionHistoryRequest) return;
    console.warn("connection history", e);
    $("connections-list").innerHTML =
      `<div class="empty">could not load connection history: ${esc(e.message)}</div>`;
  }
}

function renderConnectionHistory() {
  const groups = new Map();
  for (const connection of state.connectionHistory) {
    const app = connection.app || "Unknown";
    const pid = connection.pid || "—";
    const key = `${pid}\u0000${app}`;
    if (!groups.has(key)) groups.set(key, { app, pid, connections: [] });
    groups.get(key).connections.push(connection);
  }
  const query = $("filter-conns").value.trim().toLowerCase();
  const visibleGroups = [...groups.values()].filter((group) => {
    if (state.appConns && group.app !== state.appConns) return false;
    group.visibleConnections = group.connections.filter((connection) => {
      if (state.scopeConns && connection.scope !== state.scopeConns) return false;
      if (state.protocolConns &&
          String(connection.protocol || "").toUpperCase() !== state.protocolConns) return false;
      if (state.statusConns && connectionStatus(connection) !== state.statusConns) return false;
      return !query || JSON.stringify(connection).toLowerCase().includes(query) ||
        group.app.toLowerCase().includes(query) || String(group.pid).includes(query);
    }).sort((a, b) => b.last_seen - a.last_seen);
    group.latestSeen = Math.max(...group.visibleConnections.map((connection) => connection.last_seen));
    return group.visibleConnections.length > 0;
  }).sort((a, b) => b.latestSeen - a.latestSeen);

  // sortable groups: roll each group's counts up before rendering so the
  // header clicks can order by any column
  for (const group of visibleGroups) {
    group.totals = { established: 0, ok: 0, info: 0, closed: 0,
                     internal: 0, external: 0 };
    for (const connection of group.visibleConnections) {
      group.totals[connectionStatus(connection)]++;
      if (connection.scope === "internal") group.totals.internal++;
      if (connection.scope === "external") group.totals.external++;
    }
    group.sortName = group.app.toLowerCase();
  }
  sortRowsBy(visibleGroups, state.sortHistory);
  const total = visibleGroups.reduce((count, group) => count + group.visibleConnections.length, 0);
  $("connections-summary-count").textContent =
    `${total} observation${total === 1 ? "" : "s"} · ${visibleGroups.length} process${visibleGroups.length === 1 ? "" : "es"}`;
  state.visibleConnectionGroups = visibleGroups;
  const rows = visibleGroups.map((group, index) => {
    const counts = group.totals || { established: 0, ok: 0, info: 0, closed: 0 };
    const internal = counts.internal || 0;
    const external = counts.external || 0;
    const groupKey = JSON.stringify([group.pid, group.app]);
    const expanded = state.expandedConnectionGroups.has(groupKey);
    const detailRows = sortRowsBy(group.visibleConnections, state.sortHistorySub)
      .map((connection) => {
      const status = connectionStatus(connection);
      const protocol = String(connection.protocol || "—").toUpperCase();
      const observedState = String(connection.state || "—").toUpperCase();
      const lastSeenTitle = `Last observed ${fmtTime(connection.last_seen)}`;
      // duration = first seen -> last seen (or the close timestamp)
      const duration = fmtDuration(
        (connection.ended_at ?? connection.last_seen) - connection.started_at);
      return `<tr class="history-${status}"><td>${fmtTime(connection.started_at)}</td>` +
        `<td><span class="connection-status status-${status}" title="${status === "closed" ? "Closed after two missed snapshots" : ""}">` +
        `${status}</span></td><td><span class="protocol-label">${esc(protocol)}</span></td>` +
        `<td>${esc(observedState)}</td>` +
        `<td class="mono">${esc(connection.local || "—")}</td>` +
        `<td class="mono">${esc(connection.remote || "—")}</td>` +
        `<td>${geoCellHTML(connection)}</td>` +
        `<td>${duration}</td>` +
        `<td><span class="scope-label scope-${esc(connection.scope || "other")}">` +
        `${esc(connection.scope || "other")}</span></td>` +
        `<td title="${esc(lastSeenTitle)}">${fmtAgo(connection.last_seen)}</td></tr>`;
    }).join("");
    const summary = `<tr class="connection-process-row">` +
      `<td class="connection-app-cell"><button class="connection-expand" type="button" ` +
      `data-group="${esc(encodeURIComponent(groupKey))}" aria-expanded="${expanded}" ` +
      `title="${expanded ? "Hide" : "Show"} connection observations" ` +
      `aria-label="${expanded ? "Hide" : "Show"} connection observations">` +
      `${expanded ? "−" : "+"}</button><span class="connection-app">${esc(group.app)}</span></td>` +
      `<td class="mono">${esc(group.pid)}</td><td title="${esc(fmtTime(group.latestSeen))}">` +
      `${fmtAgo(group.latestSeen)}</td><td>${counts.established || 0}</td><td>${counts.ok || 0}</td>` +
      `<td>${counts.closed || 0}</td><td>${internal}</td><td>${external}</td></tr>`;
    const expandedContent = expanded
      ? `<tr class="connection-detail-row"><td colspan="8"><div class="tbl-wrap"><table>` +
        subHeadHTML(HISTORY_SUB_COLS, state.sortHistorySub) +
        `<tbody>${detailRows}</tbody></table></div></td></tr>` : "";
    return summary + expandedContent;
  }).join("");
  $("connections-list").innerHTML = visibleGroups.length
    ? `<div class="tbl-wrap connection-history-table-wrap"><table class="connection-history-table">` +
      `<colgroup><col class="connection-col-app"><col class="connection-col-pid">` +
      `<col class="connection-col-last"><col><col><col><col><col></colgroup>` +
      `<thead><tr>` +
      `<th class="sortable" data-sort="name">App name</th>` +
      `<th class="sortable" data-sort="pid">PID</th>` +
      `<th class="sortable" data-sort="last">Last active</th>` +
      `<th class="sortable" data-sort="established">Established</th>` +
      `<th class="sortable" data-sort="ok">OK</th>` +
      `<th class="sortable" data-sort="closed">Closed</th>` +
      `<th class="sortable" data-sort="internal">Internal</th>` +
      `<th class="sortable" data-sort="external">External</th></tr></thead>` +
      `<tbody>${rows}</tbody></table></div>`
    : '<div class="empty">No saved connections match the selected time range and filters.</div>';
  applySortIndicators("connections-list", state.sortHistory);
}

$("connections-list").addEventListener("click", (event) => {
  const button = event.target.closest(".connection-expand");
  if (!button) return;
  const groupKey = decodeURIComponent(button.dataset.group);
  if (state.expandedConnectionGroups.has(groupKey)) {
    state.expandedConnectionGroups.delete(groupKey);
  } else {
    state.expandedConnectionGroups.add(groupKey);
  }
  renderConnectionHistory();
});
function connectionStatus(connection) {
  if (connection.ended_at || String(connection.state || "").toUpperCase() === "CLOSED") return "closed";
  if (String(connection.protocol || "").toUpperCase() === "TCP" &&
      String(connection.state || "").toUpperCase() === "ESTABLISHED") return "established";
  if (String(connection.protocol || "").toUpperCase() === "TCP" &&
      String(connection.state || "").toUpperCase() === "LISTEN") return "ok";
  return "info";
}

function refreshConnectionAppOptions() {
  const sel = $("app-conns");
  if (!sel) return;
  const apps = [...new Set(state.connectionHistory.map((c) => c.app).filter(Boolean))]
    .sort((a, b) => a.localeCompare(b));
  if (state.appConns && !apps.includes(state.appConns)) {
    apps.push(state.appConns);   // keep the chosen app visible even if idle
  }
  sel.innerHTML = '<option value="">All apps</option>' +
    apps.slice(0, 200).map((a) =>
      `<option value="${esc(a)}"${a === state.appConns ? " selected" : ""}>` +
      `${esc(a)}</option>`).join("");
}

$("filter-conns").addEventListener("input", renderConnectionHistory);
$("connections-range").addEventListener("change", loadConnectionHistory);
$("refresh-conns-btn").addEventListener("click", loadConnectionHistory);
$("clear-connection-filters").addEventListener("click", () => {
  state.appConns = "";
  state.scopeConns = "";
  state.protocolConns = "";
  state.statusConns = "";
  $("app-conns").value = "";
  $("scope-conns").value = "";
  $("protocol-conns").value = "";
  $("status-conns").value = "";
  $("filter-conns").value = "";
  renderConnectionHistory();
});
$("scope-conns").addEventListener("change", (e) => {
  state.scopeConns = e.target.value;
  renderConnectionHistory();
});
$("app-conns").addEventListener("change", (e) => {
  state.appConns = e.target.value;
  renderConnectionHistory();
});
$("protocol-conns").addEventListener("change", (e) => {
  state.protocolConns = e.target.value;
  renderConnectionHistory();
});
$("status-conns").addEventListener("change", (e) => {
  state.statusConns = e.target.value;
  renderConnectionHistory();
});
$("filter-live-conns").addEventListener("input", renderLiveConnections);
$("live-group").addEventListener("change", () => {
  state.liveGroupBy = $("live-group").value === "flat" ? "flat" : "app";
  renderLiveConnections();
});
// expand/collapse one app group in the live connections table
$("tbl-live-conns").addEventListener("click", (event) => {
  const button = event.target.closest(".connection-expand");
  if (!button) return;
  const key = decodeURIComponent(button.dataset.group || "");
  if (state.expandedLiveGroups.has(key)) {
    state.expandedLiveGroups.delete(key);
  } else {
    state.expandedLiveGroups.add(key);
  }
  renderLiveConnections();
});
$("app-live-conns").addEventListener("change", renderLiveConnections);
$("scope-live-conns").addEventListener("change", renderLiveConnections);
$("geo-live-conns").addEventListener("change", () => {
  refreshLiveCityOptions();
  renderLiveConnections();
});
$("geo-city-live-conns").addEventListener("change", renderLiveConnections);
$("state-live-conns").addEventListener("change", renderLiveConnections);
$("geo-countries-country").addEventListener("change", renderGeoCountries);
$("geo-countries-mode").addEventListener("change", () => {
  state.countriesMode =
    $("geo-countries-mode").value === "flat" ? "flat" : "country";
  renderGeoCountries();
});
$("geo-countries-app").addEventListener("change", renderGeoCountries);
$("geo-countries-active").addEventListener("change", renderGeoCountries);
$("filter-geo-countries").addEventListener("input", renderGeoCountries);
$("tbl-geo-countries").addEventListener("click", (event) => {
  const blockBtn = event.target.closest("button[data-bcc]");
  if (blockBtn) {
    const cc = blockBtn.dataset.bcc;
    const name = blockBtn.dataset.bname || cc;
    let msg = `Block ALL traffic to/from ${name} (${cc})?\n\nEvery public ` +
      `IP range of the country will be dropped in both directions — ` +
      `thousands of networks, including any site merely hosted there.`;
    if (state.ownCountry === cc) {
      msg += `\n\n⚠ ${cc} appears to be YOUR OWN country — this can cut ` +
        `your connectivity entirely.`;
    }
    if (confirm(msg + "\n\nProceed?")) {
      addBlock({ type: "country", cc, confirm: true });
    }
    return;
  }
  const button = event.target.closest(".connection-expand");
  if (!button) return;
  const key = decodeURIComponent(button.dataset.group || "");
  if (state.expandedCountryGroups.has(key)) {
    state.expandedCountryGroups.delete(key);
  } else {
    state.expandedCountryGroups.add(key);
  }
  renderGeoCountries();
});
clickSort("tbl-live-conns", state.sortLive, renderLiveConnections,
  ["app", "pid", "user", "proto", "remote", "service", "local", "geo",
   "duration", "bytes_in", "bytes_out", "state"]);
clickSort("tbl-connection-summary", state.sortConnSummary,
  renderConnectionSummary, ["proto", "state", "count"]);
clickSort("tbl-blocks", state.sortBlocks, loadBlocks,
  ["ts", "type", "target", "status", "detail"]);
clickSort("tbl-dns-rules", state.sortDnsRules, loadDNS,
  ["ts", "action", "type", "value", "domains", "detail"]);
clickSortDelegated("connections-list", state.sortHistory,
  renderConnectionHistory,
  ["name", "pid", "last", "established", "ok", "closed", "internal", "external"]);
clickSort("tbl-geo-countries", state.sortGeo, renderGeoCountries, DEST_COLS);
// sub-table (detail) sorts: clicking a detail header re-sorts every detail
// table of that parent, independent of the summary-row sort above
clickSubSort("tbl-live-conns", state.sortLiveSub, renderLiveConnections,
  LIVE_SUB_COLS.map(([key]) => key).filter(Boolean));
clickSubSort("connections-list", state.sortHistorySub, renderConnectionHistory,
  HISTORY_SUB_COLS.map(([key]) => key));
clickSubSort("tbl-sites", state.sortSitesSub, renderSites,
  [...new Set([...IP_SUB_COLS, ...SITE_SUB_COLS].map(([key]) => key))]);
clickSubSort("tbl-geo-countries", state.sortGeoSub, renderGeoCountries,
  IP_SUB_COLS.map(([key]) => key));
// expand/collapse all groups (visible groups after filtering; the buttons
// hide themselves while a table is in a flat mode)
wireGroupToggles("live-expand-all", "live-collapse-all",
  () => state.visibleLiveGroupKeys, state.expandedLiveGroups,
  renderLiveConnections);
wireGroupToggles("geo-expand-all", "geo-collapse-all",
  () => state.visibleCountryGroupKeys, state.expandedCountryGroups,
  renderGeoCountries);
wireGroupToggles("sites-expand-all", "sites-collapse-all",
  () => state.visibleSiteGroupKeys, state.expandedDestGroups, renderSites);
wireGroupToggles("history-expand-all", "history-collapse-all",
  () => (state.visibleConnectionGroups || [])
    .map((group) => JSON.stringify([group.pid, group.app])),
  state.expandedConnectionGroups, renderConnectionHistory);
// paint the default-order arrows (destination tables ship pre-sorted by ↓ In)
applySortIndicators("tbl-geo-countries", state.sortGeo);
applySortIndicators("tbl-sites", state.sortSites);
applySortIndicators("tbl-blocks", state.sortBlocks);
$("clear-geo-countries-filters").addEventListener("click", () => {
  $("geo-countries-country").value = "";
  $("geo-countries-app").value = "";
  $("geo-countries-active").checked = false;
  $("filter-geo-countries").value = "";
  renderGeoCountries();
});
$("filter-sites").addEventListener("input", renderSites);
$("sites-group").addEventListener("change", () => {
  const value = $("sites-group").value;
  state.sitesGroupBy =
    value === "app" || value === "flat" ? value : "site";
  renderSites();
});
$("sites-app").addEventListener("change", renderSites);
$("sites-active").addEventListener("change", renderSites);
clickSort("tbl-sites", state.sortSites, renderSites);
$("tbl-sites").addEventListener("click", (event) => {
  const button = event.target.closest(".connection-expand");
  if (!button) return;
  const key = decodeURIComponent(button.dataset.group || "");
  if (state.expandedDestGroups.has(key)) {
    state.expandedDestGroups.delete(key);
  } else {
    state.expandedDestGroups.add(key);
  }
  renderSites();
});
$("clear-sites-filters").addEventListener("click", () => {
  $("sites-app").value = "";
  $("sites-active").checked = false;
  $("filter-sites").value = "";
  renderSites();
});
$("clear-live-connection-filters").addEventListener("click", () => {
  $("filter-live-conns").value = "";
  $("app-live-conns").value = "";
  $("scope-live-conns").value = "";
  $("geo-live-conns").value = "";
  $("geo-city-live-conns").value = "";
  refreshLiveCityOptions();
  renderLiveConnections();
});
$("scope-network").addEventListener("change", (e) => {
  state.scopeNetwork = e.target.value;
  for (const tr of $("tbl-network").tBodies[0].rows) applyFilter("tbl-network", tr);
});

async function loadLiveConnections() {
  try {
    const data = await getJSON("/api/connections");
    state.liveConnections = data.connections || [];
    $("card-conns").textContent = state.liveConnections.length;
    refreshLiveAppOptions();
    refreshLiveGeoOptions();
    refreshLiveStateOptions();
    renderLiveConnections();
    renderConnectionSummary();
  } catch (error) {
    console.warn("live connections", error);
    $("tbl-live-conns").tBodies[0].innerHTML =
      `<tr><td colspan="13" class="dim">could not load live connections: ${esc(error.message)}</td></tr>`;
  }
}

function renderConnectionSummary() {
  const counts = new Map();
  for (const connection of state.liveConnections || []) {
    const protocol = String(connection.proto || "Other").toUpperCase();
    const stateName = String(connection.state || "Info").toUpperCase();
    const key = `${protocol}\u0000${stateName}`;
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  const rows = [...counts.entries()].map(([key, count]) => {
    const [protocol, stateName] = key.split("\u0000");
    return { proto: protocol, state: stateName, count,
             sortName: protocol.toLowerCase() };
  });
  const sorted = sortRowsBy(rows, state.sortConnSummary);
  $("tbl-connection-summary").tBodies[0].innerHTML = sorted.length
    ? sorted.map((row) => {
      return `<tr><td>${esc(row.proto)}</td><td>${esc(row.state)}</td>` +
        `<td>${row.count}</td></tr>`;
    }).join("")
    : '<tr><td colspan="3" class="dim">no active endpoints</td></tr>';
}

function refreshLiveAppOptions() {
  const select = $("app-live-conns");
  const apps = [...new Set((state.liveConnections || []).map((c) => c.app).filter(Boolean))]
    .sort((a, b) => a.localeCompare(b));
  const selected = select.value;
  select.innerHTML = '<option value="">All apps</option>' +
    apps.map((app) => `<option value="${esc(app)}">${esc(app)}</option>`).join("");
  if (apps.includes(selected)) select.value = selected;
}

function refreshLiveStateOptions() {
  const select = $("state-live-conns");
  const states = [...new Set((state.liveConnections || [])
    .map((c) => NormalizeLiveConnState(c)).filter(Boolean))]
    .sort((a, b) => a.localeCompare(b));
  const selected = select.value;
  select.innerHTML = '<option value="">All states</option>' +
    states.map((s) => `<option value="${esc(s)}">${esc(s)}</option>`).join("");
  if (states.includes(selected)) select.value = selected;
}

/* Geo dropdowns list the countries/cities currently present on live rows and
   keep the selection across refetches while it still applies. The geo cache
   resolves asynchronously, so options appear as lookups land; liveNoGeo
   catches rows without a resolved country (pending lookup or not external).
   City options narrow to the chosen country when one is picked. */
const liveNoGeo = "__nogeo__";

/* Shared country <option> list (flag + ISO code + name) and selection
   keeper for the dropdowns that rebuild while a filter is picked. */
function countryOptionsHTML(countries) {
  return [...countries.entries()]
    .sort(([aCc, aName], [bCc, bName]) => (aName || aCc).localeCompare(bName || bCc))
    .map(([cc, name]) => {
      // No flag glyphs in <option>s: HTML is not rendered there, and on
      // Windows the emoji pair degrades to letters ("CN CN …").
      const label = cc + (name ? ` — ${name}` : "");
      return `<option value="${esc(cc)}">${esc(label)}</option>`;
    }).join("");
}

function keepSelectSelection(select, rebuild) {
  const selected = select.value;
  rebuild();
  if ([...select.options].some((o) => o.value === selected)) select.value = selected;
}

function refreshLiveGeoOptions() {
  const select = $("geo-live-conns");
  const countries = new Map();
  for (const connection of state.liveConnections || []) {
    if (connection.geo_cc && !countries.has(connection.geo_cc)) {
      countries.set(connection.geo_cc, connection.geo_country || "");
    }
  }
  keepSelectSelection(select, () => {
    select.innerHTML = '<option value="">All countries</option>' +
      countryOptionsHTML(countries) +
      `<option value="${liveNoGeo}">No geo / pending</option>`;
  });
  refreshLiveCityOptions();
}

function refreshLiveCityOptions() {
  const select = $("geo-city-live-conns");
  const country = $("geo-live-conns").value;
  const cities = [...new Set((state.liveConnections || [])
    .filter((c) => c.geo_city && (!country || c.geo_cc === country))
    .map((c) => c.geo_city))]
    .sort((a, b) => a.localeCompare(b));
  const selected = select.value;
  select.innerHTML = '<option value="">All cities</option>' +
    cities.map((city) => `<option value="${esc(city)}">${esc(city)}</option>`).join("");
  if (cities.includes(selected)) select.value = selected;
}

/* ---- Connections by country / Sites & apps --------------------------------
   Persisted destination views: connection lifecycles from the history store
   (so closed connections still count) plus bytes accumulated per (app, IP)
   from the live per-socket counters. */

async function loadDestinations() {
  const requestId = ++state.destinationsRequest;
  try {
    const data = await getJSON("/api/destinations");
    if (requestId !== state.destinationsRequest) return;
    state.destinations = {
      countries: data.countries || [],
      sites: data.sites || [],
      apps: data.apps || [],
    };
    refreshGeoCountriesCountryOptions();
    refreshGeoCountriesAppOptions();
    refreshSitesAppOptions();
    refreshBlockCountryOptions();
    renderGeoCountries();
    renderSites();
  } catch (error) {
    if (requestId !== state.destinationsRequest) return;
    console.warn("destinations", error);
    $("tbl-geo-countries").tBodies[0].innerHTML =
      `<tr><td colspan="9" class="dim">could not load destinations: ${esc(error.message)}</td></tr>`;
  }
}

function refreshGeoCountriesCountryOptions() {
  const select = $("geo-countries-country");
  const countries = new Map();
  for (const row of state.destinations.countries) {
    if (row.cc && !countries.has(row.cc)) countries.set(row.cc, row.country || "");
  }
  keepSelectSelection(select, () => {
    select.innerHTML = '<option value="">All countries</option>' +
      countryOptionsHTML(countries) +
      `<option value="${liveNoGeo}">No geo / pending</option>`;
  });
}

function refreshGeoCountriesAppOptions() {
  const select = $("geo-countries-app");
  const apps = new Set();
  for (const row of state.destinations.countries) {
    (row.apps || []).forEach((a) => apps.add(a));
  }
  keepSelectSelection(select, () => {
    select.innerHTML = '<option value="">All apps</option>' +
      [...apps].sort((a, b) => a.localeCompare(b))
        .map((a) => `<option value="${esc(a)}">${esc(a)}</option>`).join("");
  });
}

function refreshSitesAppOptions() {
  const select = $("sites-app");
  const apps = [...new Set((state.destinations.apps || [])
    .map((a) => a.app))].sort((a, b) => a.localeCompare(b));
  keepSelectSelection(select, () => {
    select.innerHTML = '<option value="">All apps</option>' +
      apps.map((a) => `<option value="${esc(a)}">${esc(a)}</option>`).join("");
  });
}

/* ---- column sorting (click a header: numeric columns start descending,
   text columns ascending; the arrow rides on the active header) ---------- */


function sortValueOf(row, col) {
  switch (col) {
    case "name": return String(row.sortName ?? row.app ?? row.host ??
      row.ip ?? "").toLowerCase();
    case "apps":
      if (typeof row.apps === "number") return row.apps; // sites count in app mode
      return (row.apps || []).join(", ").toLowerCase();
    // live-connection columns
    case "app": return String(row.app ?? "").toLowerCase();
    case "pid": {
      const n = Number(row.pid);
      return Number.isFinite(n) && String(row.pid).trim() !== "" ? n : row.pid;
    }
    case "user": return String(row.user ?? "").toLowerCase();
    case "proto": return String(row.proto ?? "").toUpperCase();
    case "remote": return String(row.remote_ip ?? row.remote ?? "").toLowerCase();
    case "service": return String(row.service ?? row.host ?? "").toLowerCase();
    case "local": return String(row.local_ip ?? row.local ?? "").toLowerCase();
    case "geo": return String(row.geo_cc ?? row.cc ?? "").toLowerCase();
    case "duration": return row.first_seen; // cumulative age: smaller = newer
    case "state": return String(row.state ?? "").toLowerCase();
    // blocks columns
    case "ts": return row.ts;
    case "action": return String(row.action ?? "block").toLowerCase();
    case "type": return String(row.type ?? "").toLowerCase();
    case "target": return String(row.value ?? "").toLowerCase();
    case "status": return String(row.status ?? "").toLowerCase();
    case "detail": return String(row.status_detail ?? "").toLowerCase();
    // site-visit session columns
    case "vstarted": return row.started;
    case "vended": return row.endedNum ?? row.last;
    // connection-history group columns
    case "last": return row.latestSeen;
    case "established": return row.totals?.established ?? 0;
    case "ok": return row.totals?.ok ?? 0;
    case "closed": return row.totals?.closed ?? 0;
    case "internal": return row.totals?.internal ?? 0;
    case "external": return row.totals?.external ?? 0;
    case "count": return row.count ?? 0;
    // detail (sub-table) rows: saved connection observations
    case "started": return row.started_at;
    case "status": return connectionStatus(row);
    case "protocol": return String(row.protocol ?? "").toUpperCase();
    case "duration_secs": {
      const v = (row.ended_at ?? row.last_seen) - row.started_at;
      return Number.isFinite(v) ? v : null;
    }
    case "scope": return String(row.scope ?? "").toLowerCase();
    default: return row[col];
  }
}

function cmpSortValues(a, b) {
  if (a == null || b == null) return a == null && b == null ? 0 : a == null ? 1 : -1;
  if (typeof a === "number" && typeof b === "number") return a - b;
  return String(a).localeCompare(String(b));
}

function sortRowsBy(rows, sort) {
  if (!sort.col) return rows;
  const dir = sort.dir;
  return [...rows].sort((a, b) => {
    const va = sortValueOf(a, sort.col);
    const vb = sortValueOf(b, sort.col);
    // rows without the value (e.g. bytes omitted) always sink to the bottom
    if (va == null || vb == null) {
      return va == null && vb == null ? 0 : va == null ? 1 : -1;
    }
    return dir * cmpSortValues(va, vb);
  });
}

function clickSort(tableId, sortState, rerender, cols) {
  const allowed = cols || DEST_COLS;
  $(tableId).tHead.addEventListener("click", (event) => {
    const th = event.target.closest("th.sortable");
    if (!th) return;
    applySortClick(th, sortState, allowed);
    applySortIndicators(tableId, sortState);
    rerender();
  });
}

// clickSortDelegated is clickSort for tables whose thead is regenerated on
// every render (the connection history groups) — the listener lives on the
// stable container instead. Sub-table headers (th.sub-sortable) carry their
// own sort and are skipped here.
function clickSortDelegated(containerId, sortState, rerender, cols) {
  $(containerId).addEventListener("click", (event) => {
    const th = event.target.closest("th.sortable");
    if (!th || th.classList.contains("sub-sortable")) return;
    const col = th.dataset.sort;
    if (!cols.includes(col)) return;
    applySortClick(th, sortState, cols);
    applySortIndicators(containerId, sortState);
    rerender();
  });
}

function applySortClick(th, sortState, allowed) {
  const col = th.dataset.sort;
  if (!allowed.includes(col)) return false;
  if (sortState.col === col) {
    sortState.dir = -sortState.dir;
  } else {
    sortState.col = col;
    sortState.dir = NUMERIC_SORT_COLS.has(col) ? -1 : 1;
  }
  return true;
}

// applySortIndicators paints the ▲/▼ on the sorted header of a table (and
// clears the rest) — also used to show a table's default order at load.
// Sub-table headers paint their own arrows inline (they are rebuilt on
// every render), so they are excluded here.
function applySortIndicators(root, sort) {
  const el = typeof root === "string" ? $(root) : root;
  if (!el) return;
  el.querySelectorAll("th.sortable:not(.sub-sortable)").forEach((th) => {
    if (th.dataset.sort === sort.col) {
      th.dataset.dir = sort.dir === 1 ? "asc" : "desc";
    } else {
      delete th.dataset.dir;
    }
  });
}

/* ---- sub-table sorting: the detail tables inside an expanded group (IPs
   under a site, sites under an app, observations under a process, …) toggle
   asc/desc on their own headers — one shared sort per parent table,
   independent of the summary-row sort. The headers are rebuilt on every
   render, so the arrow is painted inline and clicks are delegated to the
   stable table/container. */
function subHeadHTML(cols, sort) {
  const cells = cols.map(([key, label]) => {
    if (!key) return `<th>${label}</th>`;
    const dir = sort.col === key ? ` data-dir="${sort.dir === 1 ? "asc" : "desc"}"` : "";
    return `<th class="sortable sub-sortable" data-sort="${key}"${dir}>${label}</th>`;
  }).join("");
  return `<thead><tr>${cells}</tr></thead>`;
}

function clickSubSort(targetId, sortState, rerender, cols) {
  $(targetId).addEventListener("click", (event) => {
    const th = event.target.closest("th.sub-sortable");
    if (!th) return;
    if (!applySortClick(th, sortState, cols)) return;
    rerender();
  });
}

/* Expand all / collapse all for the groupable tables. Expand affects the
   groups currently visible after filtering (each render stashes their
   keys in state); collapse clears the whole set. The buttons hide while a
   table is in a flat (ungrouped) mode. */
function wireGroupToggles(expandId, collapseId, keySource, expandedSet, rerender) {
  $(expandId).addEventListener("click", () => {
    for (const key of keySource()) expandedSet.add(key);
    rerender();
  });
  $(collapseId).addEventListener("click", () => {
    expandedSet.clear();
    rerender();
  });
}

function setGroupTogglesVisible(expandId, collapseId, visible) {
  $(expandId).hidden = !visible;
  $(collapseId).hidden = !visible;
}

function countryCellHTML(row) {
  if (!row.cc) return '<span class="geo-cell dim" title="geo lookup pending">…</span>';
  const tip = [row.country, row.org].filter(Boolean).join(" · ");
  return `<span class="geo-cell"${tip ? ` title="${esc(tip)}"` : ""}>` +
    `${flagImgHTML(row.cc)} ${esc(row.cc)}` +
    (row.country ? ` ${esc(row.country)}` : "") + "</span>";
}

function activeCellHTML(count) {
  return count ? String(count) : '<span class="dim">—</span>';
}

function bytesCellHTML(total) {
  return total ? fmtBytes(total) : '<span class="dim">—</span>';
}

function lastSeenCellHTML(ts) {
  if (!ts) return '<span class="dim">—</span>';
  return `<span title="${esc(fmtTime(ts))}">${fmtAgo(ts)}</span>`;
}

/* Connections by country: grouped mode rolls the per-IP rows up into one
   summary row per country (expand for the IPs — some users prefer the flat
   list, which is the other mode); flat mode is one row per IP. */
function countryBlockBtnHTML(cc) {
  return ` <button class="mini-btn" data-bcc="${esc(cc)}" ` +
    `data-bname="${esc(blockCountryLabel(cc))}" title="block all traffic ` +
    `to/from ${esc(cc)}" aria-label="block all traffic to/from ${esc(cc)}">&#9940;</button>`;
}

/* name for an IP row: geo/rDNS hostname when known, else the owning org,
   else the bare IP (title always carries the IP so nothing is hidden) */
function ipNameCellHTML(row) {
  const name = row.reverse || row.org || row.ip;
  const tip = [row.ip, row.reverse, row.org].filter(Boolean).join(" · ");
  const isIP = name === row.ip;
  return `<span class="${isIP ? "mono" : ""}" title="${esc(tip)}">` +
    `${esc(name)}${isIP ? "" : ""}</span>`;
}

function countryFlatRowHTML(row) {
  return `<tr><td>${countryCellHTML(row)}${row.cc ? countryBlockBtnHTML(row.cc) : ""}</td>` +
    `<td>${ipNameCellHTML(row)}${freshBadge(row.first_seen)}</td>` +
    `<td class="dim">${esc((row.apps || []).join(", ") || "—")}</td>` +
    `<td>${row.connections || 0}</td>` +
    `<td>${activeCellHTML(row.open)}</td>` +
    `<td class="dim" title="summed across connection lifecycles">${fmtDuration(row.seconds || 0)}</td>` +
    `<td class="mono">${bytesCellHTML(row.bytes_in)}</td>` +
    `<td class="mono">${bytesCellHTML(row.bytes_out)}</td>` +
    `<td class="dim">${lastSeenCellHTML(row.last_seen)}</td></tr>`;
}

/* per-IP detail row inside an expanded country (Connections by country) or
   site (Sites & apps) group — columns mirror IP_SUB_COLS */
function ipSubRowHTML(row) {
  return `<tr><td>${countryCellHTML(row)}</td>` +
    `<td>${ipNameCellHTML(row)}${freshBadge(row.first_seen)}</td>` +
    `<td class="dim">${esc((row.apps || []).join(", ") || "—")}</td>` +
    `<td>${row.connections || 0}</td>` +
    `<td>${activeCellHTML(row.open)}</td>` +
    `<td class="dim" title="summed across connection lifecycles">${fmtDuration(row.seconds || 0)}</td>` +
    `<td class="mono">${bytesCellHTML(row.bytes_in)}</td>` +
    `<td class="mono">${bytesCellHTML(row.bytes_out)}</td>` +
    `<td class="dim">${lastSeenCellHTML(row.last_seen)}</td></tr>`;
}

function renderGeoCountries() {
  const country = $("geo-countries-country").value;
  const app = $("geo-countries-app").value;
  const activeOnly = $("geo-countries-active").checked;
  const query = $("filter-geo-countries").value.trim().toLowerCase();
  const rows = (state.destinations.countries || []).filter((row) => {
    if (country === liveNoGeo) {
      if (row.cc) return false;
    } else if (country && row.cc !== country) {
      return false;
    }
    if (app && !(row.apps || []).includes(app)) return false;
    if (activeOnly && !row.open) return false;
    return !query || JSON.stringify(row).toLowerCase().includes(query);
  });

  const body = $("tbl-geo-countries").tBodies[0];
  if (state.countriesMode === "flat") {
    setGroupTogglesVisible("geo-expand-all", "geo-collapse-all", false);
    body.innerHTML = sortRowsBy(rows, state.sortGeo)
      .map((row) => countryFlatRowHTML(row)).join("") ||
      '<tr><td colspan="9" class="dim">no external destinations match these filters</td></tr>';
    const total = state.destinations.countries.length;
    $("geo-countries-count").textContent =
      `${rows.length} of ${total} IP${total === 1 ? "" : "s"}`;
    return;
  }
  setGroupTogglesVisible("geo-expand-all", "geo-collapse-all", true);

  // grouped: one summary row per country, expandable to a sortable IP table
  const groups = new Map();
  for (const row of rows) {
    const key = row.cc || "__nogeo__";
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(row);
  }
  const aggregates = sortRowsBy([...groups.entries()].map(([cc, group]) => {
    const agg = {
      cc: cc === "__nogeo__" ? "" : cc,
      country: cc === "__nogeo__" ? "" : group[0].country,
      sortName: (cc === "__nogeo__" ? "" :
        group[0].country || cc).toLowerCase() || "no geo",
      ip: group.length, // "Remote IP" column sorts by IP count when grouped
      ips: group.length,
      connections: 0, open: 0, seconds: 0, bytes_in: 0, bytes_out: 0,
      last_seen: 0, apps: new Set(), ip_rows: group,
    };
    for (const r of group) {
      agg.connections += r.connections || 0;
      agg.open += r.open || 0;
      agg.seconds += r.seconds || 0;
      agg.bytes_in += r.bytes_in || 0;
      agg.bytes_out += r.bytes_out || 0;
      if (r.last_seen > agg.last_seen) agg.last_seen = r.last_seen;
      (r.apps || []).forEach((a) => agg.apps.add(a));
    }
    agg.apps = [...agg.apps];
    return agg;
  }), state.sortGeo);
  state.visibleCountryGroupKeys =
    aggregates.map((agg) => `country\u0000${agg.cc || "__nogeo__"}`);

  body.innerHTML = aggregates.map((agg) => {
    const key = `country\u0000${agg.cc || "__nogeo__"}`;
    const expanded = state.expandedCountryGroups.has(key);
    const expandButton = `<button class="connection-expand" type="button" ` +
      `data-group="${esc(encodeURIComponent(key))}" aria-expanded="${expanded}" ` +
      `title="${expanded ? "Hide" : "Show"} the IPs of this country" ` +
      `aria-label="${expanded ? "Hide" : "Show"} IPs">${expanded ? "−" : "+"}</button>`;
    const appsShown = agg.apps.slice(0, 3).join(", ") +
      (agg.apps.length > 3 ? ` +${agg.apps.length - 3}` : "");
    const summary = `<tr class="connection-process-row">` +
      `<td class="connection-app-cell">${expandButton}${countryCellHTML(agg)}${agg.cc ? countryBlockBtnHTML(agg.cc) : ""}</td>` +
      `<td class="mono" title="${esc(agg.ip_rows.map((r) => r.ip).join("\n"))}">${agg.ips} IP${agg.ips === 1 ? "" : "s"}</td>` +
      `<td class="dim" title="${esc(agg.apps.join(", "))}">${esc(appsShown || "—")}</td>` +
      `<td>${agg.connections}</td>` +
      `<td>${activeCellHTML(agg.open)}</td>` +
      `<td class="dim" title="summed across connection lifecycles">${fmtDuration(agg.seconds)}</td>` +
      `<td class="mono">${bytesCellHTML(agg.bytes_in)}</td>` +
      `<td class="mono">${bytesCellHTML(agg.bytes_out)}</td>` +
      `<td class="dim">${lastSeenCellHTML(agg.last_seen)}</td></tr>`;
    const details = expanded
      ? `<tr class="connection-detail-row"><td colspan="9"><div class="tbl-wrap"><table>` +
        subHeadHTML(IP_SUB_COLS, state.sortGeoSub) +
        `<tbody>${sortRowsBy(agg.ip_rows, state.sortGeoSub)
          .map(ipSubRowHTML).join("")}</tbody></table></div></td></tr>`
      : "";
    return summary + details;
  }).join("") ||
    '<tr><td colspan="9" class="dim">no external destinations match these filters</td></tr>';

  const allRows = state.destinations.countries;
  const allCountries = new Set(allRows.map((r) => r.cc || "__nogeo__")).size;
  $("geo-countries-count").textContent = `${aggregates.length} of ${allCountries} countr${allCountries === 1 ? "y" : "ies"} · ${rows.length} IP${rows.length === 1 ? "" : "s"}`;
}

/* Sites & apps rows mirror the connection history panel: one summary row
   per group (site or app) with a +/− expand revealing the detail rows —
   per-IP under a site, per-site under an app. Grouping key lives in
   state.sitesGroupBy; expanded groups survive re-renders in a Set. */
function siteNameHTML(group) {
  const name = group.label || group.host;
  const domainTag = group.label && group.label !== group.host
    ? `<span class="dest-domain">${esc(group.host)}</span>` : "";
  return `<span class="connection-app">${esc(name)}</span>${domainTag}${freshBadge(group.first_seen)}`;
}

function renderSites() {
  const groupBy = state.sitesGroupBy; // site | app | flat
  const appFilter = $("sites-app").value;
  const activeOnly = $("sites-active").checked;
  const query = $("filter-sites").value.trim().toLowerCase();
  const matches = (text) => !query || String(text).toLowerCase().includes(query);

  const body = $("tbl-sites").tBodies[0];
  let html = "";
  let visible = 0;

  if (groupBy === "flat") {
    // one row per app + site — for users who prefer no expand/collapse
    setGroupTogglesVisible("sites-expand-all", "sites-collapse-all", false);
    let rows = [];
    for (const app of state.destinations.apps || []) {
      for (const sub of app.sites || []) {
        rows.push({
          app: app.app, sortName: (sub.label || sub.host || "").toLowerCase(),
          host: sub.host, label: sub.label, ips: sub.ips,
          connections: sub.connections, open: sub.open, seconds: sub.seconds,
          bytes_in: sub.bytes_in, bytes_out: sub.bytes_out,
          last_seen: sub.last_seen, first_seen: sub.first_seen,
        });
      }
    }
    rows = rows.filter((row) => {
      if (appFilter && row.app !== appFilter) return false;
      if (activeOnly && !row.open) return false;
      return !query || matches(row.host) || matches(row.label) || matches(row.app);
    });
    rows = sortRowsBy(rows, state.sortSites);
    visible = rows.length;
    html = rows.map((row) =>
      `<tr><td>${siteNameHTML(row)}</td>` +
      `<td class="dim">${esc(row.app)}</td>` +
      `<td>${row.ips || 0}</td>` +
      `<td>${row.connections || 0}</td>` +
      `<td>${activeCellHTML(row.open)}</td>` +
      `<td class="dim" title="summed across connection lifecycles">${fmtDuration(row.seconds || 0)}</td>` +
      `<td class="mono" title="per-socket TCP counters">${bytesCellHTML(row.bytes_in)}</td>` +
      `<td class="mono" title="per-socket TCP counters">${bytesCellHTML(row.bytes_out)}</td>` +
      `<td class="dim">${lastSeenCellHTML(row.last_seen)}</td></tr>`).join("");
  } else {
    setGroupTogglesVisible("sites-expand-all", "sites-collapse-all", true);
    const groups = [];
    for (const site of state.destinations.sites || []) {
      if (groupBy !== "site") continue;
      if (appFilter && !(site.apps || []).includes(appFilter)) continue;
      if (activeOnly && !site.open) continue;
      const children = (site.ip_rows || []).filter((row) =>
        matches(row.ip) || matches((row.apps || []).join(" ")) || matches(site.host));
      const groupText = `${site.host} ${site.label || ""} ${(site.apps || []).join(" ")}`;
      if (query && !matches(groupText) && children.length === 0) continue;
      groups.push({
        key: `site\u0000${site.host}`,
        summary: { ...site, sortName: (site.label || site.host || "").toLowerCase() },
        // spread the stats onto the wrapper: the sort reads them at the top
        // level (ips, connections, seconds, bytes_in, ...)
        ...site, sortName: (site.label || site.host || "").toLowerCase(),
        isSite: true, children,
      });
    }
    for (const app of state.destinations.apps || []) {
      if (groupBy !== "app") continue;
      if (appFilter && app.app !== appFilter) continue;
      if (activeOnly && !app.open) continue;
      const children = (app.sites || []).filter((site) =>
        matches(site.host) || matches(site.label) || matches(app.app));
      if (query && !matches(app.app) && children.length === 0) continue;
      const summary = {
        app: app.app, sortName: app.app.toLowerCase(),
        apps: (app.sites || []).length, // "Apps / sites" column sorts by this
        ips: (app.sites || []).reduce((n, s) => n + (s.ips || 0), 0),
        connections: app.connections, open: app.open, seconds: app.seconds,
        bytes_in: app.bytes_in, bytes_out: app.bytes_out,
        last_seen: app.last_seen, sites: app.sites || [],
      };
      groups.push({
        key: `app\u0000${app.app}`,
        summary,
        ...summary, // top-level stats for the sort
        isSite: false, children,
      });
    }
    const sorted = sortRowsBy(groups, state.sortSites);
    visible = sorted.length;
    state.visibleSiteGroupKeys = sorted.map(({ key }) => key);
    html = sorted.map(({ key, summary, isSite, children }) => {
      const expanded = state.expandedDestGroups.has(key);
      const name = isSite ? siteNameHTML(summary) :
        `<span class="connection-app">${esc(summary.app)}</span>`;
      const secondCell = isSite
        ? `<td class="dim">${esc((summary.apps || []).join(", ") || "—")}</td>`
        : `<td class="dim">${(summary.apps || 0)} site${summary.apps === 1 ? "" : "s"}</td>`;
      const ipCount = summary.ips || 0;
      const expandButton = `<button class="connection-expand" type="button" ` +
        `data-group="${esc(encodeURIComponent(key))}" aria-expanded="${expanded}" ` +
        `title="${expanded ? "Hide" : "Show"} ${isSite ? "IPs" : "sites"}" ` +
        `aria-label="${expanded ? "Hide" : "Show"} ${isSite ? "IPs" : "sites"}">` +
        `${expanded ? "−" : "+"}</button>`;
      const bytesTitle = isSite
        ? 'title="per-socket TCP counters"'
        : 'title="per-process totals (TCP+UDP) — includes traffic the site rows can\'t attribute"';
      const summaryRow = `<tr class="connection-process-row">` +
        `<td class="connection-app-cell">${expandButton}${name}</td>` +
        secondCell +
        `<td>${ipCount}</td>` +
        `<td>${summary.connections || 0}</td>` +
        `<td>${activeCellHTML(summary.open)}</td>` +
        `<td class="dim" title="summed across connection lifecycles">${fmtDuration(summary.seconds || 0)}</td>` +
        `<td class="mono" ${bytesTitle}>${bytesCellHTML(summary.bytes_in)}</td>` +
        `<td class="mono" ${bytesTitle}>${bytesCellHTML(summary.bytes_out)}</td>` +
        `<td class="dim">${lastSeenCellHTML(summary.last_seen)}</td></tr>`;

      let detailRowsHTML = "";
      let detailCols;
      if (isSite) {
        detailCols = IP_SUB_COLS;
        detailRowsHTML = sortRowsBy(children, state.sortSitesSub)
          .map(ipSubRowHTML).join("");
      } else {
        detailCols = SITE_SUB_COLS;
        detailRowsHTML = sortRowsBy(children, state.sortSitesSub).map((sub) =>
          `<tr><td>${siteNameHTML(sub)}</td>` +
          `<td>${sub.ips || 0}</td>` +
          `<td>${sub.connections || 0}</td>` +
          `<td>${activeCellHTML(sub.open)}</td>` +
          `<td class="dim">${fmtDuration(sub.seconds || 0)}</td>` +
          `<td class="mono" title="per-socket TCP counters">${bytesCellHTML(sub.bytes_in)}</td>` +
          `<td class="mono" title="per-socket TCP counters">${bytesCellHTML(sub.bytes_out)}</td>` +
          `<td class="dim">${lastSeenCellHTML(sub.last_seen)}</td></tr>`).join("");
      }
      const detail = expanded
        ? `<tr class="connection-detail-row"><td colspan="9"><div class="tbl-wrap"><table>` +
          subHeadHTML(detailCols, state.sortSitesSub) +
          `<tbody>${detailRowsHTML}</tbody></table></div></td></tr>`
        : "";
      return summaryRow + detail;
    }).join("");
  }

  body.innerHTML = html ||
    '<tr><td colspan="9" class="dim">no sites match these filters</td></tr>';
  const unit = groupBy === "site" ? "site"
    : groupBy === "app" ? "app" : "destination";
  const total = groupBy === "site"
    ? state.destinations.sites.length
    : groupBy === "app" ? state.destinations.apps.length
    : (state.destinations.apps || []).reduce((n, a) => n + (a.sites || []).length, 0);
  $("sites-count").textContent =
    `${visible} of ${total} ${unit}${total === 1 ? "" : "s"}`;
}

function connectionScope(connection) {
  if (connection.scope === "external") return "external";
  if (connection.scope === "lan" || connection.scope === "loopback") return "internal";
  return "other";
}

// Mirrors the backend's connStateAliases (netstate.go): collapses each
// platform's spelling onto one canonical name so the state dropdown groups
// rows consistently even if a raw spelling slips through un-normalised.
const liveConnStateAliases = {
  ESTAB: "ESTABLISHED", SYNSENT: "SYN_SENT", SYNRCVD: "SYN_RECV",
  SYNRECV: "SYN_RECV", SYNRECEIVED: "SYN_RECV", FINWAIT1: "FIN_WAIT_1",
  FINWAIT2: "FIN_WAIT_2", CLOSEWAIT: "CLOSE_WAIT", LASTACK: "LAST_ACK",
  TIMEWAIT: "TIME_WAIT",
};

function NormalizeLiveConnState(connection) {
  const raw = String(connection.state || "").toUpperCase();
  if (!raw) return "";
  return liveConnStateAliases[raw.replace(/[-_]/g, "")] || raw;
}

/* one flat live-connection row (used by the flat list and by the detail
   tables inside expanded app groups) */
function liveConnRowHTML(connection) {
  const remote = endpoint(connection.remote_ip, connection.remote_port);
  const local = endpoint(connection.local_ip, connection.local_port);
  const blockButton = connection.remote_ip
    ? `<button class="mini-btn" data-btype="ip" data-bip="${esc(connection.remote_ip)}" ` +
      `title="block all traffic to/from ${esc(connection.remote_ip)}" ` +
      `aria-label="block all traffic to/from ${esc(connection.remote_ip)}">&#9940;</button>` : "";  const allowButton = connection.remote_ip
    ? `<button class="mini-btn allow-btn" data-btype="allowip" data-aip="${esc(connection.remote_ip)}" ` +
      `title="allow all traffic to/from ${esc(connection.remote_ip)} (overrides block rules)" ` +
      `aria-label="allow all traffic to/from ${esc(connection.remote_ip)}">&#9989;</button>` : "";
  const appButton = connection.app
    ? `<button class="mini-btn" data-btype="app" data-bapp="${esc(connection.app)}" ` +
      `data-bpid="${esc(connection.pid ?? "")}" title="block this app" ` +
      `aria-label="block the app ${esc(connection.app)}">&#128683;</button>` : "";
  const duration = connection.first_seen == null
    ? '<span class="dim">—</span>'
    : `<span class="conn-duration" data-first-seen="${Number(connection.first_seen)}">…</span>`;
  return `<tr><td>${esc(connection.app || "Unknown")}</td>` +
    `<td>${esc(connection.pid ?? "—")}</td><td>${esc(connection.user || "—")}</td>` +
    `<td>${esc(String(connection.proto || "—").toUpperCase())}</td>` +
    `<td class="mono">${esc(remote || "—")} ` +
      `<span class="scope scope-${esc(connection.scope || "other")}">${esc(connectionScope(connection))}</span>${freshBadge(connection.dest_first_seen)}</td>` +
    `<td class="dim">${esc(connection.service || "")}` +
    `${connection.host ? ` · ${esc(connection.host)}` :
      connection.geo_reverse ? ` · ${esc(connection.geo_reverse)}` :
      connection.geo_org ? ` · ${esc(connection.geo_org)}` : ""}</td>` +
    `<td class="mono dim">${esc(local || "—")}</td>` +
    `<td>${geoCellHTML(connection)}</td>` +
    `<td class="dim">${duration}</td>` +
    `<td class="mono">${connection.bytes_in == null ? "—" : fmtBytes(connection.bytes_in)}</td>` +
    `<td class="mono">${connection.bytes_out == null ? "—" : fmtBytes(connection.bytes_out)}</td>` +
    `<td class="dim">${esc(connection.state || "—")}</td>` +
    `<td class="blockcell">${dnsBlockBtnHtml(connection)}${blockButton}${allowButton}${appButton}</td></tr>`;
}

/* compact cell text: the first items joined, then "+N" for the rest */
function joinLimited(items, max) {
  if (!items.length) return "";
  const shown = items.slice(0, max).join(" · ");
  return items.length > max ? `${shown} +${items.length - max}` : shown;
}

/* app-level block button for a grouped live-connections summary row */
function appBlockBtnHTML(group) {
  return `<button class="mini-btn" data-btype="app" data-bapp="${esc(group.app)}" ` +
    `data-bpid="${esc(group.pids[0] ?? "")}" title="block this app" ` +
    `aria-label="block the app ${esc(group.app)}">&#128683;</button>`;
}

function renderLiveConnections() {
  const query = $("filter-live-conns").value.trim().toLowerCase();
  const app = $("app-live-conns").value;
  const scope = $("scope-live-conns").value;
  const geoCountry = $("geo-live-conns").value;
  const geoCity = $("geo-city-live-conns").value;
  const stateFilter = $("state-live-conns").value;
  const rows = (state.liveConnections || []).filter((connection) => {
    if (app && connection.app !== app) return false;
    if (scope && connectionScope(connection) !== scope) return false;
    if (geoCountry === liveNoGeo) {
      if (connection.geo_cc) return false;
    } else if (geoCountry && connection.geo_cc !== geoCountry) {
      return false;
    }
    if (geoCity && connection.geo_city !== geoCity) return false;
    if (stateFilter && NormalizeLiveConnState(connection) !== stateFilter) return false;
    return !query || JSON.stringify(connection).toLowerCase().includes(query);
  });
  const body = $("tbl-live-conns").tBodies[0];
  if (state.liveGroupBy !== "app") {
    setGroupTogglesVisible("live-expand-all", "live-collapse-all", false);
    body.innerHTML = sortRowsBy(rows, state.sortLive).map(liveConnRowHTML).join("") ||
      '<tr><td colspan="13" class="dim">no live connections match these filters</td></tr>';
    tickConnectionDurations();
    return;
  }

  // grouped by app name: one summary row per app with rolled-up counts, the
  // app's connections in an expandable detail table
  const groups = new Map();
  for (const connection of rows) {
    const name = connection.app || "Unknown";
    if (!groups.has(name)) groups.set(name, []);
    groups.get(name).push(connection);
  }
  const groupRows = [...groups.entries()].map(([name, conns]) => {
    const distinct = (pick) =>
      [...new Set(conns.map(pick).filter(Boolean))];
    const pids = distinct((c) => String(c.pid ?? ""));
    const users = distinct((c) => c.user);
    const protos = distinct((c) => String(c.proto || "").toUpperCase());
    const services = distinct((c) => String(c.service || c.host || "").trim());
    const remotes = distinct((c) => c.remote_ip);
    const ccs = distinct((c) => c.geo_cc);
    const states = distinct((c) => NormalizeLiveConnState(c) ||
      String(c.state || "").toUpperCase());
    let bytesIn = 0, bytesOut = 0, firstSeen = null;
    for (const c of conns) {
      bytesIn += c.bytes_in || 0;
      bytesOut += c.bytes_out || 0;
      if (c.first_seen != null &&
          (firstSeen == null || c.first_seen < firstSeen)) firstSeen = c.first_seen;
    }
    return {
      key: name, app: name, conns, pids, users, protos, services, remotes, ccs, states,
      // rolled-up sort values for the main header clicks
      pid: pids.length,            // PID column sorts by process count
      user: users.join(", "),
      proto: protos.join(" · "),
      remote_ip: remotes.length,   // Remote shows the connection count
      service: services.join(" · "),
      geo_cc: ccs.join(","),
      state: states.join(" · "),
      first_seen: firstSeen, bytes_in: bytesIn, bytes_out: bytesOut,
    };
  });
  state.visibleLiveGroupKeys = groupRows.map((group) => group.key);
  setGroupTogglesVisible("live-expand-all", "live-collapse-all", true);
  body.innerHTML = sortRowsBy(groupRows, state.sortLive).map((group) => {
    const expanded = state.expandedLiveGroups.has(group.key);
    const expandButton = `<button class="connection-expand" type="button" ` +
      `data-group="${esc(encodeURIComponent(group.key))}" aria-expanded="${expanded}" ` +
      `title="${expanded ? "Hide" : "Show"} the connections of this app" ` +
      `aria-label="${expanded ? "Hide" : "Show"} connections">${expanded ? "−" : "+"}</button>`;
    const pidLabel = group.pids.length > 1
      ? `${group.pids.length} pids` : (group.pids[0] || "—");
    const flags = group.ccs.slice(0, 4).map(flagImgHTML).join(" ");
    const duration = group.first_seen == null
      ? '<span class="dim">—</span>'
      : `<span class="conn-duration" data-first-seen="${Number(group.first_seen)}">…</span>`;
    const summary = `<tr class="connection-process-row">` +
      `<td class="connection-app-cell">${expandButton}` +
      `<span class="connection-app">${esc(group.app)}</span></td>` +
      `<td class="mono" title="${esc(group.pids.join(", "))}">${esc(pidLabel)}</td>` +
      `<td class="dim" title="${esc(group.users.join(", "))}">${esc(joinLimited(group.users, 2)) || "—"}</td>` +
      `<td class="dim">${esc(joinLimited(group.protos, 3)) || "—"}</td>` +
      `<td title="${group.conns.length} connection${group.conns.length === 1 ? "" : "s"} · ` +
      `${group.remotes.length} remote endpoint${group.remotes.length === 1 ? "" : "s"}">` +
      `<span class="conn-count">${group.conns.length}</span> <span class="dim">conn</span></td>` +
      `<td class="dim" title="${esc(group.services.join(" · "))}">${esc(joinLimited(group.services, 2)) || "—"}</td>` +
      `<td class="dim">—</td>` +
      `<td title="${esc(group.ccs.join(", "))}">${flags || '<span class="dim">—</span>'}</td>` +
      `<td class="dim">${duration}</td>` +
      `<td class="mono">${group.bytes_in ? fmtBytes(group.bytes_in) : "—"}</td>` +
      `<td class="mono">${group.bytes_out ? fmtBytes(group.bytes_out) : "—"}</td>` +
      `<td class="dim" title="${esc(group.states.join(", "))}">${esc(joinLimited(group.states, 2)) || "—"}</td>` +
      `<td class="blockcell">${group.app === "Unknown" ? "" : appBlockBtnHTML(group)}</td></tr>`;
    const details = expanded
      ? `<tr class="connection-detail-row"><td colspan="13"><div class="tbl-wrap"><table>` +
        subHeadHTML(LIVE_SUB_COLS, state.sortLiveSub) +
        `<tbody>${sortRowsBy(group.conns, state.sortLiveSub)
          .map(liveConnRowHTML).join("")}</tbody></table></div></td></tr>`
      : "";
    return summary + details;
  }).join("") || '<tr><td colspan="13" class="dim">no live connections match these filters</td></tr>';
  tickConnectionDurations();
}

/* Live connection durations tick every second straight from the DOM — no
   refetch needed; the first-seen timestamp rides on each cell. */
function tickConnectionDurations() {
  if (state.paused || document.hidden) return;
  const now = Date.now() / 1000;
  for (const cell of $("tbl-live-conns").querySelectorAll(".conn-duration[data-first-seen]")) {
    cell.textContent = fmtDuration(now - parseFloat(cell.dataset.firstSeen));
  }
}

function endpoint(address, port) {
  if (!address) return "";
  return port == null || port === "" ? String(address) : `${address}:${port}`;
}

async function loadTraffic() {
  try {
    const t = await getJSON("/api/traffic");
    const hist = t.history || [];
    state.trafficHistory = hist;
    if (hist.length) {
      const latest = hist[hist.length - 1];
      $("card-rx").textContent = fmtRate(latest.in);
      $("card-tx").textContent = fmtRate(latest.out);
    }
    if (state.trafficTotals === null) {
      state.trafficTotals = t.totals || null;
      renderTrafficTotals();
    }
    drawChart(hist, chartHover);
    renderTopApps(t.app_rates || {}, t.app_connections || {});
  } catch (e) {
    console.warn("traffic", e);
    if (state.trafficTotals === null) {
      $("traffic-totals-body").innerHTML =
        `<tr><td colspan="4" class="dim">could not load transfer totals: ${esc(e.message)}</td></tr>`;
    }
  }
}

function renderTrafficTotals() {
  const range = $("traffic-range").value;
  const names = {
    hour: "Last hour", six_hours: "Last 6 hours", day: "Last 24 hours",
    since_boot: "Since boot",
    session: "Since this session", retained: "All recorded",
  };
  const total = state.trafficTotals && state.trafficTotals[range];
  const available = total && total.available === true;
  const coverage = available
    ? range === "since_boot" ? "Interface counters; may reset on adapter restart"
      : `Since ${fmtTime(total.since)}`
    : `No baseline available for ${names[range]}`;
  $("traffic-totals-body").innerHTML =
    `<tr><td>${names[range]}</td><td>${available ? fmtBytes(total.rx) : "—"}</td>` +
    `<td>${available ? fmtBytes(total.tx) : "—"}</td><td class="dim">${esc(coverage)}</td></tr>`;
}

$("traffic-range").addEventListener("change", async () => {
  try {
    const totals = await getJSON("/api/traffic");
    state.trafficTotals = totals.totals || null;
    renderTrafficTotals();
  } catch (error) {
    console.warn("traffic totals", error);
    $("traffic-totals-body").innerHTML =
      `<tr><td colspan="4" class="dim">could not load transfer totals: ${esc(error.message)}</td></tr>`;
  }
});

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

// live events keep the summary card counting between the periodic refreshes
function bumpEventCard() {
  const card = $("card-events");
  const n = Number(card.textContent);
  if (Number.isFinite(n)) card.textContent = n + 1;
}

/* -------------------------------------------------------------- chart -- */
const CHART_HEIGHT = 130;
const chartPad = { l: 60, r: 12, t: 10, b: 20 };

function withAlpha(color, alpha) {
  if (/^#[0-9a-f]{6}$/i.test(color)) {
    const r = parseInt(color.slice(1, 3), 16);
    const g = parseInt(color.slice(3, 5), 16);
    const b = parseInt(color.slice(5, 7), 16);
    return `rgba(${r},${g},${b},${alpha})`;
  }
  return color; // unexpected format: use solid
}

function fmtClock(ts) {
  return new Date(ts * 1000).toLocaleTimeString(undefined,
    { hour: "2-digit", minute: "2-digit", hour12: false });
}

function chartGeometry(hist) {
  const cv = $("chart");
  const w = cv.clientWidth, h = CHART_HEIGHT;
  const max = Math.max(...hist.map((p) => Math.max(p.in, p.out)), 1);
  const X = (i) => chartPad.l + (i / Math.max(1, hist.length - 1)) * (w - chartPad.l - chartPad.r);
  const Y = (v) => h - chartPad.b - (v / max) * (h - chartPad.t - chartPad.b);
  return { cv, w, h, max, X, Y };
}

function drawChart(hist, hoverIndex = -1) {
  hist = hist || [];
  const { cv, w, h, max, X, Y } = chartGeometry(hist);
  const dpr = window.devicePixelRatio || 1;
  cv.width = w * dpr; cv.height = h * dpr;
  const g = cv.getContext("2d");
  g.scale(dpr, dpr);
  g.clearRect(0, 0, w, h);
  if (hist.length < 2) return;
  const styles = getComputedStyle(document.documentElement);
  const accent = styles.getPropertyValue("--accent").trim();
  const green = styles.getPropertyValue("--green").trim();
  // horizontal grid + rate labels
  g.strokeStyle = styles.getPropertyValue("--line").trim();
  g.fillStyle = styles.getPropertyValue("--dim").trim();
  g.font = "10px sans-serif"; g.textAlign = "right";
  for (let i = 0; i <= 3; i++) {
    const v = (max / 3) * i, y = Y(v);
    g.beginPath(); g.moveTo(chartPad.l, y); g.lineTo(w - chartPad.r, y); g.stroke();
    g.fillText(fmtRate(v), chartPad.l - 6, y + 3);
  }
  // time ticks on the x axis (clamped so edge labels stay inside the plot)
  g.textAlign = "center";
  const ticks = Math.min(4, hist.length - 1);
  for (let i = 0; i <= ticks; i++) {
    const idx = Math.round((i / ticks) * (hist.length - 1));
    const lx = Math.min(Math.max(X(idx), chartPad.l + 18), w - chartPad.r - 18);
    g.fillText(fmtClock(hist[idx].ts), lx, h - 6);
  }
  // soft area fill + line per series
  const series = (key, color) => {
    const baseline = h - chartPad.b;
    const grad = g.createLinearGradient(0, chartPad.t, 0, baseline);
    grad.addColorStop(0, withAlpha(color, 0.22));
    grad.addColorStop(1, withAlpha(color, 0));
    g.beginPath();
    hist.forEach((p, i) => i ? g.lineTo(X(i), Y(p[key])) : g.moveTo(X(0), Y(p[key])));
    g.lineTo(X(hist.length - 1), baseline);
    g.lineTo(X(0), baseline);
    g.closePath();
    g.fillStyle = grad;
    g.fill();
    g.strokeStyle = color; g.lineWidth = 1.6;
    g.lineJoin = "round"; g.lineCap = "round";
    g.beginPath();
    hist.forEach((p, i) => i ? g.lineTo(X(i), Y(p[key])) : g.moveTo(X(0), Y(p[key])));
    g.stroke();
  };
  series("in", accent);
  series("out", green);
  // hover crosshair + sample points
  if (hoverIndex >= 0 && hoverIndex < hist.length) {
    g.strokeStyle = styles.getPropertyValue("--dim").trim();
    g.setLineDash([3, 3]);
    g.beginPath();
    g.moveTo(X(hoverIndex), chartPad.t);
    g.lineTo(X(hoverIndex), h - chartPad.b);
    g.stroke();
    g.setLineDash([]);
    for (const [key, color] of [["in", accent], ["out", green]]) {
      g.fillStyle = color;
      g.beginPath();
      g.arc(X(hoverIndex), Y(hist[hoverIndex][key]), 3, 0, Math.PI * 2);
      g.fill();
    }
  }
  g.textAlign = "left"; g.fillStyle = accent; g.fillText("↓ in", chartPad.l + 4, chartPad.t + 8);
  g.fillStyle = green; g.fillText("↑ out", chartPad.l + 44, chartPad.t + 8);
}

// hover tooltip: crosshair on canvas, values in a floating chip
const chartCanvas = $("chart");
const chartTooltip = document.createElement("div");
chartTooltip.className = "chart-tooltip";
chartTooltip.hidden = true;
chartCanvas.parentElement.append(chartTooltip);
let chartHover = -1;

chartCanvas.addEventListener("pointermove", (event) => {
  const hist = state.trafficHistory;
  if (hist.length < 2) return;
  const rect = chartCanvas.getBoundingClientRect();
  const usable = rect.width - chartPad.l - chartPad.r;
  if (usable <= 0) return;
  const index = Math.max(0, Math.min(hist.length - 1,
    Math.round((event.clientX - rect.left - chartPad.l) / usable * (hist.length - 1))));
  if (index === chartHover) return;
  chartHover = index;
  drawChart(hist, index);
  const point = hist[index];
  chartTooltip.innerHTML = `<b>${fmtClock(point.ts)}</b>` +
    ` <span style="color:var(--accent)">↓ ${esc(fmtRate(point.in))}</span>` +
    ` <span style="color:var(--green)">↑ ${esc(fmtRate(point.out))}</span>`;
  chartTooltip.hidden = false;
  const { cv, X, Y } = chartGeometry(hist);
  const half = chartTooltip.offsetWidth / 2;
  chartTooltip.style.left = `${Math.max(half + 2, Math.min(cv.clientWidth - half - 2, X(index)))}px`;
  // keep the chip inside the panel: peaks flip it below the sample point
  // (Y() is canvas-relative; the tooltip is positioned within the panel)
  const pointY = cv.offsetTop + Math.min(Y(point.in), Y(point.out));
  const flip = pointY - chartTooltip.offsetHeight - 12 < 0;
  chartTooltip.style.top = `${flip ? pointY + 16 : pointY - 10}px`;
  chartTooltip.style.transform = flip ? "translate(-50%, 0)" : "translate(-50%, -100%)";
});
chartCanvas.addEventListener("pointerleave", () => {
  chartHover = -1;
  chartTooltip.hidden = true;
  drawChart(state.trafficHistory, -1);
});

// redraw on window resize instead of waiting for the next traffic poll
let chartResizeFrame = 0;
window.addEventListener("resize", () => {
  cancelAnimationFrame(chartResizeFrame);
  chartResizeFrame = requestAnimationFrame(() =>
    drawChart(state.trafficHistory, chartHover));
});

/* ---------------------------------------------------------------- SSE -- */
let sse = null;
function connectSSE() {
  if (sse) sse.close();
  sse = new EventSource("/api/stream");
  sse.onopen = () => { $("sse-state").className = "dot dot-on"; $("footer-text").textContent = "live"; };
  sse.onmessage = (m) => {
    try {
      const msg = JSON.parse(m.data);
      if (msg.type === "event" && !state.paused) {
        handleEvent(msg.data);
        bumpEventCard();
      }
    } catch (e) { /* ignore */ }
  };
  sse.onerror = () => { $("sse-state").className = "dot dot-off"; $("footer-text").textContent = "reconnecting…"; };
}
$("pause").addEventListener("change", (e) => {
  state.paused = e.target.checked;
  if (!state.paused) refreshLiveViews();
});

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
    renderThermal(b.thermal);
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

/* Thermal readout: a "temp" detail row plus a banner when the machine
   needs to cool down (hot status from the collector: high temperature,
   recorded thermal warning, or active CPU throttling). */
function renderThermal(thermal) {
  const parts = [];
  if (thermal && thermal.battery_temp_c != null) {
    parts.push(`battery ${thermal.battery_temp_c}°C`);
  }
  if (thermal && thermal.cpu_temp_c != null) {
    parts.push(`${thermal.zone || "cpu"} ${thermal.cpu_temp_c}°C`);
  }
  if (thermal && thermal.throttle_percent != null &&
      thermal.throttle_percent < 100) {
    parts.push(`CPU throttled to ${thermal.throttle_percent}%`);
  }
  // battery-less desktops have no °C sensors on macOS, but the OS-level
  // thermal state is always there and is the cooling-down signal
  if (thermal && thermal.thermal_state_name) {
    parts.push(`machine ${thermal.thermal_state_name}`);
  }
  if (thermal && thermal.zones && thermal.zones.length > 1) {
    $("vd-temp").title = thermal.zones
      .map((z) => `${z.zone}: ${z.temp_c}°C`).join("\n");
  }
  $("vd-temp").textContent = parts.join(" · ") || "n/a";

  const alert = $("thermal-alert");
  const status = thermal && thermal.status;
  if (status === "hot") {
    alert.hidden = false;
    alert.className = "thermal-alert thermal-hot";
    alert.textContent = "🔥 Machine needs to cool down — " +
      (parts.join(", ") || "throttling active") +
      ". Close heavy apps, improve airflow, or let it idle.";
  } else if (status === "warm") {
    alert.hidden = false;
    alert.className = "thermal-alert thermal-warm";
    alert.textContent = "🌡 Temperatures elevated — " +
      (parts.join(", ") || "watching");
  } else {
    alert.hidden = true;
    alert.textContent = "";
  }
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
      `/api/events?category=${t}&limit=${MAX_ROWS}&since=${since.toFixed(3)}`);
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
    const pauseBtn = $("block-pause-btn");
    if (d.paused) {
      pauseBtn.textContent = "\u25B6 resume blocking";
      pauseBtn.className = "purge-btn pill-paused";
      pauseBtn.title = "blocking is PAUSED — stored rules stay unenforced; " +
        "click to re-apply everything";
      st.textContent = "paused";
      st.style.color = "var(--amber)";
      st.title = "every enforced rule was lifted; resume re-applies them";
    } else {
      pauseBtn.textContent = "\u23F8 pause blocking";
      pauseBtn.className = "purge-btn";
      pauseBtn.title = "lift every enforced rule at once (a safety valve " +
        "for when a block cuts your own connectivity); resume re-applies";
      if (mode) {
        st.textContent = "enforcing";
        st.style.color = "var(--green)";
        st.title = d.enforcement.reason || "";
      } else {
        const reason = d.enforcement?.reason || "no privilege";
        st.textContent = "queued only";
        st.style.color = "var(--amber)";
        st.title = reason;
      }
    }
    lockBtn.dataset.enforcing = mode && !d.paused ? "1" : "0";
    if (mode && !d.paused) {
      // closed padlock: the firewall is actually dropping traffic; click
      // to revoke the grant and stop enforcing
      lockBtn.textContent = "\u{1F512} ENFORCED";
      lockBtn.className = "state-pill state-on";
      lockBtn.title = "blocking is ENFORCED (" + (d.enforcement.reason || "") +
        ")\n\nclick to remove the grant \u2014 applied rules are lifted and " +
        "stored rules go back to queued";
      lockBtn.style.display = "";
    } else if (!d.paused) {
      const reason = d.enforcement?.reason || "no privilege";
      // open padlock: rules are stored but nothing is dropped yet; click
      // to run the one-time grant (password once)
      lockBtn.textContent = "\u{1F513} NOT ENFORCED";
      lockBtn.className = "state-pill state-off";
      lockBtn.title = reason + "\n\nclick to enforce \u2014 one-time privileged " +
        "install, the OS asks for your password once";
      lockBtn.style.display =
        d.enforcement?.grant_supported === false ? "none" : "";
    } else {
      // paused: the grant itself stays installed — the pill would lie
      lockBtn.style.display = "none";
    }
    lockBtn.setAttribute("aria-label",
      "blocking is " + (d.paused ? "paused" : mode ? "enforced" : "queued only") +
      " — click to toggle");
    state.ownCountry = d.ipolice?.own_country || "";
    state.countryCIDRs = d.country_cidrs || {};
    // allow rules need the helper's allow verbs; surface the reinstall
    // button while the installed helper predates them
    $("block-helper-update").style.display = d.helper_outdated ? "" : "none";
    const sortedRules = sortRowsBy(d.rules || [], state.sortBlocks);
    const statusBadge = (status) => {
      const cls = status === "enforced" ? "b-login"
        : status === "queued" ? "b-file"
        : status === "paused" ? "b-sys" : "b-priv";
      return `<span class="badge ${cls}">${esc(status)}</span>`;
    };
    const countryTarget = (r) => {
      const n = state.countryCIDRs[r.value];
      const label = blockCountryLabel(r.value);
      return `${flagImgHTML(r.value)} ${esc(r.value)}` +
        (label !== r.value ? ` <span class="dim">${esc(label)}</span>` : "") +
        (n ? ` <span class="tag tag-net">${n} CIDRs</span>` : "");
    };
    const tb = $("tbl-blocks").tBodies[0];
    tb.innerHTML = sortedRules.map((r) => `
      <tr>
        <td class="dim">${fmtTime(r.ts)}</td>
        <td>${r.action === "allow"
          ? '<span class="badge b-allow" title="exception: permits this target even when a broader block matches">allow</span>'
          : '<span class="badge b-priv">block</span>'}</td>
        <td>${badge("network", r.type)}</td>
        <td class="mono">${r.type === "country" ? countryTarget(r) :
          r.type === "list" ? `${esc(r.value)} <span class="dim" ` +
            `title="${esc(r.app_path || "")}">${esc(r.app_path || "")}</span>` :
          esc(r.value)}</td>
        <td>${statusBadge(r.status)}</td>
        <td class="dim">${esc(r.status_detail || "")}</td>
        <td><button class="mini-btn" data-unblock="${r.id}"
              title="remove this rule" aria-label="remove this rule">&#10006;</button></td>
      </tr>`).join("") ||
      '<tr><td colspan="7" class="dim">no rules yet — use the ⛔ block buttons ' +
      'on connections or the form above (an allow rule is an exception that ' +
      'overrides broader blocks)</td></tr>';
  } catch (e) { console.warn("blocks", e); }
}

async function addBlock(payload) {
  try {
    const r = await fetch("/api/blocks", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "add", ...payload }),
    });
    const d = await r.json();
    if (!d.ok) {
      alert((payload.action === "allow" ? "Allow rule failed: " : "Block failed: ") +
        (d.error || d.detail || "unknown"));
      return;
    }
    if (d.status !== "enforced") {
      alert(`Rule saved but not yet enforced (${d.status}).\n${d.detail || ""}`);
    }
    loadBlocks();
  } catch (e) { alert("Block failed: " + e); }
}

// Row buttons use event delegation so rerendering a live snapshot is safe.
$("connections-list").addEventListener("click", (e) => {
  const btn = e.target.closest("button[data-btype]");
  if (!btn) return;
  if (btn.dataset.btype === "allowip") {
    if (confirm(`Allow ALL traffic to/from ${btn.dataset.aip}, overriding any ` +
        `block rule it matches?`))
      addBlock({ type: "ip", action: "allow", ip: btn.dataset.aip });
  } else if (btn.dataset.btype === "ip") {
    if (confirm(`Block ALL traffic to/from ${btn.dataset.bip}?`))
      addBlock({ type: "ip", ip: btn.dataset.bip });
  } else {
    if (confirm(`Block the app "${btn.dataset.bapp || "this app"}" (all its ` +
        `network traffic)?`))
      addBlock({ type: "app", pid: btn.dataset.bpid, app: btn.dataset.bapp });
  }
});
$("tbl-live-conns").addEventListener("click", (e) => {
  const dnsBtn = e.target.closest("button[data-dnsblock]");
  if (dnsBtn) {
    const domain = dnsBtn.dataset.dnsblock;
    const removing = (state.dnsCustomDomains || []).includes(domain.toLowerCase());
    if (removing) {
      if (confirm(`Remove ${domain} from the DNS shield's custom blocklist?\n\n` +
          `Lookups for it resolve normally again.`))
        dnsPost({ action: "unblock_domain", domain });
    } else if (confirm(`NXDOMAIN the domain ${domain} in the DNS shield?\n\n` +
        `Every lookup for it (and its subdomains) is refused at the name ` +
        `layer — added to the custom blocklist, removable from the DNS ` +
        `panel. Requires the shield to be routed (system DNS → 127.0.0.1).`)) {
      dnsPost({ action: "block_domain", domain });
    }
    return;
  }
  const btn = e.target.closest("button[data-btype]");
  if (!btn) return;
  if (btn.dataset.btype === "allowip") {
    if (confirm(`Allow ALL traffic to/from ${btn.dataset.aip}, overriding any ` +
        `block rule it matches?`))
      addBlock({ type: "ip", action: "allow", ip: btn.dataset.aip });
  } else if (btn.dataset.btype === "ip") {
    if (confirm(`Block ALL traffic to/from ${btn.dataset.bip}?`))
      addBlock({ type: "ip", ip: btn.dataset.bip });
  } else if (confirm(`Block the app "${btn.dataset.bapp || "this app"}" (all its network traffic)?`)) {
    addBlock({ type: "app", pid: btn.dataset.bpid, app: btn.dataset.bapp });
  }
});
$("tbl-network").addEventListener("click", (e) => {
  const allowBtn = e.target.closest("button[data-aip]");
  if (allowBtn) {
    if (confirm(`Allow ALL traffic to/from ${allowBtn.dataset.aip}, overriding ` +
        `any block rule it matches?`))
      addBlock({ type: "ip", action: "allow", ip: allowBtn.dataset.aip });
    return;
  }
  const btn = e.target.closest("button.mini-btn[data-bip]");
  if (!btn) return;
  if (confirm(`Block ALL traffic to/from ${btn.dataset.bip}?`))
    addBlock({ type: "ip", ip: btn.dataset.bip });
});

$("block-type").addEventListener("change", (e) => {
  const t = e.target.value;
  $("block-ip").style.display =
    t === "app" || t === "country" || t === "list" || t === "provider" ||
    t === "paste" ? "none" : "";
  $("block-port").style.display = t === "connection" ? "" : "none";
  $("block-app").style.display = t === "app" ? "" : "none";
  $("block-country").style.display = t === "country" ? "" : "none";
  $("block-list").style.display = t === "list" ? "" : "none";
  $("block-provider").style.display = t === "provider" ? "" : "none";
  $("block-paste").style.display = t === "paste" ? "" : "none";
  $("block-paste-name").style.display = t === "paste" ? "" : "none";
  if (t === "country") refreshBlockCountryOptions();
  if (t === "provider") refreshBlockProviderOptions();
});
$("block-add").addEventListener("click", () => {
  const type = $("block-type").value;
  const ruleAction = $("block-action").value === "allow" ? "allow" : "block";
  const payload = { type, action: ruleAction };
  // the confirm dialogs below are the destructive warnings for BLOCK rules
  // (an allow only ever permits, so it needs none)
  if (type === "country") {
    const cc = $("block-country").value;
    if (!cc) { alert("Pick a country first."); return; }
    payload.cc = cc;
    if (ruleAction === "block") {
      payload.confirm = true; // the dialog below is the confirmation
      const own = state.ownCountry === cc ? "\n\n⚠ " + cc +
        " appears to be YOUR OWN country — blocking it can cut your " +
        "connectivity entirely." : "";
      if (!confirm(`Block ALL traffic to/from ${blockCountryLabel(cc)} (${cc})?\n\n` +
          `Every public IP range of the country will be dropped in both ` +
          `directions — that can be thousands of networks, and it also ` +
          `blocks sites merely hosted there.${own}\n\nProceed?`)) {
        return;
      }
    }
  } else if (type === "list") {
    const path = $("block-list").value.trim();
    if (!path) { alert("Enter the path of your list file first."); return; }
    payload.list = path;
    if (ruleAction === "block" && !confirm(
        `Block ALL traffic to/from the addresses in\n${path}?\n\n` +
        `The file is re-read on every re-apply/restart — edits take ` +
        `effect without re-adding the rule. When WGrid is running, the ` +
        `file is also registered there as a source.\n\nProceed?`)) {
      return;
    }
  } else if (type === "provider") {
    const provider = $("block-provider").value;
    if (!provider) { alert("Pick an WGrid list first."); return; }
    payload.provider = provider;
    if (ruleAction === "block" && !confirm(
        `Block ALL traffic to/from the ranges of the WGrid list\n` +
        `"${provider}"?\n\nThe ranges are re-fetched on every ` +
        `re-apply/restart — manage the list in WGrid; the block follows ` +
        `it.\n\nProceed?`)) {
      return;
    }
  } else if (type === "paste") {
    const text = $("block-paste").value.trim();
    if (!text) { alert("Paste some IP addresses or CIDRs first."); return; }
    payload.list_text = text;
    payload.name = $("block-paste-name").value.trim() || "uploaded";
    if (ruleAction === "block" && !confirm(
        `Block ALL traffic to/from the pasted addresses?\n\n` +
        `They are saved to the app's data folder as a blocklist file ` +
        `(and registered in WGrid when it is running).\n\nProceed?`)) {
      return;
    }
  } else if (type !== "app") {
    payload.ip = $("block-ip").value.trim();
    if (type === "connection") payload.port = $("block-port").value.trim();
  } else {
    if (ruleAction === "allow") {
      alert("Allow rules only make sense as exceptions to block rules — " +
        "remove the app block instead.");
      return;
    }
    payload.app = $("block-app").value.trim();
  }
  addBlock(payload);
});

// the installed helper predates the allow verbs: reinstall it (password
// once), then everything re-applies through the fresh helper
$("block-helper-update").addEventListener("click", async () => {
  if (!confirm("Reinstall the firewall helper so allow rules can enforce?\n\n" +
      "The OS asks for your password once; enforced blocks stay in place " +
      "and every rule re-applies afterwards.")) {
    return;
  }
  const btn = $("block-helper-update");
  btn.disabled = true;
  try {
    const r = await fetch("/api/block/grant", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "grant" }),
    });
    const d = await r.json();
    if (!d.ok && !d.canceled) alert("Helper update failed: " + (d.error || "unknown"));
  } catch (e) {
    alert("Helper update failed: " + e);
  }
  btn.disabled = false;
  loadBlocks();
});

/* country dropdown for the block form: every country seen in the geo data */
function refreshBlockCountryOptions() {
  const select = $("block-country");
  const seen = new Map();
  for (const row of state.destinations.countries || []) {
    if (row.cc && !seen.has(row.cc)) seen.set(row.cc, row.country || "");
  }
  const selected = select.value;
  select.innerHTML = '<option value="">— pick a country —</option>' +
    [...seen.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([cc, name]) =>
        `<option value="${esc(cc)}">${esc(cc)}${name ? " — " + esc(name) : ""}</option>`)
      .join("");
  if ([...select.options].some((o) => o.value === selected)) select.value = selected;
}

function blockCountryLabel(cc) {
  for (const row of state.destinations.countries || []) {
    if (row.cc === cc && row.country) return row.country;
  }
  return cc;
}

/* WGrid list (provider) dropdown: fetched from WGrid when the option
   is picked — country/* and list/* feeds are monitor-managed and excluded */
async function refreshBlockProviderOptions() {
  const select = $("block-provider");
  select.innerHTML = '<option value="">— loading WGrid lists… —</option>';
  try {
    const d = await getJSON("/api/wgrid/providers");
    if (d.error) {
      select.innerHTML =
        `<option value="">WGrid offline (${esc(d.error)})</option>`;
      return;
    }
    if (!(d.providers || []).length) {
      select.innerHTML = '<option value="">no WGrid lists yet — add a ' +
        'source in WGrid (Databases)</option>';
      return;
    }
    select.innerHTML = '<option value="">— pick an WGrid list —</option>' +
      d.providers.map((p) => `<option value="${esc(p)}">${esc(p)}</option>`).join("");
  } catch (e) {
    select.innerHTML = '<option value="">WGrid offline</option>';
  }
}
$("block-reapply").addEventListener("click", async () => {
  await fetch("/api/blocks", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action: "reconcile" }),
  });
  loadBlocks();
});
// global safety valve: one click lifts every enforced rule, one click
// restores them (stored rules are never touched)
$("block-pause-btn").addEventListener("click", async () => {
  const pausing = !$("block-pause-btn").textContent.includes("resume");
  const msg = pausing
    ? "Pause ALL blocking?\n\nEvery enforced rule is lifted from the firewall " +
      "at once (rules stay stored, the grant stays installed). Useful when a " +
      "block cuts the machine's own connectivity. Resume re-applies everything."
    : "Resume blocking?\n\nEvery stored rule re-applies through the firewall " +
      "(the previously paused status returns to enforced or queued).";
  if (!confirm(msg)) return;
  const btn = $("block-pause-btn");
  btn.disabled = true;
  try {
    const r = await fetch("/api/blocks", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: pausing ? "pause" : "resume" }),
    });
    const d = await r.json();
    if (!d.ok) alert("Pause/resume failed: " + (d.error || "unknown"));
  } catch (e) {
    alert("Pause/resume failed: " + e);
  }
  btn.disabled = false;
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
setupDashboardLayoutControls();
loadDashboardLayout();
loadTableVisibility();
loadThemes().catch((e) => {
  $("theme-msg").classList.add("error");
  $("theme-msg").textContent = e.message;
});
loadStatus();
loadLiveConnections();
loadConnectionHistory();
loadDestinations();
loadTraffic();
loadSummary();
loadBattery();
loadBlocks();
loadHistory();
connectSSE();

// ------------------------------------------------------------- DNS shield ----

async function loadDNS() {
  let d;
  try {
    d = await getJSON("/api/dns");
  } catch (e) {
    $("dns-stats").innerHTML = '<span class="dim">dns shield: ' + e + "</span>";
    return;
  }
  // the live-connections domain-block button reads this for its state
  state.dnsCustomDomains = (d.custom_domains || []).map((x) => String(x).toLowerCase());
  const tag = $("dns-status-tag");
  tag.textContent = d.running ? ("on · :" + d.port) : "off";
  const btn = $("dns-toggle");
  btn.textContent = d.running ? "stop" : "start";
  const route = $("dns-route-btn");
  const modeSel = $("dns-route-mode");
  route.style.display = d.supported ? "" : "none";
  modeSel.style.display = d.supported ? "" : "none";
  const mode = d.route_mode || "auto";
  if (modeSel.value !== mode) modeSel.value = mode;
  route.textContent = d.routed === "on" ? "unroute system DNS" : "route system DNS";
  route.dataset.routed = d.routed === "on" ? "1" : "";
  route.title = d.routed === "on"
    ? (mode === "auto"
      ? "lift the redirect — the helper restores the DNS servers it recorded"
      : "lift the redirect — set your system DNS back yourself")
    : (mode === "auto"
      ? "the helper records your current DNS servers, points the system " +
        "resolver at the shield (127.0.0.1), and verifies a real lookup — " +
        "no System Settings edits"
      : "install the loopback port-53 redirect; you point system DNS at " +
        "127.0.0.1 yourself");
  // watchdog banner: the route auto-lifted after failed health checks
  const banner = $("dns-banner");
  if (d.auto_reverted) {
    banner.style.display = "";
    banner.innerHTML = `<span class="badge b-priv">auto-reverted</span> ` +
      `${fmtTime(d.auto_reverted.ts)} — ${esc(d.auto_reverted.reason)}`;
  } else {
    banner.style.display = "none";
    banner.innerHTML = "";
  }
  // opt-in query log toggle: ON gives the site-visit panel its exact names
  const logBtn = $("dns-log-btn");
  const logOn = !!d.log_enabled;
  logBtn.textContent = logOn ? "\u{1F4DD} log ON" : "\u{1F4DD} log queries";
  logBtn.title = logOn
    ? "query log is ON — asked names + resolved IPs are remembered in memory " +
      "only; click to turn it off (both are wiped)"
    : "record asked domain names and their resolved IPs (memory only, wiped " +
      "when turned off) — this is what names the Site visits panel precisely";
  logBtn.style.borderColor = logOn ? "var(--accent)" : "";
  if (d.running) {
    $("dns-stats").textContent = "";
    const up = document.createElement("span");
    up.className = "dim";
    up.textContent = " · upstream: " + (d.upstreams || []).join(", ");
    let logInfo = "";
    if (logOn) logInfo = ` · log: ${d.log_entries ?? 0} queries, ${d.answers ?? 0} names`;
    $("dns-stats").append(
      `queries ${d.stats.queries} · blocked ${d.stats.blocked} · forwarded ${d.stats.forwarded}` +
      ` · ${d.domains} domains on ${d.lists.length} list(s)` + logInfo);
    $("dns-stats").appendChild(up);
    if (d.error) $("dns-stats").append(" · last error: " + d.error);
  } else {
    $("dns-stats").textContent = d.error ? ("last error: " + d.error) : "shield is off";
  }
  renderDNSRules(d.rules || []);
  renderDNSLists(d.lists || []);
}

/* DNS rules: the dns_rules rows with live load state — the firewall-rules
   analogue for the name layer. Rows carry status_detail so the existing
   sortValueOf cases cover every sortable column. */
function renderDNSRules(rules) {
  const tb = $("tbl-dns-rules").querySelector("tbody");
  const sorted = sortRowsBy(rules.map((r) => ({
    ...r,
    status_detail: r.error ? "⚠ " + r.error : (r.detail ?? ""),
  })), state.sortDnsRules);
  tb.innerHTML = sorted.map((r) => `
    <tr>
      <td class="dim">${fmtTime(r.ts)}</td>
      <td>${r.action === "allow"
        ? '<span class="badge b-allow" title="exception: permits this name even when a block matches">allow</span>'
        : '<span class="badge b-priv">block</span>'}</td>
      <td>${badge("file", r.type)}</td>
      <td class="mono">${esc(r.value)}</td>
      <td>${r.domains ?? 0}</td>
      <td class="dim">${esc(r.status_detail)}</td>
      <td><button class="mini-btn" data-dnsrule="${r.id}"
            title="remove this rule" aria-label="remove this rule">&#10006;</button></td>
    </tr>`).join("") ||
    '<tr><td colspan="7" class="dim">no DNS rules yet — add one above, or ' +
    'paste a bulk list below (an allow rule is an exception that overrides ' +
    'broader blocks)</td></tr>';
}

/* WGrid provider dropdown for DNS rules: same registry as the firewall's,
   same offline handling. */
async function refreshDnsProviderOptions() {
  const select = $("dns-rule-provider");
  select.innerHTML = '<option value="">— loading WGrid lists… —</option>';
  try {
    const d = await getJSON("/api/wgrid/providers");
    if (d.error) {
      select.innerHTML =
        `<option value="">WGrid offline (${esc(d.error)})</option>`;
      return;
    }
    if (!(d.providers || []).length) {
      select.innerHTML = '<option value="">no WGrid lists yet — add a ' +
        'source in WGrid (Databases)</option>';
      return;
    }
    select.innerHTML = '<option value="">— pick an WGrid list —</option>' +
      d.providers.map((p) => `<option value="${esc(p)}">${esc(p)}</option>`).join("");
  } catch (e) {
    select.innerHTML = '<option value="">WGrid offline</option>';
  }
}

function renderDNSLists(lists) {
  const tbody = $("tbl-dns-lists").querySelector("tbody");
  tbody.textContent = "";
  if (!lists.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 4;
    td.className = "dim";
    td.textContent = "no domain lists yet — paste one above (the MVPS HOSTS file works as-is)";
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }
  for (const l of lists) {
    const tr = document.createElement("tr");
    const name = document.createElement("td");
    name.textContent = l.name;
    const kind = document.createElement("td");
    kind.textContent = l.allow ? "allowlist" : "blocklist";
    const count = document.createElement("td");
    count.textContent = l.domains;
    const act = document.createElement("td");
    const btn = document.createElement("button");
    btn.className = "purge-btn";
    btn.textContent = "remove";
    btn.dataset.dnsList = l.name;
    act.appendChild(btn);
    tr.append(name, kind, count, act);
    tbody.appendChild(tr);
  }
}

async function dnsPost(payload) {
  try {
    const r = await fetch("/api/dns", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const d = await r.json();
    if (!d.ok) { alert("DNS shield: " + (d.error || "unknown error")); }
  } catch (e) { alert("DNS shield: " + e); }
  loadDNS();
}

$("dns-toggle").addEventListener("click", () => {
  dnsPost({ action: $("dns-status-tag").textContent === "off" ? "start" : "stop" });
});
$("dns-route-btn").addEventListener("click", () => {
  const on = $("dns-route-btn").dataset.routed === "1";
  const auto = $("dns-route-mode").value !== "manual";
  const msg = on
    ? (auto
      ? "Lift the system DNS route? The pf redirect is removed and the DNS " +
        "servers the helper recorded are restored exactly."
      : "Remove the pf redirect? The system resolver will bypass the DNS " +
        "shield again — set your system DNS back yourself.")
    : (auto
      ? "Route system DNS through the shield?\n\nThe helper records your " +
        "current DNS servers, points the system resolver at the shield " +
        "(127.0.0.1), and verifies a real lookup end-to-end before " +
        "reporting success. Nothing to edit in System Settings — and if " +
        "lookups ever fail, health checks lift the route and restore your " +
        "previous servers automatically."
      : "Install the loopback port-53 redirect?\n\nAfter this, set your " +
        "system DNS to 127.0.0.1 (System Settings → your network → DNS " +
        "servers). The shield health-checks the path and lifts the " +
        "redirect for you if it breaks.");
  if (confirm(msg)) dnsPost({ action: "route", enabled: !on });
});
$("dns-route-mode").addEventListener("change", () => {
  const manual = $("dns-route-mode").value === "manual";
  const msg = manual
    ? "Switch to manual routing?\n\nYou will point system DNS at 127.0.0.1 " +
      "yourself (System Settings → your network → DNS servers). The shield " +
      "still verifies the path and lifts the redirect if it breaks."
    : "Switch to auto-managed routing?\n\nThe helper will point system DNS " +
      "at the shield for you when you route, and restore your previous " +
      "servers when you unroute.";
  if (confirm(msg)) dnsPost({ action: "route_mode", mode: $("dns-route-mode").value });
});
$("dns-rule-type").addEventListener("change", () => {
  const t = $("dns-rule-type").value;
  $("dns-rule-domain").style.display = t === "domain" ? "" : "none";
  $("dns-rule-list").style.display = t === "list" ? "" : "none";
  $("dns-rule-provider").style.display = t === "provider" ? "" : "none";
  if (t === "provider") refreshDnsProviderOptions();
});
$("dns-rule-add").addEventListener("click", () => {
  const t = $("dns-rule-type").value;
  const action = $("dns-rule-action").value;
  let value = "";
  if (t === "domain") {
    value = $("dns-rule-domain").value.trim();
    if (!value) { alert("Type a domain to match, e.g. 4life.com."); return; }
    const verb = action === "allow" ? "ALLOW" : "BLOCK";
    if (!confirm(`${verb} "${value}" at the DNS level?` +
      (action === "allow"
        ? "\n\nAllow wins over blocks: queries for this name (and its " +
          "subdomains) resolve normally again."
        : "\n\nQueries for this name and its subdomains get NXDOMAIN — " +
          "nothing resolves it while the shield runs."))) return;
  } else if (t === "list") {
    value = $("dns-rule-list").value.trim();
    if (!value) { alert("Give the absolute path of a domains file."); return; }
    if (!confirm(`Use "${value}" as a DNS ${action} list?\n\nOne domain per ` +
      "line (or a HOSTS file); the file is re-read on every reload.")) return;
  } else {
    value = $("dns-rule-provider").value;
    if (!value) { alert("Pick an WGrid list first."); return; }
    if (!confirm(`DNS-${action} the domains of the WGrid list "${value}"?\n\n` +
      "The list's domain lines sync every 5 minutes while WGrid runs; a " +
      "mixed list also keeps feeding the firewall's IP rules. Manage the " +
      "list in WGrid — the shield follows it.")) return;
  }
  dnsPost({ action: "add_rule", type: t, rule_action: action, value });
  $("dns-rule-domain").value = "";
  $("dns-rule-list").value = "";
});
$("tbl-dns-rules").addEventListener("click", (e) => {
  const btn = e.target.closest("button[data-dnsrule]");
  if (!btn) return;
  if (confirm("Remove this DNS rule?")) dnsPost({ action: "remove_rule", id: btn.dataset.dnsrule });
});
$("dns-add-list").addEventListener("click", () => {
  const name = $("dns-list-name").value.trim();
  const text = $("dns-list-text").value;
  if (!name || !text.trim()) { alert("Give the list a name and paste some domains."); return; }
  dnsPost({ action: "add_list", name, text });
  $("dns-list-name").value = "";
  $("dns-list-text").value = "";
});
$("dns-log-btn").addEventListener("click", () => {
  const on = $("dns-log-btn").textContent.includes("log ON");
  const msg = on
    ? "Turn OFF the query log?\n\nThe remembered query names and resolved IPs are wiped now."
    : "Turn ON the query log?\n\nRecords every domain this machine asks for and the IPs it " +
      "resolves to (memory only — never written to disk, wiped when turned off or on " +
      "restart). The Site visits panel uses it to name visits with the exact domain.";
  if (confirm(msg)) dnsPost({ action: "log", enabled: !on });
});
$("tbl-dns-lists").addEventListener("click", (e) => {
  const btn = e.target.closest("button[data-dns-list]");
  if (!btn) return;
  if (confirm(`Remove the domain list "${btn.dataset.dnsList}"?`))
    dnsPost({ action: "remove_list", name: btn.dataset.dnsList });
});

// ------------------------------------------------------- activity heatmap ----

/* "Who called home at 3am?" — external connection lifecycles per app and
   local hour of day, from the persisted connection history. */
async function loadHeatmap() {
  const hours = parseInt($("heatmap-range").value, 10) || 24;
  let d;
  try {
    d = await getJSON(`/api/heatmap?hours=${hours}`);
  } catch (e) {
    $("heatmap").innerHTML = `<div class="empty">heatmap unavailable: ${esc(e.message)}</div>`;
    return;
  }
  const perAppHour = new Map();
  const totals = new Map();
  let max = 0;
  for (const b of d.buckets || []) {
    if (!perAppHour.has(b.app)) perAppHour.set(b.app, new Array(24).fill(0));
    const row = perAppHour.get(b.app);
    row[b.hour] += b.count;
    totals.set(b.app, (totals.get(b.app) || 0) + b.count);
    if (row[b.hour] > max) max = row[b.hour];
  }
  const apps = [...totals.entries()].sort((a, b) => b[1] - a[1]).slice(0, 12)
    .map(([app]) => app);
  const el = $("heatmap");
  if (!apps.length) {
    el.innerHTML = '<div class="empty">no external connections recorded in ' +
      'this window yet (the history keeps what the retention window holds)</div>';
    return;
  }
  const head = `<span></span>` +
    [...Array(24).keys()].map((h) =>
      `<span class="hm-hour" title="${String(h).padStart(2, "0")}:00–${String((h + 1) % 24).padStart(2, "0")}:00">${h}</span>`).join("") +
    `<span class="hm-hour">Σ</span>`;
  const rows = apps.map((app) => {
    const cells = perAppHour.get(app).map((n, h) => {
      const pct = n ? Math.max(12, Math.round((n / max) * 100)) : 0;
      const bg = n
        ? `background:color-mix(in srgb, var(--accent) ${pct}%, var(--inset))`
        : "";
      return `<span class="hm-cell" style="${bg}" ` +
        `title="${esc(app)} · ${String(h).padStart(2, "0")}:00–${String((h + 1) % 24).padStart(2, "0")}:00 · ${n} connection${n === 1 ? "" : "s"}"></span>`;
    }).join("");
    return `<span class="hm-app" title="${esc(app)}">${esc(app)}</span>${cells}` +
      `<span class="hm-total">${totals.get(app)}</span>`;
  });
  el.style.gridTemplateColumns = `minmax(120px, 180px) repeat(24, minmax(20px, 1fr)) 2.4em`;
  el.innerHTML = head + rows.join("");
}

$("heatmap-range").addEventListener("change", loadHeatmap);

// ---------------------------------------------------------- site visits ----

/* Reconstructed visits: one app's sockets to one site merged while the
   network gap stays small; closed when the last connection ends. */
async function loadVisits() {
  const hours = parseInt($("visits-range").value, 10) || 24;
  const gap = parseInt($("visits-gap").value, 10) || 300;
  let d;
  try {
    d = await getJSON(`/api/visits?hours=${hours}&gap=${gap}`);
  } catch (e) {
    $("tbl-visits").tBodies[0].innerHTML =
      `<tr><td colspan="9" class="dim">visits unavailable: ${esc(e.message)}</td></tr>`;
    return;
  }
  state.visits = d.visits || [];
  refreshVisitsOptions();
  renderVisits();
}

/* app + site dropdowns for the visits panel, rebuilt from the loaded data
   (selection preserved across the frequent reloads, like the sites panel) */
function refreshVisitsOptions() {
  const apps = [...new Set((state.visits || []).map((v) => v.app))]
    .sort((a, b) => a.localeCompare(b));
  keepSelectSelection($("visits-app"), () => {
    $("visits-app").innerHTML = '<option value="">All apps</option>' +
      apps.map((a) => `<option value="${esc(a)}">${esc(a)}</option>`).join("");
  });
  const sites = [...new Map((state.visits || [])
    .map((v) => [v.domain, v.label || v.domain])).entries()]
    .sort((a, b) => a[1].localeCompare(b[1]));
  keepSelectSelection($("visits-site"), () => {
    $("visits-site").innerHTML = '<option value="">All sites</option>' +
      sites.map(([domain, name]) =>
        `<option value="${esc(domain)}">${esc(name)}</option>`).join("");
  });
}

function visitNameHTML(v) {
  const name = v.label || v.domain;
  const domainTag = v.label && v.label !== v.domain
    ? `<span class="dest-domain">${esc(v.domain)}</span>` : "";
  const cc = v.cc ? flagImgHTML(v.cc) + " " : "";
  return `${cc}<span class="connection-app">${esc(name)}</span>${domainTag}`;
}

function renderVisits() {
  const query = $("filter-visits").value.trim().toLowerCase();
  const app = $("visits-app").value;
  const site = $("visits-site").value;
  const rows = (state.visits || []).filter((v) =>
    (!app || v.app === app) &&
    (!site || v.domain === site) &&
    (!query || `${v.domain} ${v.label || ""} ${v.app} ${v.country || ""}`
      .toLowerCase().includes(query)));
  const sorted = sortRowsBy(rows, state.sortVisits);
  $("tbl-visits").tBodies[0].innerHTML = sorted.map((v) => {
    const closed = v.open
      ? '<span class="badge b-allow" title="a connection of this visit is still up — the network has not closed yet">still open</span>'
      : `<span class="dim">${fmtTime(v.ended ?? v.last)}</span>`;
    const ips = (v.ips || []).join("\n");
    return `<tr>` +
      `<td title="${esc(ips)}">${visitNameHTML(v)}</td>` +
      `<td class="dim">${esc(v.app)}</td>` +
      `<td class="dim">${fmtTime(v.started)}</td>` +
      `<td>${closed}</td>` +
      `<td class="dim" title="wall clock from first to last network activity">${fmtDuration(v.span)}</td>` +
      `<td class="dim" title="summed connection lifetimes (no idle gaps)">${fmtDuration(v.active)}</td>` +
      `<td class="mono" title="${ips ? "per-connection counters of this visit" : ""}">${fmtBytes(v.bytes_in)}</td>` +
      `<td class="mono">${fmtBytes(v.bytes_out)}</td>` +
      `<td>${v.connections}</td>` +
      `</tr>`;
  }).join("") ||
    '<tr><td colspan="9" class="dim">no site visits in this window — ' +
    'open some pages and come back (history keeps what the retention window holds)</td></tr>';
}

const VISIT_COLS = ["domain", "app", "vstarted", "vended", "span", "active",
  "bytes_in", "bytes_out", "connections"];
clickSort("tbl-visits", state.sortVisits, renderVisits, VISIT_COLS);
$("filter-visits").addEventListener("input", renderVisits);
$("visits-app").addEventListener("change", renderVisits);
$("visits-site").addEventListener("change", renderVisits);
$("clear-visits-filters").addEventListener("click", () => {
  $("filter-visits").value = "";
  $("visits-app").value = "";
  $("visits-site").value = "";
  renderVisits();
});
$("visits-range").addEventListener("change", loadVisits);
$("visits-gap").addEventListener("change", loadVisits);

// ------------------------------------------------------------- retention ----

async function loadRetention() {
  try {
    const d = await getJSON("/api/retention");
    const select = $("retention-days");
    const days = String(d.days ?? 7);
    if ([...select.options].some((o) => o.value === days)) select.value = days;
  } catch (e) { console.warn("retention", e); }
}

$("retention-days").addEventListener("change", async (e) => {
  const days = parseInt(e.target.value, 10);
  const label = days === 0 ? "forever" : `${days} day${days === 1 ? "" : "s"}`;
  if (days > 0 && !confirm(`Automatically purge stored events older than ${label}?`)) {
    loadRetention();
    return;
  }
  try {
    const r = await fetch("/api/retention", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ days }),
    });
    const d = await r.json();
    const msg = $("purge-msg");
    msg.textContent = d.ok ? `history kept for ${label}` : `error: ${d.error}`;
    msg.style.color = d.ok ? "var(--green)" : "var(--red)";
    setTimeout(() => { msg.textContent = ""; }, 6000);
  } catch (err) {
    $("purge-msg").textContent = `error: ${err}`;
  }
});

// Polling only runs while the dashboard is actually watched: paused or
// backgrounded tabs skip ticks and catch up on resume / when the tab returns.
const poll = (fn) => () => { if (!state.paused && !document.hidden) fn(); };
setInterval(poll(updatePrivacyCard), 1000);   // keep "Xs ago" ticking between events
setInterval(tickConnectionDurations, 1000);   // live connection durations tick from the DOM
setInterval(poll(loadLiveConnections), 3000);
setInterval(poll(loadTraffic), 3000);
setInterval(poll(loadDestinations), 10000);
setInterval(poll(loadBattery), 5000);
setInterval(poll(loadBlocks), 5000);
setInterval(poll(refreshFilterOptions), 30000);
setInterval(poll(loadSummary), 10000);
setInterval(poll(loadStatus), 15000);
setInterval(poll(loadDNS), 5000);   // DNS shield stats + list state
setInterval(poll(loadHeatmap), 60000);   // slow-moving hour buckets
setInterval(poll(loadVisits), 45000);    // reconstructed site visits
loadDNS();
loadHeatmap();
loadVisits();
loadRetention();

function refreshLiveViews() {
  updatePrivacyCard();
  loadLiveConnections();
  loadTraffic();
  loadDestinations();
  loadBattery();
  loadBlocks();
  loadSummary();
  loadStatus();
}
document.addEventListener("visibilitychange", () => {
  if (!document.hidden && !state.paused) refreshLiveViews();
});

/* AppScope Monitor dashboard */
"use strict";

const $ = (id) => document.getElementById(id);
/* sort registries shared by every sortable table (declared first: the
   clickSort registrations below run during script evaluation) */
const DEST_COLS = ["name", "ip", "apps", "ips", "connections", "open",
  "seconds", "bytes_in", "bytes_out", "last_seen"];
const NUMERIC_SORT_COLS = new Set(["ips", "connections", "open", "seconds",
  "bytes_in", "bytes_out", "last_seen", "pid", "established", "ok", "closed",
  "internal", "external", "count", "ts"]);

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
  destinations: { countries: [], sites: [], apps: [] },
  destinationsRequest: 0,
  ownCountry: "",
  sitesGroupBy: "site",
  expandedDestGroups: new Set(),
  countriesMode: "country",
  expandedCountryGroups: new Set(),
  sortGeo: { col: "bytes_in", dir: -1 },
  sortSites: { col: "bytes_in", dir: -1 },
  sortLive: { col: null, dir: 1 },
  sortBlocks: { col: "ts", dir: -1 },
  sortConnSummary: { col: null, dir: 1 },
  sortHistory: { col: "last", dir: -1 },
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

function applyTheme(theme) {
  for (const key of appliedThemeKeys) {
    document.documentElement.style.removeProperty(key);
  }
  appliedThemeKeys = [];
  for (const [key, value] of Object.entries(theme.colors || {})) {
    document.documentElement.style.setProperty(key, value);
    appliedThemeKeys.push(key);
  }
  document.documentElement.dataset.theme = theme.id;
  document.documentElement.style.colorScheme = "dark";
}

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
  const active = data.active;
  const select = $("theme-select");
  select.innerHTML = data.themes.map((theme) =>
    `<option value="${esc(theme.id)}"${theme.id === active ? " selected" : ""}>` +
    `${esc(theme.name)}</option>`).join("");
  const theme = data.themes.find((item) => item.id === active);
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
  "battery-panel": "Battery & power",
  "privacy-panel": "Privacy events",
  "files-panel": "File access",
  "network-panel": "Network events",
  "system-panel": "System & devices",
  "blocks-panel": "Blocked connections",
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
  const offset = direction === "left" ? -1 : direction === "right" ? 1 :
    direction === "up" ? -2 : 2;
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
    "connections-panel", "top-apps-panel", "connection-summary-panel", "battery-panel",
    "privacy-panel", "files-panel", "network-panel", "system-panel", "blocks-panel"];
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
      { html: `<span class="mono">${esc(ev.remote ?? "")}</span>${blockBtnHtml(ev.remote)}` },
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
    const detailRows = group.visibleConnections.map((connection) => {
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
        `<thead><tr><th>First observed</th><th>Status</th><th>Protocol</th><th>State</th>` +
        `<th>Local endpoint</th><th>Remote endpoint</th><th>Geo</th><th>Duration</th>` +
        `<th>Scope</th><th>Last seen</th></tr></thead>` +
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
clickSortDelegated("connections-list", state.sortHistory,
  renderConnectionHistory,
  ["name", "pid", "last", "established", "ok", "closed", "internal", "external"]);
clickSort("tbl-geo-countries", state.sortGeo, renderGeoCountries, DEST_COLS);
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
    case "type": return String(row.type ?? "").toLowerCase();
    case "target": return String(row.value ?? "").toLowerCase();
    case "status": return String(row.status ?? "").toLowerCase();
    case "detail": return String(row.status_detail ?? "").toLowerCase();
    // connection-history group columns
    case "last": return row.latestSeen;
    case "established": return row.totals?.established ?? 0;
    case "ok": return row.totals?.ok ?? 0;
    case "closed": return row.totals?.closed ?? 0;
    case "internal": return row.totals?.internal ?? 0;
    case "external": return row.totals?.external ?? 0;
    case "count": return row.count ?? 0;
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
// stable container instead.
function clickSortDelegated(containerId, sortState, rerender, cols) {
  $(containerId).addEventListener("click", (event) => {
    const th = event.target.closest("th.sortable");
    if (!th) return;
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
function applySortIndicators(root, sort) {
  const el = typeof root === "string" ? $(root) : root;
  if (!el) return;
  el.querySelectorAll("th.sortable").forEach((th) => {
    if (th.dataset.sort === sort.col) {
      th.dataset.dir = sort.dir === 1 ? "asc" : "desc";
    } else {
      delete th.dataset.dir;
    }
  });
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

function countryFlatRowHTML(row, withCountry) {
  const countryCell = withCountry
    ? countryCellHTML(row) + (row.cc ? countryBlockBtnHTML(row.cc) : "")
    : '<span class="dim">└</span>';
  return `<tr class="${withCountry ? "" : "dest-subrow"}">` +
    `<td>${countryCell}</td>` +
    `<td>${ipNameCellHTML(row)}</td>` +
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
    body.innerHTML = sortRowsBy(rows, state.sortGeo)
      .map((row) => countryFlatRowHTML(row, true)).join("") ||
      '<tr><td colspan="9" class="dim">no external destinations match these filters</td></tr>';
    const total = state.destinations.countries.length;
    $("geo-countries-count").textContent =
      `${rows.length} of ${total} IP${total === 1 ? "" : "s"}`;
    return;
  }

  // grouped: one summary row per country, expandable to its IPs
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
      ? sortRowsBy(agg.ip_rows, state.sortGeo)
        .map((row) => countryFlatRowHTML(row, false)).join("")
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
  return `<span class="connection-app">${esc(name)}</span>${domainTag}`;
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
    let rows = [];
    for (const app of state.destinations.apps || []) {
      for (const sub of app.sites || []) {
        rows.push({
          app: app.app, sortName: (sub.label || sub.host || "").toLowerCase(),
          host: sub.host, label: sub.label, ips: sub.ips,
          connections: sub.connections, open: sub.open, seconds: sub.seconds,
          bytes_in: sub.bytes_in, bytes_out: sub.bytes_out,
          last_seen: sub.last_seen,
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
      if (isSite) {
        detailRowsHTML = sortRowsBy(children, state.sortSites).map((row) =>
          `<tr><td>${countryCellHTML(row)}</td>` +
          `<td>${ipNameCellHTML(row)}</td>` +
          `<td class="dim">${esc((row.apps || []).join(", ") || "—")}</td>` +
          `<td>${row.connections || 0}</td>` +
          `<td>${activeCellHTML(row.open)}</td>` +
          `<td class="dim">${fmtDuration(row.seconds || 0)}</td>` +
          `<td class="mono">${bytesCellHTML(row.bytes_in)}</td>` +
          `<td class="mono">${bytesCellHTML(row.bytes_out)}</td>` +
          `<td class="dim">${lastSeenCellHTML(row.last_seen)}</td></tr>`).join("");
      } else {
        detailRowsHTML = sortRowsBy(children, state.sortSites).map((sub) =>
          `<tr><td>${siteNameHTML(sub)}</td>` +
          `<td>${sub.ips || 0}</td>` +
          `<td>${sub.connections || 0}</td>` +
          `<td>${activeCellHTML(sub.open)}</td>` +
          `<td class="dim">${fmtDuration(sub.seconds || 0)}</td>` +
          `<td class="mono" title="per-socket TCP counters">${bytesCellHTML(sub.bytes_in)}</td>` +
          `<td class="mono" title="per-socket TCP counters">${bytesCellHTML(sub.bytes_out)}</td>` +
          `<td class="dim">${lastSeenCellHTML(sub.last_seen)}</td></tr>`).join("");
      }
      const detailHead = isSite
        ? "<th>Geo</th><th>IP</th><th>Apps</th><th>Connections</th><th>Active</th>" +
          "<th>Time connected</th><th>&darr; In</th><th>&uarr; Out</th><th>Last seen</th>"
        : "<th>Site</th><th>IPs</th><th>Connections</th><th>Active</th>" +
          "<th>Time connected</th><th>&darr; In</th><th>&uarr; Out</th><th>Last seen</th>";
      const detail = expanded
        ? `<tr class="connection-detail-row"><td colspan="9"><div class="tbl-wrap"><table>` +
          `<thead><tr>${detailHead}</tr></thead>` +
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
  const sorted = sortRowsBy(rows, state.sortLive);
  const body = $("tbl-live-conns").tBodies[0];
  body.innerHTML = sorted.map((connection) => {
    const remote = endpoint(connection.remote_ip, connection.remote_port);
    const local = endpoint(connection.local_ip, connection.local_port);
    const blockButton = connection.remote_ip
      ? `<button class="mini-btn" data-btype="ip" data-bip="${esc(connection.remote_ip)}" ` +
        `title="block all traffic to/from ${esc(connection.remote_ip)}" ` +
        `aria-label="block all traffic to/from ${esc(connection.remote_ip)}">&#9940;</button>` : "";
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
        `<span class="scope scope-${esc(connection.scope || "other")}">${esc(connectionScope(connection))}</span></td>` +
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
      `<td class="blockcell">${blockButton}${appButton}</td></tr>`;
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
    lockBtn.dataset.enforcing = mode ? "1" : "0";
    if (mode) {
      st.textContent = "enforcing";
      st.style.color = "var(--green)";
      st.title = d.enforcement.reason || "";
      // closed padlock: the firewall is actually dropping traffic; click
      // to revoke the grant and stop enforcing
      lockBtn.textContent = "\u{1F512} ENFORCED";
      lockBtn.className = "state-pill state-on";
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
      lockBtn.textContent = "\u{1F513} NOT ENFORCED";
      lockBtn.className = "state-pill state-off";
      lockBtn.title = reason + "\n\nclick to enforce \u2014 one-time privileged " +
        "install, the OS asks for your password once";
      lockBtn.style.display =
        d.enforcement?.grant_supported === false ? "none" : "";
    }
    lockBtn.setAttribute("aria-label",
      "blocking is " + (mode ? "enforced" : "queued only") + " — click to toggle");
    state.ownCountry = d.ipolice?.own_country || "";
    state.countryCIDRs = d.country_cidrs || {};
    const sortedRules = sortRowsBy(d.rules || [], state.sortBlocks);
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
        <td>${badge("network", r.type)}</td>
        <td class="mono">${r.type === "country" ? countryTarget(r) :
          r.type === "list" ? `${esc(r.value)} <span class="dim" ` +
            `title="${esc(r.app_path || "")}">${esc(r.app_path || "")}</span>` :
          esc(r.value)}</td>
        <td><span class="badge ${r.status === "enforced" ? "b-login" :
          r.status === "queued" ? "b-file" : "b-priv"}">${esc(r.status)}</span></td>
        <td class="dim">${esc(r.status_detail || "")}</td>
        <td><button class="mini-btn" data-unblock="${r.id}"
              title="remove this rule" aria-label="remove this rule">&#10006;</button></td>
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

// Row buttons use event delegation so rerendering a live snapshot is safe.
$("connections-list").addEventListener("click", (e) => {
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
$("tbl-live-conns").addEventListener("click", (e) => {
  const btn = e.target.closest("button[data-btype]");
  if (!btn) return;
  if (btn.dataset.btype === "ip") {
    if (confirm(`Block ALL traffic to/from ${btn.dataset.bip}?`))
      addBlock({ type: "ip", ip: btn.dataset.bip });
  } else if (confirm(`Block the app "${btn.dataset.bapp || "this app"}" (all its network traffic)?`)) {
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
  const payload = { type };
  if (type === "country") {
    const cc = $("block-country").value;
    if (!cc) { alert("Pick a country to block first."); return; }
    payload.cc = cc;
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
  } else if (type === "list") {
    const path = $("block-list").value.trim();
    if (!path) { alert("Enter the path of your blocklist file first."); return; }
    payload.list = path;
    if (!confirm(`Block ALL traffic to/from the addresses in\n${path}?\n\n` +
        `The file is re-read on every re-apply/restart — edits take ` +
        `effect without re-adding the rule. When IPolice is running, the ` +
        `file is also registered there as a source.\n\nProceed?`)) {
      return;
    }
  } else if (type === "provider") {
    const provider = $("block-provider").value;
    if (!provider) { alert("Pick an IPolice list first."); return; }
    payload.provider = provider;
    if (!confirm(`Block ALL traffic to/from the ranges of the IPolice list\n` +
        `"${provider}"?\n\nThe ranges are re-fetched on every ` +
        `re-apply/restart — manage the list in IPolice; the block follows ` +
        `it.\n\nProceed?`)) {
      return;
    }
  } else if (type === "paste") {
    const text = $("block-paste").value.trim();
    if (!text) { alert("Paste some IP addresses or CIDRs first."); return; }
    payload.list_text = text;
    payload.name = $("block-paste-name").value.trim() || "uploaded";
    if (!confirm(`Block ALL traffic to/from the pasted addresses?\n\n` +
        `They are saved to the app's data folder as a blocklist file ` +
        `(and registered in IPolice when it is running).\n\nProceed?`)) {
      return;
    }
  } else if (type !== "app") {
    payload.ip = $("block-ip").value.trim();
    if (type === "connection") payload.port = $("block-port").value.trim();
  } else {
    payload.app = $("block-app").value.trim();
  }
  addBlock(payload);
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

/* IPolice list (provider) dropdown: fetched from IPolice when the option
   is picked — country/* and list/* feeds are monitor-managed and excluded */
async function refreshBlockProviderOptions() {
  const select = $("block-provider");
  select.innerHTML = '<option value="">— loading IPolice lists… —</option>';
  try {
    const d = await getJSON("/api/ipolice/providers");
    if (d.error) {
      select.innerHTML =
        `<option value="">IPolice offline (${esc(d.error)})</option>`;
      return;
    }
    if (!(d.providers || []).length) {
      select.innerHTML = '<option value="">no IPolice lists yet — add a ' +
        'source in IPolice (Databases)</option>';
      return;
    }
    select.innerHTML = '<option value="">— pick an IPolice list —</option>' +
      d.providers.map((p) => `<option value="${esc(p)}">${esc(p)}</option>`).join("");
  } catch (e) {
    select.innerHTML = '<option value="">IPolice offline</option>';
  }
}
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

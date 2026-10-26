/* SpaceLens — canvas sunburst / treemap / bars disk explorer. Vanilla JS,
   no deps. Click a segment → focus that folder; click the middle → go up.
   Hover → tooltip with path + size. Scan roots: the preset dropdown, whose
   last entry opens the OS file manager to pick folders or volumes; queue
   several locations to scan them together. Delete from the details pane or
   via checkboxes — everything moves to the OS Trash, never permanently
   deleted here. */

const $ = (s) => document.querySelector(s);
const api = async (path, body) => {
  const opt = body ? { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) } : {};
  const r = await fetch(path, opt);
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || ('HTTP ' + r.status));
  return data;
};

let tree = null;      // root Node of the last finished scan
let focus = null;     // node currently in the middle
let hover = null;     // node under the cursor
let scanning = false;
let pollTimer = null;
let view = 'sun';                 // sun | treemap | bars
let pendingRoots = [];            // multi-scan list shown as chips
let lastRoots = [];               // last scanned roots (rescan after trash)
const selected = new Map();       // path -> display name
const PICK = '__pick__';          // dropdown sentinel: open the OS picker
const rootSel = $('#rootSel');

function fmtBytes(n) {
  if (n == null) return '—';
  const u = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n : n.toFixed(1)) + ' ' + u[i];
}
function fmtNum(n) { return (n || 0).toLocaleString('en-US'); }
function esc(s) { return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
function toast(msg) {
  const t = $('#toast'); t.textContent = msg; t.hidden = false;
  clearTimeout(t._h); t._h = setTimeout(() => { t.hidden = true; }, 3800);
}

/* ---------- theme: dark → light → auto cycle ---------- */

const themeMq = window.matchMedia ? matchMedia('(prefers-color-scheme: light)') : null;

function themeMode() {
  let m = null;
  try { m = localStorage.getItem('spacelens.theme'); } catch { }
  return m === 'dark' || m === 'light' || m === 'auto' ? m : 'dark';
}

function applyTheme(mode) {
  const resolved = mode === 'auto'
    ? (themeMq && themeMq.matches ? 'light' : 'dark') : mode;
  document.body.classList.toggle('light', resolved === 'light');
  $('#themeBtn').textContent = mode === 'dark' ? '🌙' : mode === 'light' ? '☀️' : '🌗';
  $('#themeBtn').title = mode === 'dark' ? 'Dark theme — click for light'
    : mode === 'light' ? 'Light theme — click to follow this device\'s appearance'
    : 'Follows this device\'s appearance — click for dark';
  try { localStorage.setItem('spacelens.theme', mode); } catch { }
}
$('#themeBtn').addEventListener('click', () => applyTheme(
  themeMode() === 'dark' ? 'light' : themeMode() === 'light' ? 'auto' : 'dark'));
if (themeMq) themeMq.addEventListener
  ? themeMq.addEventListener('change', () => { if (themeMode() === 'auto') applyTheme('auto'); })
  : themeMq.addListener(() => { if (themeMode() === 'auto') applyTheme('auto'); });
try { applyTheme(themeMode()); } catch { }

/* ---------- color ---------- */

function hueOf(node) {
  // stable hue per top-level branch: hash the name
  let h = 0;
  for (const ch of node.name) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
  return h % 360;
}
function colorFor(node, depth) {
  const hue = node._hue != null ? node._hue : hueOf(node);
  const light = Math.max(26, Math.min(62, 58 - depth * 5));
  const sat = 62 - depth * 3;
  return `hsl(${hue} ${sat}% ${light}%)`;
}
function assignHues(node, hue, depth) {
  if (depth === 0) { node._hue = hueOf(node); }
  else node._hue = hue;
  (node.children || []).forEach((c, i) => {
    if (depth === 0) assignHues(c, node._hue + i * 47, depth + 1);
    else assignHues(c, hue, depth + 1);
  });
}

/* ---------- sunburst ---------- */

const canvas = $('#sun');
const ctx = canvas.getContext('2d');
const MAXRINGS = 8;

function draw() {
  if (view === 'bars') { renderBarsView(); return; }
  $('#bars').hidden = true;
  canvas.hidden = false;
  if (view === 'treemap') { $('#center').hidden = true; drawTreemap(); }
  else drawSun();
  if (focus) renderCrumbs(crumbsOf(focus));
}

// pre-scan canvas message: point people at the two controls that matter
function drawEmptyState(x, y) {
  const cs = getComputedStyle(document.documentElement);
  ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
  ctx.fillStyle = cs.getPropertyValue('--text').trim();
  ctx.font = '600 16px system-ui';
  ctx.fillText(tree ? 'scan finished' : '① Pick a location   ② Press Scan', x, y - 12);
  ctx.fillStyle = cs.getPropertyValue('--muted').trim();
  ctx.font = '12.5px system-ui';
  ctx.fillText('dropdown ends with 📁 Choose folder or volume… for anything custom', x, y + 14);
}

function drawSun() {
  const dpr = window.devicePixelRatio || 1;
  const size = canvas.clientWidth || 900;
  canvas.width = size * dpr; canvas.height = size * dpr;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, size, size);
  const cx = size / 2, cy = size / 2;
  const rMax = size / 2 - 6;
  const rMin = rMax * 0.22;
  const ringW = (rMax - rMin) / MAXRINGS;
  const bg = getComputedStyle(document.documentElement).getPropertyValue('--bg').trim();

  if (!focus) {
    drawEmptyState(cx, cy);
    return;
  }
  const total = focus.size || 1;
  const base = -Math.PI / 2; // angle 0 at 12 o'clock

  // absolute angular offset of every node (radians' worth of bytes), once per focus
  const setOff = (node, off) => {
    node._off = off;
    let acc = 0;
    for (const c of (node.children || [])) { setOff(c, off + acc); acc += c.size; }
  };
  setOff(focus, 0);

  const drawRing = (node, depth, a0, a1) => {
    const span = a1 - a0;
    if (span <= 0) return;
    const r0 = rMin + depth * ringW;
    if (depth > 0) {
      ctx.beginPath();
      ctx.arc(cx, cy, r0 + ringW - 1.5, a0, a1);
      ctx.arc(cx, cy, r0, a1, a0, true);
      ctx.closePath();
      ctx.fillStyle = node === hover ? `hsl(${node._hue} 82% 68%)` : colorFor(node, depth);
      ctx.fill();
      ctx.strokeStyle = bg;
      ctx.lineWidth = 1;
      ctx.stroke();
    } else {
      // the focused node itself: full inner disc
      ctx.beginPath();
      ctx.arc(cx, cy, r0 + ringW - 1.5, 0, 2 * Math.PI);
      ctx.fillStyle = `hsl(${node._hue} 62% 44%)`;
      ctx.fill();
    }
    if (span < 0.0004 || depth >= MAXRINGS - 1) return;
    for (const c of (node.children || [])) {
      const ca0 = base + (c._off - node._off) / total * 2 * Math.PI;
      const ca1 = ca0 + c.size / total * 2 * Math.PI;
      drawRing(c, depth + 1, ca0, ca1);
    }
  };
  drawRing(focus, 0, base, base + 2 * Math.PI);

  const center = $('#center');
  center.hidden = false;
  $('#centerName').textContent = focus.name || focus.path || '/';
  $('#centerSize').textContent = fmtBytes(focus.size);
  $('#centerHint').textContent = focus._parent ? 'click middle: up one level' : 'top of scan';
}

function crumbsOf(node) {
  const path = [];
  let p = node;
  while (p) { path.unshift(p); p = p._parent; }
  return path;
}

function nodeAt(mx, my) {
  if (!focus) return null;
  const rect = canvas.getBoundingClientRect();
  const size = rect.width;
  const cx = size / 2, cy = size / 2;
  const dx = mx - cx, dy = my - cy;
  const dist = Math.hypot(dx, dy);
  const rMax = size / 2 - 6, rMin = rMax * 0.22;
  const ringW = (rMax - rMin) / MAXRINGS;
  if (dist <= rMin + ringW) return focus; // the whole drawn center disc
  if (dist > rMax) return null;
  const depth = Math.min(MAXRINGS - 1, Math.floor((dist - rMin) / ringW));
  let ang = Math.atan2(dy, dx) + Math.PI / 2; // 0 at top
  if (ang < 0) ang += 2 * Math.PI;
  const total = focus.size || 1;
  // children live one ring out of their parent: node drawn at ring d,
  // its children at ring d+1 — hence the d + 1 === depth check
  const find = (node, d, base) => {
    for (const c of (node.children || [])) {
      const a0 = base + (c._off - node._off) / total * 2 * Math.PI;
      const a1 = a0 + c.size / total * 2 * Math.PI;
      if (ang >= a0 && ang < a1) {
        if (d + 1 === depth) return c;
        return find(c, d + 1, a0);
      }
    }
    return null; // empty area (beyond a leaf) — nothing to highlight
  };
  return find(focus, 0, 0);
}

/* ---------- treemap ---------- */

const TM_DEPTH = 4; // levels of subdivision below the focused node
let tmCells = [];   // {x, y, w, h, node, depth} in CSS px, rebuilt per draw

function tmAt(mx, my) {
  for (let i = tmCells.length - 1; i >= 0; i--) {
    const c = tmCells[i];
    if (mx >= c.x && mx < c.x + c.w && my >= c.y && my < c.y + c.h) return c.node;
  }
  return null;
}

function worstRatio(row, side) {
  const s = row.reduce((a, c) => a + c.area, 0);
  const thick = s / side;
  let worst = 0;
  for (const c of row) {
    const len = c.area / thick;
    worst = Math.max(worst, Math.max(len / thick, thick / len));
  }
  return worst;
}

// classic squarified treemap: each strip spans the shorter side of the
// remaining rectangle, so its thickness (rowSum / span) always fits
function squarifyLayout(items, x, y, w, h) {
  const out = [];
  let i = 0;
  while (i < items.length) {
    if (w <= 0 || h <= 0) break;
    const across = w <= h; // horizontal strip spanning the width
    const span = across ? w : h;
    let row = [items[i]];
    let sum = items[i].area;
    let worst = worstRatio(row, span);
    i++;
    while (i < items.length) {
      const nrow = row.concat(items[i]);
      const nworst = worstRatio(nrow, span);
      if (nworst > worst) break;
      row = nrow; sum += items[i].area; worst = nworst; i++;
    }
    const thick = sum / span;
    if (thick <= 0 || !isFinite(thick)) break;
    let off = 0;
    for (const it of row) {
      const len = it.area / thick;
      if (across) out.push({ x: x + off, y, w: len, h: thick, node: it.node });
      else out.push({ x, y: y + off, w: thick, h: len, node: it.node });
      off += len;
    }
    if (across) { y += thick; h -= thick; } else { x += thick; w -= thick; }
  }
  return out;
}

function layoutTreemap(node, x, y, w, h, depth) {
  const kids = (node.children || []).filter(c => c.size > 0);
  if (!kids.length || depth >= TM_DEPTH || w < 8 || h < 8) {
    tmCells.push({ x, y, w, h, node, depth }); // leaf: itself is the cell
    return;
  }
  kids.sort((a, b) => b.size - a.size);
  const total = kids.reduce((s, c) => s + c.size, 0) || 1;
  const items = kids.map(c => ({ node: c, area: c.size / total * w * h }));
  for (const r of squarifyLayout(items, x, y, w, h)) {
    r.depth = depth;
    tmCells.push(r);
    if (r.node.isDir && !r.node.residual && depth + 1 < TM_DEPTH && r.w > 8 && r.h > 8) {
      layoutTreemap(r.node, r.x + 1, r.y + 1, r.w - 2, r.h - 2, depth + 1);
    }
  }
}

function clipText(s, maxW) {
  if (ctx.measureText(s).width <= maxW) return s;
  while (s.length > 1 && ctx.measureText(s + '…').width > maxW) s = s.slice(0, -1);
  return s + '…';
}

function drawTreemap() {
  const dpr = window.devicePixelRatio || 1;
  const size = canvas.clientWidth || 900;
  canvas.width = size * dpr; canvas.height = size * dpr;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, size, size);
  if (!focus) {
    drawEmptyState(size / 2, size / 2);
    return;
  }
  tmCells = [];
  layoutTreemap(focus, 0, 0, size, size, 0);
  ctx.textAlign = 'left'; ctx.textBaseline = 'alphabetic';
  for (const c of tmCells) {
    const cw = Math.max(0.5, c.w - 1), ch = Math.max(0.5, c.h - 1);
    ctx.fillStyle = c.node === hover ? `hsl(${c.node._hue} 82% 68%)` : colorFor(c.node, c.depth + 1);
    if (c.node.residual) ctx.globalAlpha = 0.55;
    ctx.fillRect(c.x, c.y, cw, ch);
    ctx.globalAlpha = 1;
    if (c.node === hover) {
      ctx.strokeStyle = getComputedStyle(document.documentElement).getPropertyValue('--accent').trim();
      ctx.lineWidth = 2;
      ctx.strokeRect(c.x + 1, c.y + 1, cw - 2, ch - 2);
    }
    if (c.w > 42 && c.h > 16) {
      ctx.fillStyle = '#fff';
      ctx.shadowColor = 'rgba(0,0,0,.55)'; ctx.shadowBlur = 2; ctx.shadowOffsetY = 1;
      ctx.font = '11px system-ui';
      ctx.fillText(clipText(c.node.name, c.w - 8), c.x + 4, c.y + 13);
      if (c.h > 30) {
        ctx.font = '10px ui-monospace, monospace';
        ctx.fillText(fmtBytes(c.node.size), c.x + 4, c.y + 27);
      }
      ctx.shadowColor = 'transparent'; ctx.shadowBlur = 0; ctx.shadowOffsetY = 0;
    }
  }
}

/* ---------- bars view ---------- */

let barsKids = [];

function renderBarsView() {
  canvas.hidden = true;
  $('#center').hidden = true;
  const host = $('#bars');
  host.hidden = false;
  if (focus) renderCrumbs(crumbsOf(focus));
  if (!focus) { host.innerHTML = '<p class="muted">Scan a folder first.</p>'; return; }
  barsKids = [...(focus.children || [])].sort((a, b) => b.size - a.size);
  const max = barsKids.length ? barsKids[0].size : 0;
  host.innerHTML =
    `<div class="bars-head"><b>${esc(focus.name || focus.path || '/')}</b>` +
    `<span class="muted">${fmtBytes(focus.size)} · ${fmtNum(barsKids.length)} item(s)</span></div>` +
    (barsKids.length ? barsKids.map((c, i) => `
    <div class="bar-row" data-i="${i}">
      <input type="checkbox" class="pick" data-path="${esc(c.path || '')}" data-name="${esc(c.name)}"
             aria-label="Select ${esc(c.name)}"
             ${c.path && selected.has(c.path) ? 'checked' : ''} ${c.path ? '' : 'disabled title="aggregate of smaller items"'}>
      <span class="b-name" title="${esc(c.path || c.name)}">${esc(c.name)}</span>
      <span class="b-track"><span class="b-fill${c.residual ? ' res' : ''}" style="width:${max ? (c.size / max * 100).toFixed(2) : 0}%;${c.residual ? '' : 'background:' + colorFor(c, 1)}"></span></span>
      <span class="b-size">${fmtBytes(c.size)}</span>
    </div>`).join('') : '<p class="muted">No items inside — this is a single file.</p>');
  wireBars(host);
  bindPicks(host);
}

function wireBars(host) {
  host.querySelectorAll('.bar-row').forEach(row => {
    row.addEventListener('click', (e) => {
      if (e.target.tagName === 'INPUT') return;
      const c = barsKids[+row.dataset.i];
      if (!c) return;
      if (c.isDir) { focus = c; hover = null; draw(); renderSel(); }
      else if (c.path) revealPath(c.path);
    });
  });
}

/* ---------- canvas interactions ---------- */

canvas.addEventListener('mousemove', (e) => {
  const rect = canvas.getBoundingClientRect();
  const mx = e.clientX - rect.left, my = e.clientY - rect.top;
  const n = view === 'treemap' ? tmAt(mx, my) : nodeAt(mx, my);
  hover = n;
  const tip = $('#tip');
  if (n && n !== focus) {
    tip.hidden = false;
    tip.style.left = (e.clientX + 14) + 'px';
    tip.style.top = (e.clientY + 14) + 'px';
    tip.innerHTML = `<b>${esc(n.name)}</b><br>${fmtBytes(n.size)} · ${fmtNum(n.files)} file(s)`;
    canvas.style.cursor = 'pointer';
  } else {
    tip.hidden = true;
    canvas.style.cursor = 'default';
  }
  draw();
});
canvas.addEventListener('mouseleave', () => { hover = null; $('#tip').hidden = true; draw(); });
canvas.addEventListener('click', (e) => {
  const rect = canvas.getBoundingClientRect();
  const mx = e.clientX - rect.left, my = e.clientY - rect.top;
  if (view === 'treemap') {
    const n = tmAt(mx, my);
    if (!n) return;
    hover = null;
    if (n.isDir || n.residual) { focus = n; draw(); renderSel(); }
    else if (n.path) revealPath(n.path);
    return;
  }
  const size = rect.width;
  const dx = mx - size / 2, dy = my - size / 2;
  const rMax = size / 2 - 6, rMin = rMax * 0.22;
  const ringW = (rMax - rMin) / MAXRINGS;
  if (Math.hypot(dx, dy) < rMin + ringW - 1.5) {
    // the whole center disc = go up one level (matches the drawn disc)
    if (focus && focus._parent) { focus = focus._parent; hover = null; draw(); renderSel(); }
    return;
  }
  if (hover && hover !== focus) { focus = hover; hover = null; draw(); renderSel(); }
});

document.querySelectorAll('#views button').forEach(b =>
  b.addEventListener('click', () => setView(b.dataset.view)));
function setView(v) {
  view = v;
  document.querySelectorAll('#views button').forEach(b =>
    b.classList.toggle('active', b.dataset.view === v));
  hover = null; $('#tip').hidden = true;
  draw();
}

/* ---------- side pane ---------- */

function renderCrumbs(path) {
  $('#crumbs').innerHTML = path.map((n, i) =>
    `<button data-i="${i}">${esc(n.name)}</button>`).join(' <span class="muted">›</span> ');
  document.querySelectorAll('#crumbs button').forEach(b =>
    b.addEventListener('click', () => { focus = path[+b.dataset.i]; draw(); renderSel(); }));
}

function renderSel() {
  const n = focus;
  if (!n) return;
  const share = tree && n.size ? (n.size / tree.size * 100) : 0;
  const canReveal = !!n.path;
  $('#sel').innerHTML = `
    <div class="card">
      <div class="mono">${esc(n.path || n.name)}</div>
      <div class="row"><span class="k">Size</span><span class="mono">${fmtBytes(n.size)} (${share.toFixed(1)}% of scan)</span></div>
      <div class="row"><span class="k">Files</span><span class="mono">${fmtNum(n.files)}</span></div>
      <div class="row"><span class="k">Folders</span><span class="mono">${fmtNum(n.dirs)}</span></div>
      ${n.errs ? `<div class="row"><span class="k">Unreadable</span><span class="mono">${fmtNum(n.errs)}</span></div>` : ''}
      ${n.residual ? '<p class="muted small" style="margin:6px 0 0">This is an aggregate of smaller items hidden for readability.</p>' : ''}
      ${n.path ? `<label class="pick-row"><input type="checkbox" class="pick" data-path="${esc(n.path)}" data-name="${esc(n.name)}" ${selected.has(n.path) ? 'checked' : ''}> Select for trash</label>` : ''}
      ${canReveal ? `<div class="actions">
        <button class="btn ghost small" id="revealBtn" title="Open in the OS file manager">📂 Reveal</button>
        <button class="btn danger-ghost small" id="trashBtn" title="Move this to the OS Trash — recoverable">🗑 Move to Trash</button>
      </div>` : ''}
    </div>`;
  bindPicks($('#sel'));
  const rv = $('#revealBtn');
  if (rv) rv.addEventListener('click', async () => {
    const target = n.residual ? (n._parent ? n._parent.path : '') : n.path;
    await revealPath(target);
  });
  const tv = $('#trashBtn');
  if (tv) tv.addEventListener('click', () => {
    // single-item delete: reuse the batch confirm dialog + trash flow
    selected.clear();
    selected.set(n.path, n.name || n.path);
    renderDelbar(); syncChecksAll();
    $('#delBtn').click();
  });
}

async function revealPath(p) {
  if (!p) return;
  try {
    await api('/api/reveal', { path: p });
    toast('Opened in file manager');
  } catch (e) { toast('Reveal failed: ' + e.message); }
}

function renderBig(list) {
  $('#bigMeta').textContent = list.length ? `top ${list.length}` : '';
  $('#bigList').innerHTML = list.map((b) => `
    <div class="big-item" data-path="${esc(b.path)}">
      <input type="checkbox" class="pick" data-path="${esc(b.path)}" data-name="${esc(b.path.split('/').pop() || b.path)}" ${selected.has(b.path) ? 'checked' : ''} aria-label="Select ${esc(b.path)}">
      <span class="p" title="${esc(b.path)}">${esc(b.path)}</span>
      <span class="s">${fmtBytes(b.size)}</span>
    </div>`).join('');
  document.querySelectorAll('.big-item').forEach(el =>
    el.addEventListener('click', (e) => {
      if (e.target.tagName === 'INPUT') return;
      revealPath(el.dataset.path);
    }));
  bindPicks($('#bigList'));
}

/* ---------- selection & trash ---------- */

function toggleSelect(path, name, on) {
  if (!path) return;
  if (on) selected.set(path, name || path); else selected.delete(path);
  renderDelbar();
  // keep every checkbox for the same path in sync (bars, biggest, details)
  document.querySelectorAll(`input.pick[data-path="${CSS.escape(path)}"]`).forEach(cb => {
    if (cb.checked !== on) cb.checked = on;
  });
}

function syncChecksAll() {
  document.querySelectorAll('input.pick[data-path]').forEach(cb => {
    cb.checked = !!cb.dataset.path && selected.has(cb.dataset.path);
  });
}

function bindPicks(root) {
  root.querySelectorAll('input.pick').forEach(cb => {
    cb.addEventListener('click', e => e.stopPropagation());
    cb.addEventListener('change', () =>
      toggleSelect(cb.dataset.path, cb.dataset.name, cb.checked));
  });
}

function renderDelbar() {
  const bar = $('#delbar');
  bar.hidden = selected.size === 0;
  $('#delCount').textContent = `${selected.size} selected`;
}

$('#delClear').addEventListener('click', () => {
  selected.clear(); renderDelbar(); syncChecksAll();
});

$('#delBtn').addEventListener('click', () => {
  $('#delList').innerHTML = [...selected.keys()].map(p => `<li>${esc(p)}</li>`).join('');
  $('#delGo').textContent = `Trash ${selected.size} item${selected.size === 1 ? '' : 's'}`;
  $('#confirmDlg').showModal();
});

$('#delCancel').addEventListener('click', () => $('#confirmDlg').close());

$('#delGo').addEventListener('click', async () => {
  const paths = [...selected.keys()];
  $('#delGo').disabled = true;
  try {
    const r = await api('/api/delete', { paths });
    const results = r.results || [];
    const bad = results.filter(x => !x.ok);
    if (bad.length) toast(`Trashed ${results.length - bad.length}, failed ${bad.length} — first: ${bad[0].error}`);
    else toast(`Moved ${paths.length} item(s) to the OS Trash`);
  } catch (e) {
    toast('Delete failed: ' + e.message);
  }
  $('#delGo').disabled = false;
  $('#confirmDlg').close();
  selected.clear(); renderDelbar();
  if (lastRoots.length) startScan(lastRoots); // refresh numbers after trash
});

/* ---------- scan lifecycle ---------- */

async function loadRoots() {
  try {
    const d = await api('/api/roots');
    const opts = d.roots.map(r => `<option value="${esc(r.path)}">${esc(r.name)} — ${esc(r.path)}</option>`).join('');
    rootSel.innerHTML =
      `<optgroup label="Locations">${opts}</optgroup>` +
      `<optgroup label="Custom"><option value="${PICK}">📁 Choose folder or volume…</option></optgroup>`;
  } catch { /* dropdown optional */ }
}

function renderChips() {
  const host = $('#chips');
  host.hidden = pendingRoots.length === 0;
  host.innerHTML = pendingRoots.map((p, i) =>
    `<span class="chip" title="${esc(p)}"><span>${esc(p)}</span><button data-i="${i}" aria-label="Remove ${esc(p)}">×</button></span>`).join('');
  host.querySelectorAll('button').forEach(b =>
    b.addEventListener('click', () => { pendingRoots.splice(+b.dataset.i, 1); renderChips(); }));
}

function addRoots(paths) {
  let added = 0;
  for (const p of paths || []) {
    const t = (p || '').trim();
    if (t && !pendingRoots.includes(t)) { pendingRoots.push(t); added++; }
  }
  renderChips();
  return added;
}

$('#addBtn').addEventListener('click', () => {
  const v = rootSel.value;
  if (!v || v === PICK) { toast('Choose a location first'); return; }
  addRoots([v]);
});

// "📁 Choose folder or volume…" opens the native OS folder picker; picked
// paths become chips. Afterwards the dropdown snaps back to the first
// preset so picking again (single-select on Windows) fires another change.
rootSel.addEventListener('change', async () => {
  if (rootSel.value !== PICK) return;
  try {
    const d = await api('/api/pick', {});
    const n = addRoots(d.paths || []);
    toast(n ? `Added ${n} location${n === 1 ? '' : 's'} — Scan to start` : 'No folder chosen');
  } catch (e) { toast('Picker failed: ' + e.message); }
  const first = [...rootSel.options].find(o => o.value !== PICK);
  rootSel.value = first ? first.value : '';
});

function startScan(roots) {
  lastRoots = [...roots];
  api('/api/scan', { roots }).then(() => {
    scanning = true;
    $('#cancelBtn').hidden = false;
    $('#scanBtn').disabled = true;
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(poll, 400);
    poll();
  }).catch(e => toast('Scan failed: ' + e.message));
}

$('#scanBtn').addEventListener('click', () => {
  let roots;
  if (pendingRoots.length) {
    roots = [...pendingRoots];
  } else {
    const v = rootSel.value;
    if (!v || v === PICK) { toast('Choose a folder to scan'); return; }
    roots = [v];
  }
  startScan(roots);
});
$('#cancelBtn').addEventListener('click', () => api('/api/scan/cancel', {}).catch(() => {}));
window.addEventListener('resize', draw);

function poll() {
  api('/api/scan/poll').then(p => {
    if (p.running) {
      const where = (p.roots && p.roots.length > 1)
        ? `${p.roots.length} locations — ${p.current || ''}`
        : (p.current || p.root);
      $('#progress').textContent = `scanning ${where}… ${fmtNum(p.files)} files · ${fmtBytes(p.bytes)}`;
      return;
    }
    clearInterval(pollTimer); pollTimer = null;
    $('#cancelBtn').hidden = true;
    $('#scanBtn').disabled = false;
    if (p.error) { $('#progress').textContent = 'scan failed: ' + p.error; return; }
    if (!p.done) { $('#progress').textContent = ''; return; }
    scanning = false;
    tree = p.tree;
    const link = (n, parent) => { n._parent = parent; for (const c of (n.children || [])) link(c, n); };
    link(tree, null);
    focus = tree;
    assignHues(tree, 0, 0);
    draw(); renderSel();
    renderBig(p.biggest || []);
    $('#progress').textContent =
      `${fmtNum(p.files)} files · ${fmtBytes(p.bytes)} · ${p.durationS.toFixed(1)}s` +
      (p.errs ? ` · ${fmtNum(p.errs)} unreadable` : '');
  }).catch(() => { /* poll hiccup — next tick retries */ });
}

(async function init() {
  try { const s = await api('/api/status'); document.querySelectorAll('.ver').forEach(el => el.textContent = 'v' + s.version); } catch { }
  await loadRoots();
})();

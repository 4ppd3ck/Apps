'use strict';
/* feed.js — wGrid's feed UI: provider/source table, IP lookup, refresh,
   source add/remove, peer status. Ported from the merged wTower
   dashboard's intel panel (web/app.js loadIntel/renderIntel/intelPost),
   pointed at wGrid's own endpoints. */

(function () {

const $ = (s) => document.querySelector(s);
const esc = (t) => String(t ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

let intelSources = []; // last /api/sources payload
let intelStatus = null; // last /api/status payload

function fmtTime(ts) {
  if (!ts) return 'never';
  const d = new Date(ts * 1000);
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) +
    ' ' + d.toLocaleTimeString();
}

function toast(msg, isErr) {
  const t = $('#toast');
  t.textContent = msg;
  t.classList.toggle('err', !!isErr);
  t.hidden = false;
  clearTimeout(t._h);
  t._h = setTimeout(() => { t.hidden = true; }, 4200);
}

async function getJSON(path) {
  const r = await fetch(path);
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || ('HTTP ' + r.status));
  return d;
}

/* ---------- status + sources table ---------- */

async function loadIntel() {
  try {
    const [status, sources] = await Promise.all([
      getJSON('/api/status'),
      getJSON('/api/sources'),
    ]);
    intelStatus = status;
    intelSources = sources.sources || [];
    renderIntel();
  } catch (e) { console.warn('intel', e); }
}

function renderIntel() {
  const tag = $('#intel-status-tag');
  const st = intelStatus || {};
  const nets = st.networks ?? 0;
  const provs = Object.keys(st.providers || {}).length;
  const errs = Object.keys(st.errors || {}).length;
  tag.classList.remove('ok', 'warn', 'err');
  if (errs > 0 && nets === 0) {
    tag.textContent = 'offline';
    tag.classList.add('err');
  } else {
    tag.textContent = `${provs} providers · ${nets} networks`;
    tag.classList.add(errs > 0 ? 'warn' : 'ok');
  }
  const updated = st.updated_at ? fmtTime(st.updated_at) : 'never';
  $('#intel-summary').innerHTML =
    `updated ${esc(updated)} · ${provs} providers / ${nets} networks` +
    (errs ? ` · <span style="color:var(--amber)">${errs} source error(s)</span>` : '');

  $('#tbl-intel-sources').tBodies[0].innerHTML = intelSources.map((s) => {
    const loc = s.type === 'file' ? (s.path || s.url || '')
      : s.type === 'git' ? `${s.url} · ${s.path}` : (s.url || '');
    const name = `${s.name}${s.default ? ' (default)' : ''}`;
    return `<tr>
      <td title="${esc(name)}"><b>${esc(s.name)}</b>${s.default ? ' <span class="dim">(default)</span>' : ''}</td>
      <td class="mono dim" title="${esc(loc)}">${esc(loc)}</td>
      <td class="mono dim">${esc(s.format)}</td>
      <td class="mono dim">${esc(s.type || 'http')}</td>
      <td>${s.error ? `<span style="color:var(--amber)" title="${esc(s.error)}">error</span>` : 'ok'}</td>
      <td><button class="btn ghost intel-src-del" data-name="${esc(s.name)}"
            data-url="${esc(s.url || '')}" data-type="${esc(s.type || 'http')}"
            data-path="${esc(s.path || '')}"
            title="remove this source (deletions persist)">&times;</button></td>
    </tr>`;
  }).join('') || '<tr><td colspan="6" class="dim">no sources — add one above</td></tr>';
}

async function intelPost(path, payload, okText) {
  try {
    const r = await fetch(path, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const d = await r.json();
    if (!r.ok || d.ok === false) throw new Error(d.error || r.status);
    $('#intel-summary').textContent = okText;
  } catch (e) {
    $('#intel-summary').textContent = 'failed: ' + e.message;
  }
  loadIntel();
}

/* ---------- peers pills (header) ---------- */

// wHawk-style pills, one per peer, in the page header: green when up, red
// when down — the connection error is demoted to the tooltip instead of
// flooding the panel.
async function loadWired() {
  const set = (id, p) => {
    const el = $(id);
    if (!el) return;
    if (!p) { el.classList.remove('on', 'off'); return; }
    const cls = p.running ? 'on' : 'off';
    el.classList.remove('on', 'off');
    el.classList.add(cls);
    el.textContent = `${p.name} · ${p.running ? 'up' : 'down'}`;
    el.title = p.running ? (p.url || '') : `${p.url || ''} — ${p.error || 'unreachable'}`;
  };
  try {
    const d = await getJSON('/api/wired');
    // a peer absent from the payload is not discoverable right now —
    // surface that as down rather than leaving a stale "…"
    set('#peerWhawk', d.whawk || { name: 'wHawk', running: false, error: 'not in the launcher registry' });
    set('#peerWpurge', d.wpurge || { name: 'wPurge', running: false, error: 'not in the launcher registry' });
  } catch (e) { /* server hiccup — the pills keep their pending state */ }
}

/* ---------- installed apps via wPurge ---------- */

// Scans the apps wPurge reports installed (GET /api/apps — the wPurge
// inventory joined with the vendor catalog) and offers the official IP
// database of every installed vendor as an "Add & download" action, which
// is a plain /api/sources/add + background refresh. Ported from the
// original wGrid dashboard when this app's UI was rebuilt lean.
async function scanApps() {
  $('#appsMeta').textContent = 'scanning…';
  $('#appsErr').style.display = 'none';
  try {
    const r = await getJSON('/api/apps');
    if (!r.reachable) {
      $('#appsErr').textContent = 'wPurge unreachable: ' + (r.error || 'is it running?') +
        ' — the installed-apps scan runs through wPurge.';
      $('#appsErr').style.display = '';
      $('#tbl-apps').tBodies[0].innerHTML =
        '<tr><td colspan="5" class="dim">wPurge unreachable</td></tr>';
      $('#appsMeta').textContent = '';
      return;
    }
    $('#appsMeta').textContent =
      `${r.apps_count} installed apps · scanned ${new Date().toLocaleTimeString()}`;
    const entries = r.entries || [];
    $('#tbl-apps').tBodies[0].innerHTML = entries.map((e) => {
      const apps = (e.apps || []).map((a) => esc(a.name)).join(', ');
      const status = e.active ? '<span class="tag ok">active</span>'
        : e.seed_only ? '<span class="tag warn">seed 🌱</span>'
        : '<span class="tag">available</span>';
      const action = e.active || e.seed_only || !e.source ? '<span class="dim">—</span>'
        : `<button class="btn ghost" data-add='${esc(JSON.stringify(e.source))}'>Add &amp; download</button>`;
      return `<tr><td><b>${esc(e.vendor)}</b></td>
        <td>${apps || '<span class="dim">not installed</span>'}</td>
        <td>${esc(e.provider)}${e.note ? `<div class="dim">${esc(e.note)}</div>` : ''}</td>
        <td>${status}</td><td>${action}</td></tr>`;
    }).join('') || '<tr><td colspan="5" class="dim">catalog empty</td></tr>';
    document.querySelectorAll('#tbl-apps [data-add]').forEach((b) =>
      b.addEventListener('click', async () => {
        b.disabled = true;
        try {
          const res = await fetch('/api/sources/add', {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: b.dataset.add,
          });
          const out = await res.json().catch(() => ({}));
          $('#appsMeta').textContent = out.error || out.message || '';
          loadIntel();
          setTimeout(loadIntel, 2500);
          setTimeout(scanApps, 4000);
        } catch (err) { $('#appsMeta').textContent = 'failed: ' + err.message; }
      }));
    const un = r.unmatched || [];
    $('#apps-unmatched').textContent = un.length
      ? `No known IP database for ${un.length} app(s): ${un.slice(0, 12).map((a) => a.name).join(', ')}${un.length > 12 ? '…' : ''}`
      : '';
  } catch (e) { $('#appsMeta').textContent = 'scan failed: ' + e.message; }
}
$('#scanApps').addEventListener('click', scanApps);

/* ---------- controls ---------- */

$('#intel-lookup').addEventListener('input', async (e) => {
  const ip = e.target.value.trim();
  try {
    if (!ip) { $('#intel-lookup-result').textContent = ''; return; }
    const d = await getJSON('/api/intel?ip=' + encodeURIComponent(ip));
    $('#intel-lookup-result').textContent = d.known
      ? `→ ${d.provider}` : '→ unknown';
  } catch (err) { $('#intel-lookup-result').textContent = ''; }
});

$('#intel-refresh-btn').addEventListener('click', () =>
  intelPost('/api/refresh', {}, 'refreshing in the background'));

$('#intel-add-btn').addEventListener('click', () => {
  const form = $('#intel-add-form');
  form.style.display = form.style.display === 'none' ? '' : 'none';
});
$('#intel-src-cancel').addEventListener('click', () => {
  $('#intel-add-form').style.display = 'none';
});
$('#intel-src-type').addEventListener('change', (e) => {
  const gitOrFile = e.target.value !== 'http';
  $('#intel-src-path').style.display = gitOrFile ? '' : 'none';
  $('#intel-src-url').placeholder = e.target.value === 'file'
    ? 'url (optional for a local file)' : 'url of the feed';
});
$('#intel-src-save').addEventListener('click', () => {
  const type = $('#intel-src-type').value;
  const src = {
    name: $('#intel-src-name').value.trim(),
    url: $('#intel-src-url').value.trim(),
    path: $('#intel-src-path').value.trim(),
    format: $('#intel-src-format').value,
  };
  if (type !== 'http') src.type = type;
  if (!src.name) { $('#intel-summary').textContent = 'a provider name is required'; return; }
  intelPost('/api/sources/add', src, 'added — fetching in the background');
});

$('#tbl-intel-sources').addEventListener('click', (e) => {
  const del = e.target.closest('.intel-src-del');
  if (!del) return;
  intelPost('/api/sources/delete', {
    name: del.dataset.name, url: del.dataset.url,
    type: del.dataset.type, path: del.dataset.path,
  }, 'removed');
});

/* ---------- Excel-style column resize ---------- */

// The shared .tbl-wrap tables keep the design system's fixed layout +
// ellipsis: long cells truncate and the full text stays in the cell's
// title tooltip. These edge handles add the Excel behavior — drag a
// header's right edge to widen that one column (the others keep their
// frozen widths and the table grows past the panel, where .tbl-wrap's
// horizontal scrollbar takes over) or narrow it; double-click resets the
// table to its default widths.
for (const id of ['#tbl-intel-sources', '#tbl-apps']) {
  const table = $(id);
  const cells = [...table.tHead.rows[0].cells];
  const defWidths = cells.map((t) => t.style.width); // design defaults (some are inline styles)
  const ths = cells;
  ths.forEach((th) => {
    const handle = document.createElement('span');
    handle.className = 'col-resizer';
    handle.title = 'drag to resize this column · double-click to reset';
    handle.addEventListener('pointerdown', (e) => {
      e.preventDefault();
      // freeze every column at its current width so only the dragged one moves
      cells.forEach((t) => { t.style.width = t.offsetWidth + 'px'; });
      const startX = e.clientX;
      const startW = th.offsetWidth;
      const onMove = (ev) => {
        th.style.width = Math.max(48, startW + ev.clientX - startX) + 'px';
      };
      const onUp = () => {
        document.removeEventListener('pointermove', onMove);
        document.removeEventListener('pointerup', onUp);
        document.body.classList.remove('col-resizing');
      };
      document.addEventListener('pointermove', onMove);
      document.addEventListener('pointerup', onUp);
      document.body.classList.add('col-resizing');
    });
    handle.addEventListener('dblclick', () => {
      cells.forEach((t, i) => { t.style.width = defWidths[i]; });
    });
    th.appendChild(handle);
  });
}

loadIntel();
loadWired();
setInterval(loadWired, 30000); // peers restart — keep the header pills honest

})();

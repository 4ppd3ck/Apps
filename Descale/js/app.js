'use strict';
/* Descale dashboard — talks to the local Go server. The client only ever
   sends rule IDs / app paths that the server itself enumerated; all paths
   are derived and re-validated server-side. Scanning runs as a background
   job; the UI polls /api/scan/poll and renders the full report when done. */

const $ = s => document.querySelector(s);
const esc = t => String(t ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const CAT_ICON = { Caches: '🗃️', Development: '🛠️', Logs: '📜', System: '⚙️', Trash: '🗑️', Downloads: '📥', Docker: '🐳' };
let report = null;
const selected = new Set();
let tab = localStorage.getItem('descale.tab') || 'buildup';
let pollTimer = null;

function fmtBytes(n) {
  if (!n) return '0 B';
  const u = ['B','KB','MB','GB','TB'];
  const i = Math.min(u.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
  return (n / Math.pow(1024, i)).toFixed(i ? 1 : 0) + ' ' + u[i];
}

async function api(path, body) {
  const opt = body ? { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body) } : {};
  const r = await fetch(path, opt);
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || ('HTTP ' + r.status));
  return data;
}

function toast(msg, isErr) {
  const t = $('#toast');
  t.textContent = msg;
  t.classList.toggle('err', !!isErr);
  t.hidden = false;
  clearTimeout(t._h);
  t._h = setTimeout(() => { t.hidden = true; }, 4200);
}

function showError(msg) {
  const el = $('#error');
  el.textContent = '⚠️ ' + msg;
  el.hidden = false;
}

/* ---------- theme ---------- */

function setTheme(t) {
  document.documentElement.dataset.theme = t;
  localStorage.setItem('descale.theme', t);
  $('#themeBtn').textContent = t === 'dark' ? '☀️' : '🌙';
}
$('#themeBtn').addEventListener('click', () =>
  setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'));

/* ---------- onboarding ---------- */

function initOnboarding() {
  if (!localStorage.getItem('descale.onboarded')) $('#onboard').hidden = false;
  $('#onboardOk').addEventListener('click', () => {
    $('#onboard').hidden = true;
    localStorage.setItem('descale.onboarded', '1');
  });
}

/* ---------- tabs ---------- */

function showTab(t) {
  tab = t;
  localStorage.setItem('descale.tab', t);
  document.querySelectorAll('.tabs button').forEach(b => b.classList.toggle('on', b.dataset.tab === t));
  for (const name of ['buildup', 'uninstall', 'traces', 'startup']) {
    document.getElementById('tab-' + name).hidden = name !== t;
  }
  $('#cleanbar').hidden = t !== 'buildup' || selected.size === 0;
  if (t === 'uninstall') loadApps();
  if (t === 'traces') loadTraces();
  if (t === 'startup') loadStartup();
}

document.querySelectorAll('.tabs button').forEach(b =>
  b.addEventListener('click', () => showTab(b.dataset.tab)));

/* ---------- Buildup: scanning (background job + polling) ---------- */

async function init() {
  try {
    const info = await api('/api/info');
    const bits = [info.osVersion ? `macOS ${info.osVersion}` : info.os, info.archLabel].filter(Boolean);
    if (info.diskFreeBytes) bits.push(fmtBytes(info.diskFreeBytes) + ' free');
    $('#machine').textContent = `${bits.join(' · ')}\n${info.rulesActive} active rules · ${info.rulesSigned ? 'rules signed' : 'rules unsigned'} · v${info.version}`;
    if (info.os === 'windows') {
      $('#startupNote').textContent = 'These are Windows autostart entries: your user Run key (HKCU\\…\\Run) and the Startup folder. Deactivating a Run-key entry stores its value and removes it (reversible via Activate); Startup-folder items are renamed. Machine-wide HKLM entries are read-only — they need an administrator.';
    }
    $('#trustJournal').textContent = info.os === 'windows'
      ? info.home + '\\.descale\\journal.json'
      : info.home + '/.descale/journal.json';
    $('#trustSigned').textContent = info.rulesSigned
      ? 'A signature file is present and verified against the public key embedded in this build.'
      : 'No signature file — running in unsigned local mode (add one with `descale rules sign`).';
  } catch (e) { showError('Could not reach the Descale server: ' + e.message); }
  initOnboarding();
  showTab(tab);
  if (tab === 'buildup') pollScan(); // picks up an in-flight job after reload
}

function scan() {
  $('#error').hidden = true;
  $('#results').hidden = true;
  $('#stats').hidden = true;
  $('#scanBtn').disabled = true;
  if (pollTimer) clearInterval(pollTimer);
  api('/api/scan', {})
    .then(() => { pollTimer = setInterval(pollScan, 350); pollScan(); })
    .catch(e => { showError('Scan failed: ' + e.message); $('#scanBtn').disabled = false; });
}

async function pollScan() {
  let d;
  try { d = await api('/api/scan/poll'); }
  catch (e) { return; }
  if (d.running) {
    $('#scanProgress').hidden = false;
    $('#scanBar').style.width = (d.total ? Math.round(d.done * 100 / d.total) : 0) + '%';
    $('#scanMeta').textContent = `scanned ${d.done}/${d.total} rules…`;
    return;
  }
  clearInterval(pollTimer);
  pollTimer = null;
  $('#scanProgress').hidden = true;
  $('#scanMeta').textContent = '';
  $('#scanBtn').disabled = false;
  if (d.report) {
    report = d.report;
    selected.clear();
    render();
    loadJournalCount();
  }
}

/* ---------- Buildup: rendering ---------- */

function cardHTML(res) {
  const blocked = res.status === 'blocked';
  const chips = [
    `<span class="chip ${esc(res.safety)}">${esc(res.safety)}</span>`,
    `<span class="chip">${CAT_ICON[res.category] || '•'} ${esc(res.category || '')}</span>`,
    (res.action === 'delete' || res.permanent) ? `<span class="chip review">permanent</span>` : '',
    blocked ? `<span class="chip review">can’t see inside</span>`
      : res.status === 'ok' ? `<span class="chip size">${fmtBytes(res.sizeBytes)} · ${res.fileCount} files</span>` : ''
  ].join('');
  const samples = (res.samples || []).map(s =>
    `<li><span>${esc(s.name)}</span><span>${fmtBytes(s.sizeBytes)}</span></li>`).join('');

  let control, dim = false;
  if (res.status === 'ok') {
    const checked = res.safety === 'safe';
    if (checked) selected.add(res.id);
    control = `<input type="checkbox" data-rule="${esc(res.id)}" ${checked ? 'checked' : ''}>`;
  } else if (res.status === 'command') {
    control = `<input type="checkbox" data-rule="${esc(res.id)}">`;
  } else {
    const icon = { skipped: '⏸️', unavailable: '🚫', disabled: '⛔', blocked: '🙈' }[res.status] || '•';
    control = `<span class="sticon" title="${esc(res.status)}">${icon}</span>`;
    dim = true;
  }

  return `
  <div class="card${dim ? ' dim' : ''}${blocked ? ' blocked' : ''}">
    <label class="row">
      ${control}
      <span><span class="t">${esc(res.title)}</span>
        <div class="chips">${chips}</div></span>
    </label>
    <p class="desc">${esc(res.description)}</p>
    ${res.status !== 'ok' ? `<p class="desc">— <b>${esc(res.status)}</b>${res.reason ? ': ' + esc(res.reason) : ''}</p>` : ''}
    ${samples ? `<ul class="samples">${samples}</ul>` : ''}
  </div>`;
}

function render() {
  const isForeign = r => r.status === 'unavailable' && (r.reason || '').includes('different OS/arch');
  const ok = report.rules.filter(r => r.status === 'ok' || r.status === 'command');
  const safe = ok.filter(r => r.safety === 'safe' && r.status === 'ok');
  const review = ok.filter(r => !(r.safety === 'safe' && r.status === 'ok'));
  const blocked = report.rules.filter(r => r.status === 'blocked');
  // Rules for another OS are config, not skips — keep them out of the UI.
  const others = report.rules.filter(r => r.status !== 'ok' && r.status !== 'command' && r.status !== 'blocked' && !isForeign(r));

  $('#stats').hidden = false;
  $('#stats').innerHTML = `
    <div class="stat"><div class="v">${fmtBytes(report.totalBytes)}</div><div class="k">Reclaimable · ${report.totalFiles} files</div></div>
    <div class="stat"><div class="v">${fmtBytes(report.safeBytes)}</div><div class="k">Safe (pre-selected)</div></div>
    <div class="stat amber"><div class="v">${fmtBytes(report.reviewBytes)}</div><div class="k">Review only</div></div>
    <div class="stat"><div class="v">${report.rules.filter(r => r.status === 'ok').length}</div><div class="k">Rules with buildup</div></div>`;

  let html = '';
  if (blocked.length) {
    // Not folded into "skipped": a blocked rule is invisible buildup, and
    // one of them (Empty the Trash) is permanent-delete — it must be loud.
    html += `<div class="banner warn" id="blockedBanner">
      🙈 ${blocked.length} rule${blocked.length > 1 ? 's' : ''} point${blocked.length > 1 ? '' : 's'} at folders this app can’t read — sizes unknown, cleaning refused until access is fixed.
      ${navigator.platform.includes('Mac') ? 'Grant the app that launches Descale <b>Full Disk Access</b> (System Settings › Privacy & Security), then rescan.' : 'Check folder permissions (or run elevated), then rescan.'}
    </div>`;
    html += `<h2>Blocked — access needed — ${blocked.length} rule${blocked.length > 1 ? 's' : ''}</h2><div class="grid">${blocked.map(cardHTML).join('')}</div>`;
  }
  const groupTools = g => `
    <button class="btn small ghost" data-grp="${g}" data-on="1">all</button>
    <button class="btn small ghost" data-grp="${g}" data-on="0">none</button>`;
  if (safe.length) {
    html += `<h2>Safe to descale — ${safe.length} rules &nbsp;${groupTools('safe')}</h2><div class="grid">${safe.map(cardHTML).join('')}</div>`;
  }
  if (review.length) {
    html += `<h2>Review before touching — ${review.length} rules &nbsp;${groupTools('review')}</h2><div class="grid">${review.map(cardHTML).join('')}</div>`;
  }
  if (others.length) {
    html += `<details class="group"><summary>Skipped / not applicable — ${others.length} rules</summary>
      <div class="grid">${others.map(cardHTML).join('')}</div></details>`;
  }
  $('#results').innerHTML = html;
  $('#results').hidden = false;

  document.querySelectorAll('input[data-rule]').forEach(cb =>
    cb.addEventListener('change', () => {
      const r = report.rules.find(x => x.id === cb.dataset.rule);
      if (cb.checked && r && (r.action === 'delete' || r.permanent)) {
        // Permanent rules run alone — checking one clears everything else.
        document.querySelectorAll('input[data-rule]').forEach(o => { if (o !== cb) o.checked = false; });
        selected.clear();
        selected.add(cb.dataset.rule);
        toast('"' + r.title + '" is permanent — it runs alone, nothing else is selected.', true);
      } else if (cb.checked) {
        for (const id of [...selected]) {
          const pr = report.rules.find(x => x.id === id);
          if (pr && (pr.action === 'delete' || pr.permanent)) {
            selected.delete(id);
            const el = document.querySelector('input[data-rule="' + id + '"]');
            if (el) el.checked = false;
            toast('Deselected "' + pr.title + '" — permanent rules run alone.', false);
          }
        }
        selected.add(cb.dataset.rule);
      } else {
        selected.delete(cb.dataset.rule);
      }
      updateBar();
    }));
  document.querySelectorAll('[data-grp]').forEach(b =>
    b.addEventListener('click', () => {
      const on = b.dataset.on === '1';
      report.rules.forEach(r => {
        if (r.status === 'ok' && r.safety === b.dataset.grp && !(r.action === 'delete' || r.permanent)) {
          const cb = document.querySelector('input[data-rule="' + r.id + '"]');
          if (cb) cb.checked = on;
          if (on) selected.add(r.id); else selected.delete(r.id);
        }
      });
      updateBar();
    }));
  updateBar();
}

function updateBar() {
  let bytes = 0, n = 0;
  for (const id of selected) {
    const r = report && report.rules.find(x => x.id === id);
    if (r && (r.status === 'ok' || r.status === 'command')) { bytes += r.sizeBytes; n++; }
  }
  $('#cleanbar').hidden = tab !== 'buildup' || n === 0;
  $('#cleanSummary').textContent = `${n} rule${n === 1 ? '' : 's'} selected · ${fmtBytes(bytes)}`;
}

function deselectAll() {
  selected.clear();
  document.querySelectorAll('input[data-rule]').forEach(cb => { cb.checked = false; });
  updateBar();
}

function openConfirm() {
  const ids = [...selected];
  if (!ids.length) return;
  api('/api/clean', { rules: ids, confirm: false })
    .then(plan => {
      $('#planList').innerHTML = plan.plan.map(p => `
        <div class="p"><span>${esc(p.title)}${(p.action === 'delete' || p.permanent) ? ' <b class="amber">(permanent)</b>' : ''}</span>
        <span>${fmtBytes(p.sizeBytes)} · ${p.fileCount} files</span></div>`).join('');
      const dlg = $('#confirmDialog');
      dlg.returnValue = '';
      dlg.showModal();
      $('#confirmClean').onclick = () => { dlg.close('yes'); doClean(ids); };
    })
    .catch(e => toast(e.message, true));
}

async function doClean(ids) {
  $('#cleanBtn').disabled = true;
  try {
    const res = await api('/api/clean', { rules: ids, confirm: true });
    const failed = (res.failed || []).length;
    let msg = `Cleaned ${res.files} files · ${fmtBytes(res.bytes)} → Trash`;
    if ((res.commands || []).length) msg += ' · command ran';
    if (failed) msg += ` · ${failed} failed`;
    toast(msg, failed > 0);
    scan();
  } catch (e) {
    toast('Clean failed: ' + e.message, true);
  } finally {
    $('#cleanBtn').disabled = false;
  }
}

async function loadJournalCount() {
  try {
    const j = await api('/api/journal');
    $('#journalCount').textContent = j.entries.length ? `(${j.entries.length})` : '(empty)';
    $('#journal').innerHTML = j.entries.slice().reverse().map(e => `
      <div class="entry">
        <div class="meta">
          <span>${esc(e.at.replace('T', ' ').replace('Z', ' UTC'))}</span>
          <span class="pill">${esc(e.action || 'clean')}${e.name ? ' · ' + esc(e.name) : ''}</span>
          <span>${e.restored ? '↩️ restored' : ''}</span>
          <span><b>${fmtBytes(e.bytes)}</b> · ${e.files} files</span>
          <span class="muted">${esc((e.rules || []).join(', '))}</span>
          ${!e.restored && e.items && e.items.length && (e.action || 'clean') === 'clean' ? `<button class="btn small ghost" data-restore="${esc(e.id)}">Restore</button>` : ''}
        </div>
      </div>`).join('');
    document.querySelectorAll('[data-restore]').forEach(b =>
      b.addEventListener('click', async () => {
        try {
          const r = await api('/api/restore', { id: b.dataset.restore });
          toast(`Restored ${r.restored} files (${r.skipped} skipped, ${r.failed} failed)`, r.failed > 0);
          loadJournalCount();
        } catch (e) { toast(e.message, true); }
      }));
  } catch (e) { /* journal is best-effort */ }
}

/* ---------- Uninstall tab ---------- */

let appsCache = null;

async function loadApps(force) {
  if (appsCache && !force) { renderApps(); return; }
  $('#appsMeta').textContent = 'listing installed applications…';
  try {
    const d = await api('/api/apps');
    if (d.note && (!d.apps || !d.apps.length)) {
      appsCache = [];
      $('#appsList').innerHTML = `<p class="muted note">${esc(d.note)}</p>`;
      $('#appsMeta').textContent = '';
      return;
    }
    appsCache = d.apps;
  } catch (e) { toast('Could not list applications: ' + e.message, true); }
  $('#appsMeta').textContent = appsCache ? `${appsCache.length} applications` : '';
  renderApps();
}

function appIcon(a, big) {
  return `<span class="appicon${big ? ' big' : ''}">
    <img src="/api/app/icon?path=${encodeURIComponent(a.path)}" alt="" loading="lazy"
         onerror="this.remove(); this.parentNode.textContent='📦'"></span>`;
}

function renderApps() {
  const q = ($('#appSearch').value || '').trim().toLowerCase();
  const list = (appsCache || []).filter(a =>
    !q || a.name.toLowerCase().includes(q) || (a.id || '').toLowerCase().includes(q));
  $('#appsList').innerHTML = list.map(a => `
    <button class="card app-card" data-app="${esc(a.path)}">
      ${appIcon(a)}
      <span class="grow"><span class="t">${esc(a.name)}</span>${a.running ? ' <span class="chip review">running</span>' : ''}
      <br><span class="muted small mono">${esc(a.id || 'no bundle id')}${a.version ? ' · v' + esc(a.version) : ''}</span></span>
    </button>`).join('') || '<p class="muted">No applications match.</p>';
  document.querySelectorAll('[data-app]').forEach(el =>
    el.addEventListener('click', () => openApp(el.dataset.app)));
}

async function openApp(path) {
  const a = (appsCache || []).find(x => x.path === path);
  $('#appDetail').hidden = false;
  $('#appDetail').innerHTML = '<p class="muted">Hunting leftovers…</p>';
  $('#appDetail').scrollIntoView({ behavior: 'smooth', block: 'start' });
  try {
    const d = await api('/api/app/leftovers', { path });
    renderAppDetail(d);
  } catch (e) {
    $('#appDetail').innerHTML = '';
    // registry apps on an older backend still get their uninstaller card
    if (a && a.kind === 'winapp') { renderWinDetail(a); return; }
    toast(e.message, true);
  }
}

function renderWinDetail(a) {
  $('#appDetail').hidden = false;
  $('#appDetail').innerHTML = `
    <div class="panel">
      <div class="detail-head">
        ${appIcon(a, true)}
        <h3>${esc(a.name)} ${a.version ? '<span class="muted">v' + esc(a.version) + '</span>' : ''}</h3>
        <button class="btn small ghost" id="detailBack" style="margin-left:auto">← All applications</button>
      </div>
      <p class="muted small">Registered uninstaller (from the registry):</p>
      <p class="mono">${esc(a.uninstallString || '(none)')}</p>
      <div class="dialog-actions">
        <button class="btn danger" id="winUninstall" ${a.uninstallString ? '' : 'disabled'}>Run uninstaller</button>
      </div>
      <p class="muted small">The app's own uninstaller opens in its own window. After it finishes, rescan for leftovers it may have left behind.</p>
    </div>`;
  $('#detailBack').addEventListener('click', () => { $('#appDetail').hidden = true; });
  $('#winUninstall').addEventListener('click', async () => {
    try {
      const res = await api('/api/app/uninstall', { path: a.path, confirm: true });
      toast('Uninstaller launched: ' + (res.app || a.name));
      loadJournalCount();
    } catch (e) { toast(e.message, true); }
  });
}

function renderAppDetail(d) {
  const rows = [{ path: d.app.path, kind: 'application', sizeBytes: d.bundleBytes }, ...d.leftovers]
    .map(l => `
    <label class="rowline">
      <input type="checkbox" checked data-leftover="${esc(l.path)}">
      <span class="mono grow">${esc(l.path)}</span>
      <span class="chip">${esc(l.kind)}</span>
      <span class="chip size">${fmtBytes(l.sizeBytes)}</span>
    </label>`).join('');
  const isWin = d.app.kind === 'winapp';
  const uninstallBtn = isWin
    ? `<button class="btn danger" id="winUninstall" ${d.app.uninstallString ? '' : 'disabled'}>Run uninstaller</button>`
    : `<button class="btn danger" id="uninstallBtn" ${d.app.running ? 'disabled' : ''}>
         ${d.app.running ? 'Quit the app first' : `🗑️ Uninstall ${esc(d.app.name)} (${fmtBytes(d.totalBytes)})`}
       </button>`;
  const delBtn = d.leftovers.length
    ? `<button class="btn" id="deleteLeftoversBtn" title="move the checked folders to the Trash — the application itself stays installed">
         🧹 Delete checked leftovers (${fmtBytes(d.leftoverBytes)})</button>`
    : '';
  $('#appDetail').innerHTML = `
    <div class="panel">
      <div class="detail-head">
        ${appIcon(d.app, true)}
        <h3>${esc(d.app.name)} ${d.app.version ? '<span class="muted">v' + esc(d.app.version) + '</span>' : ''}
          ${d.app.running ? '<span class="chip review">running</span>' : ''}</h3>
        <button class="btn small ghost" id="detailBack" style="margin-left:auto">← All applications</button>
      </div>
      <p class="muted small mono">${esc(d.app.id || (isWin ? 'registry entry' : 'no bundle id'))} — ${d.leftovers.length} leftover location(s) · total ${fmtBytes(d.totalBytes)}</p>
      <div id="leftoverList">${rows}</div>
      ${isWin ? `<p class="muted small">Registered uninstaller: <span class="mono">${esc(d.app.uninstallString || '(none)')}</span></p>` : ''}
      <div class="dialog-actions">
        ${uninstallBtn}
        ${delBtn}
      </div>
    </div>`;
  $('#detailBack').addEventListener('click', () => { $('#appDetail').hidden = true; });
  if (isWin) {
    const wu = $('#winUninstall');
    if (wu) wu.addEventListener('click', async () => {
      try {
        const res = await api('/api/app/uninstall', { path: d.app.path, confirm: true });
        toast(res.note || ('Uninstaller launched: ' + (res.app || d.app.name)));
        loadJournalCount();
      } catch (e) { toast(e.message, true); }
    });
  } else {
    $('#uninstallBtn').addEventListener('click', () => uninstallFlow(d));
  }
  const del = $('#deleteLeftoversBtn');
  if (del) del.addEventListener('click', () => deleteLeftoversFlow(d));
}

// delete checked leftover folders without uninstalling anything — the
// "the uninstaller already ran / the app was dragged away, its folders
// remain" case, on every OS
function deleteLeftoversFlow(d) {
  const checked = [...document.querySelectorAll('#leftoverList input:checked')]
    .map(cb => cb.dataset.leftover)
    .filter(p => p !== d.app.path);
  if (!checked.length) { toast('No leftover folders checked.', true); return; }
  const chosen = d.leftovers.filter(l => checked.includes(l.path));
  $('#udTitle').textContent = `Delete ${chosen.length} leftover location(s) of ${d.app.name}?`;
  $('#udList').innerHTML = chosen.map(l => `
    <div class="p"><span>${esc(l.path)}</span><span>${fmtBytes(l.sizeBytes)}</span></div>`).join('');
  const dlg = $('#uninstallDialog');
  dlg.returnValue = '';
  dlg.showModal();
  $('#udGo').onclick = async () => {
    dlg.close('yes');
    try {
      const res = await api('/api/app/leftovers/delete', { path: d.app.path, paths: checked });
      const failed = (res.failed || []).length;
      const skipped = (res.skipped || []).length;
      toast(`Deleted ${res.removed} location(s) · ${fmtBytes(res.bytes)} → Trash` +
        `${failed ? ' · ' + failed + ' failed' : ''}${skipped ? ' · ' + skipped + ' skipped' : ''}`,
        failed > 0);
      loadJournalCount();
      openApp(d.app.path);
    } catch (e) { toast('Delete failed: ' + e.message, true); }
  };
}

function uninstallFlow(d) {
  const checked = [...document.querySelectorAll('#leftoverList input:checked')].map(cb => cb.dataset.leftover);
  if (!checked.length) { toast('Nothing selected.', true); return; }
  $('#udTitle').textContent = `Uninstall ${d.app.name}?`;
  $('#udList').innerHTML = `
    <div class="p"><span>${esc(d.app.path)}</span><span>${fmtBytes(d.bundleBytes)}</span></div>
    ${d.leftovers.filter(l => checked.includes(l.path)).map(l => `
      <div class="p"><span>${esc(l.path)}</span><span>${fmtBytes(l.sizeBytes)}</span></div>`).join('')}`;
  const dlg = $('#uninstallDialog');
  dlg.returnValue = '';
  dlg.showModal();
  $('#udGo').onclick = async () => {
    dlg.close('yes');
    try {
      const res = await api('/api/app/uninstall', { path: d.app.path, confirm: true });
      const failed = (res.failed || []).length;
      toast(`Uninstalled ${res.app}: ${res.files} items · ${fmtBytes(res.bytes)} → Trash${failed ? ' · ' + failed + ' failed' : ''}`, failed > 0);
      appsCache = null;
      $('#appDetail').hidden = true;
      loadApps(true);
      loadJournalCount();
    } catch (e) { toast('Uninstall failed: ' + e.message, true); }
  };
}

/* ---------- Traces tab ---------- */

let tracesCache = null;

async function loadTraces() {
  $('#tracesMeta').textContent = 'scanning…';
  try {
    const d = await api('/api/traces');
    tracesCache = d;
    renderTraces(d);
  } catch (e) {
    $('#tracesMeta').textContent = '';
    toast('Trace scan failed: ' + e.message, true);
  }
}

function renderTraces(d) {
  $('#tracesNote').textContent = d.note || $('#tracesNote').textContent;
  $('#tracesMeta').textContent = d.traces.length
    ? `${d.traces.length} trace(s) · ${fmtBytes(d.bytes)} total`
    : 'no traces — every leftover location belongs to an installed app';
  const tb = $('#tbl-traces').tBodies[0];
  tb.innerHTML = d.traces.map((t) => `
    <tr>
      <td><input type="checkbox" class="trace-check" data-trace="${esc(t.path)}" data-size="${t.sizeBytes}"></td>
      <td class="mono">${esc(t.path)}</td>
      <td><span class="chip">${esc(t.kind)}</span></td>
      <td><span class="chip size">${fmtBytes(t.sizeBytes)}</span></td>
    </tr>`).join('') ||
    '<tr><td colspan="4" class="muted">nothing to clean</td></tr>';
  $('#tracesDelete').disabled = true;
  document.querySelectorAll('.trace-check').forEach(cb =>
    cb.addEventListener('change', updateTracesSelection));
}

function updateTracesSelection() {
  const checked = [...document.querySelectorAll('.trace-check:checked')];
  $('#tracesDelete').disabled = !checked.length;
  $('#tracesAll').checked = checked.length > 0 &&
    checked.length === document.querySelectorAll('.trace-check').length;
  const bytes = checked.reduce((n, cb) => n + (parseInt(cb.dataset.size, 10) || 0), 0);
  $('#tracesMeta').textContent = checked.length
    ? `${checked.length} selected · ${fmtBytes(bytes)}`
    : `${tracesCache ? tracesCache.traces.length : 0} trace(s) · ${fmtBytes(tracesCache ? tracesCache.bytes : 0)} total`;
}

$('#tracesAll').addEventListener('change', (e) => {
  document.querySelectorAll('.trace-check').forEach(cb => { cb.checked = e.target.checked; });
  updateTracesSelection();
});

$('#tracesReload').addEventListener('click', loadTraces);

$('#tracesDelete').addEventListener('click', () => {
  const checked = [...document.querySelectorAll('.trace-check:checked')]
    .map(cb => cb.dataset.trace);
  if (!checked.length) return;
  const chosen = (tracesCache.traces || []).filter(t => checked.includes(t.path));
  $('#udTitle').textContent = `Delete ${checked.length} trace(s)?`;
  $('#udList').innerHTML = chosen.map(t => `
    <div class="p"><span>${esc(t.path)}</span><span>${fmtBytes(t.sizeBytes)}</span></div>`).join('');
  const dlg = $('#uninstallDialog');
  dlg.returnValue = '';
  dlg.showModal();
  $('#udGo').onclick = async () => {
    dlg.close('yes');
    try {
      const res = await api('/api/traces/delete', { paths: checked });
      const failures = res.failed || [];
      const failed = failures.length;
      const skipped = (res.skipped || []).length;
      const failureDetails = failures.map(f => `${f.path}: ${f.error}`).join(' · ');
      toast(`Deleted ${res.removed} trace(s) · ${fmtBytes(res.bytes)} → Trash` +
        `${failed ? ' · ' + failed + ' failed: ' + failureDetails : ''}${skipped ? ' · ' + skipped + ' skipped' : ''}`,
        failed > 0);
      loadJournalCount();
      loadTraces();
    } catch (e) { toast('Delete failed: ' + e.message, true); }
  };
});

/* ---------- Startup tab ---------- */

async function loadStartup() {
  try {
    const d = await api('/api/startup');
    const user = d.items.filter(i => i.scope === 'user');
    const sys = d.items.filter(i => i.scope !== 'user');
    const row = i => `
      <div class="rowline card-row">
        <span class="grow"><b>${esc(i.label)}</b>
          ${i.active ? '<span class="chip safe">enabled at startup</span>' : '<span class="chip review">disabled at startup</span>'}
          ${i.runAtLoad ? '<span class="chip">RunAtLoad</span>' : ''}
          ${i.keepAlive ? '<span class="chip">KeepAlive</span>' : ''}
          <span class="muted small mono">${esc(i.program || '')}</span></span>
        ${i.scope === 'user'
          ? `<button class="btn small ${i.active ? 'ghost' : 'primary'}" data-toggle="${esc(i.path)}" data-activate="${i.active ? '0' : '1'}">${i.active ? 'Deactivate' : 'Activate'}</button>`
          : '<span class="chip">read-only</span>'}
      </div>`;
    $('#uaList').innerHTML = user.map(row).join('') || '<p class="muted">No user launch agents.</p>';
    $('#saList').innerHTML = sys.map(row).join('') || '<p class="muted">None found.</p>';
    document.querySelectorAll('[data-toggle]').forEach(b =>
      b.addEventListener('click', async () => {
        try {
          const r = await api('/api/startup/toggle', { path: b.dataset.toggle, activate: b.dataset.activate === '1' });
          toast(r.active ? 'Activated.' : 'Deactivated. ' + (r.output || ''));
        } catch (e) { toast(e.message, true); }
        loadStartup();
      }));
    // Weekly reminder (macOS only)
    try {
      const n = await api('/api/nudge');
      $('#nudgeRow').hidden = !n.supported;
      const btn = $('#nudgeBtn');
      btn.textContent = n.installed ? 'Remove' : 'Install';
      btn.onclick = async () => {
        try {
          await api('/api/nudge', { install: !n.installed });
          toast(n.installed ? 'Weekly reminder removed.' : 'Weekly reminder installed — Mondays at 10:00.');
          loadStartup();
        } catch (e) { toast(e.message, true); }
      };
    } catch (e) { $('#nudgeRow').hidden = true; }
  } catch (e) { toast('Could not list startup items: ' + e.message, true); }
}

/* ---------- trust dialog ---------- */

function initTrust() {
  $('#trustBtn').addEventListener('click', () => $('#trustDialog').showModal());
  $('#trustClose').addEventListener('click', () => $('#trustDialog').close());
}

/* ---------- boot ---------- */

$('#scanBtn').addEventListener('click', scan);
$('#cleanBtn').addEventListener('click', openConfirm);
$('#deselectAll').addEventListener('click', deselectAll);
$('#cancelClean').addEventListener('click', () => $('#confirmDialog').close());
$('#confirmDialog').addEventListener('cancel', e => e.target.close());
$('#udCancel').addEventListener('click', () => $('#uninstallDialog').close());
$('#appSearch').addEventListener('input', renderApps);
$('#appsReload').addEventListener('click', () => { appsCache = null; loadApps(true); });
$('#trustBtn').addEventListener('click', () => $('#trustDialog').showModal());
$('#trustClose').addEventListener('click', () => $('#trustDialog').close());

init();

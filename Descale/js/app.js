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
  if (!r.ok) {
    const err = new Error(data.error || ('HTTP ' + r.status));
    err.payload = data; // error payloads can carry the operation's step log
    throw err;
  }
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

/* ---------- guardrails ---------- */

let guardrails = true;

function renderGuardBtn() {
  const b = $('#guardBtn');
  b.textContent = guardrails ? '🛡️ Guardrails' : '⚠️ Guardrails off';
  b.classList.toggle('off', !guardrails);
  b.title = guardrails
    ? 'Guardrails are on: system and shared locations (Library roots, Containers, standard user folders) are never proposed or deleted. Click to turn off for expert use.'
    : 'Expert mode: protected locations are NOT blocked. Only proceed if you know exactly what you are deleting. Click to turn guardrails back on.';
}

$('#guardBtn').addEventListener('click', async () => {
  const target = !guardrails;
  if (!target && !confirm('Turn off guardrails?\n\n' +
    'Descale will no longer block protected system locations (Library roots, Containers, standard user folders) in scans and deletions.\n\n' +
    'Only do this if you know exactly what you are deleting. The home folder itself and its parents stay protected either way.')) return;
  try {
    const r = await api('/api/guardrails', { enabled: target });
    guardrails = r.guardrails;
    renderGuardBtn();
    toast(guardrails
      ? 'Guardrails on — protected locations are blocked again.'
      : 'Guardrails off — expert mode. Protected locations are no longer blocked.', !guardrails);
  } catch (e) { toast(e.message, true); }
});

// one-line warning injected into every delete dialog while expert mode is on
function expertNote() {
  return guardrails ? '' :
    '<div class="p"><span class="amber">⚠️ Expert mode — guardrails are off; protected locations are not blocked.</span></div>';
}

/* ---------- onboarding ---------- */

function initOnboarding(info) {
  // The dismissed flag lives server-side too: embedded webviews may not
  // keep localStorage between launches, which made the banner reappear.
  let seen = false;
  try { seen = !!localStorage.getItem('descale.onboarded'); } catch (e) {}
  if (info && info.onboarded) seen = true;
  if (seen) return;
  $('#onboard').hidden = false;
  $('#onboardOk').addEventListener('click', () => {
    $('#onboard').hidden = true;
    try { localStorage.setItem('descale.onboarded', '1'); } catch (e) {}
    api('/api/onboarded', {}).catch(() => {}); // best-effort; banner stays hidden this session regardless
  });
}

/* ---------- tabs ---------- */

function showTab(t) {
  if (t === 'exclusions') { // the old top-level tab became a Traces sub-tab
    t = 'traces';
    localStorage.setItem('descale.tracesPane', 'exclusions');
  }
  if (!['buildup', 'uninstall', 'traces', 'startup'].includes(t)) t = 'buildup';
  tab = t;
  localStorage.setItem('descale.tab', t);
  document.querySelectorAll('.tabs button').forEach(b => b.classList.toggle('on', b.dataset.tab === t));
  for (const name of ['buildup', 'uninstall', 'traces', 'startup']) {
    document.getElementById('tab-' + name).hidden = name !== t;
  }
  $('#cleanbar').hidden = t !== 'buildup' || selected.size === 0;
  if (t === 'uninstall') loadApps();
  if (t === 'traces') showTracePane(localStorage.getItem('descale.tracesPane') || 'cleanup');
  if (t === 'startup') loadStartup();
}

document.querySelectorAll('.tabs button').forEach(b =>
  b.addEventListener('click', () => showTab(b.dataset.tab)));

/* sub-tabs inside Traces: Cleanup (the scan) and Exclusions */

function showTracePane(pane) {
  if (pane !== 'exclusions') pane = 'cleanup'; // self-heal stale/garbage stored values
  localStorage.setItem('descale.tracesPane', pane);
  document.querySelectorAll('.subtabs button').forEach(b => b.classList.toggle('on', b.dataset.pane === pane));
  $('#pane-traces-cleanup').hidden = pane !== 'cleanup';
  $('#pane-traces-exclusions').hidden = pane !== 'exclusions';
  if (pane === 'cleanup') loadTraces();
  else loadExclusions();
}

document.querySelectorAll('.subtabs button').forEach(b =>
  b.addEventListener('click', () => showTracePane(b.dataset.pane)));

// 📂 — show a trace/exclusion folder in the system file manager
async function revealPath(path) {
  try {
    await api('/api/reveal', { path });
  } catch (e) { toast('Could not open the folder: ' + e.message, true); }
}

/* ---------- Buildup: scanning (background job + polling) ---------- */

async function init() {
  let info = null;
  try {
    info = await api('/api/info');
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
    guardrails = info.guardrails !== false; // older servers have no toggle: protected
    renderGuardBtn();
  } catch (e) { showError('Could not reach the Descale server: ' + e.message); }
  initOnboarding(info);
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
    `<li><span title="${esc(s.name)}">${esc(s.name)}</span><span>${fmtBytes(s.sizeBytes)}</span></li>`).join('');

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
  const box = logOpen('Cleaning…');
  try {
    const res = await api('/api/clean', { rules: ids, confirm: true });
    logRender(box, res.log);
    const failed = (res.failed || []).length;
    let msg = `Cleaned ${res.files} files · ${fmtBytes(res.bytes)} → Trash`;
    if (res.husks) msg += ` · ${res.husks} empty folder${res.husks === 1 ? '' : 's'} removed`;
    if ((res.commands || []).length) msg += ' · command ran';
    if (failed) msg += ` · ${failed} failed`;
    if (res.logPath) msg += `\nlog: ${res.logPath}`;
    logDone(failed ? 'Clean finished (with failures)' : 'Clean finished', box, msg.replace(/\n/, ' · '));
    toast(msg, failed > 0);
    scan();
  } catch (e) {
    if (e.payload && e.payload.log) logRender(box, e.payload.log);
    logDone('Clean failed', box, e.message);
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
          ${!e.restored && e.items && e.items.length ? `<button class="btn small ghost" data-restore="${esc(e.id)}">Restore</button>` : ''}
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
// The Uninstall tab splits by install scope: "system" (/Applications,
// ~/Applications) and "appdeck" (AppDeck-managed apps). The choice persists.
let uninstallScope = localStorage.getItem('descale.uninstallScope') === 'appdeck'
  ? 'appdeck' : 'system';

function setUninstallScope(scope) {
  uninstallScope = scope;
  localStorage.setItem('descale.uninstallScope', scope);
  document.querySelectorAll('#uninstallSubtabs button').forEach(b =>
    b.classList.toggle('on', b.dataset.scope === scope));
  $('#appDetail').hidden = true; // the open detail card may belong to the other scope
  appSelected.clear();           // selections never span scopes
  renderApps();
}

// Batch selection: a Set of app paths (never spans scopes; AppDeck apps
// selected here are skipped by the batch endpoint with a pointer back to
// the launcher, since those uninstalls are permanent).
const appSelected = new Set();

function updateAppsBar() {
  const bar = $('#appsBar');
  const n = appSelected.size;
  bar.hidden = n === 0;
  $('#appsBarText').textContent = n === 1 ? '1 application selected' : `${n} applications selected`;
  $('#appsUninstall').disabled = n === 0;
}

document.querySelectorAll('#uninstallSubtabs button').forEach(b =>
  b.addEventListener('click', () => setUninstallScope(b.dataset.scope)));

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
  document.querySelectorAll('#uninstallSubtabs button').forEach(b =>
    b.classList.toggle('on', b.dataset.scope === uninstallScope));
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
    (a.scope || 'system') === uninstallScope &&
    (!q || a.name.toLowerCase().includes(q) || (a.id || '').toLowerCase().includes(q)));
  const inScope = (appsCache || []).filter(a => (a.scope || 'system') === uninstallScope).length;
  $('#appsMeta').textContent = appsCache
    ? `${list.length} of ${inScope} application${inScope === 1 ? '' : 's'}${q ? ` matching “${q}”` : ''}`
    : '';
  $('#appsList').innerHTML = list.map(a => `
    <div class="card app-card${appSelected.has(a.path) ? ' selected' : ''}" role="button" tabindex="0" data-app="${esc(a.path)}">
      <input type="checkbox" class="app-check" data-app="${esc(a.path)}" ${appSelected.has(a.path) ? 'checked' : ''}
             aria-label="Select ${esc(a.name)} for batch uninstall">
      ${appIcon(a)}
      <span class="grow"><span class="t">${esc(a.name)}</span>${a.running ? ' <span class="chip review">running</span>' : ''}
      ${a.source === 'registry' ? ' <span class="chip review" title="Registered in AppDeck\'s apps.json — AppDeck refuses to uninstall it; remove its entry there first">registry</span>' : ''}
      <br><span class="muted small mono">${esc(a.id || 'no bundle id')}${a.version ? ' · v' + esc(a.version) : ''}</span></span>
    </div>`).join('') ||
    `<p class="muted">No ${uninstallScope === 'appdeck' ? 'AppDeck ' : ''}applications match.</p>`;
  document.querySelectorAll('#appsList .app-card').forEach(el => {
    el.addEventListener('click', (e) => {
      if (e.target.closest('.app-check')) return; // the checkbox selects, never opens
      openApp(el.dataset.app);
    });
    el.addEventListener('keydown', (e) => {
      if ((e.key === 'Enter' || e.key === ' ') && !e.target.closest('.app-check')) {
        e.preventDefault();
        openApp(el.dataset.app);
      }
    });
  });
  document.querySelectorAll('#appsList .app-check').forEach(cb =>
    cb.addEventListener('change', () => {
      if (cb.checked) appSelected.add(cb.dataset.app);
      else appSelected.delete(cb.dataset.app);
      cb.closest('.app-card').classList.toggle('selected', cb.checked);
      const all = document.querySelectorAll('#appsList .app-check');
      $('#appsAll').checked = all.length > 0 && [...all].every(c => c.checked);
      updateAppsBar();
    }));
  $('#appsAll').checked = list.length > 0 && list.every(a => appSelected.has(a.path));
  updateAppsBar();
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
  if (!Array.isArray(d.leftovers)) d.leftovers = []; // older servers send null when an app has none
  const bundlePath = d.bundlePath || d.app.path; // AppDeck apps: the launcher-managed folder, not the .app inside it
  const rows = [{ path: bundlePath, kind: 'application', sizeBytes: d.bundleBytes }, ...d.leftovers]
    .map(l => `
    <label class="rowline">
      <input type="checkbox" checked data-leftover="${esc(l.path)}">
      <span class="mono grow" title="${esc(l.path)}">${esc(l.path)}</span>
      <span class="chip">${esc(l.kind)}</span>
      <span class="chip size">${fmtBytes(l.sizeBytes)}</span>
    </label>`).join('');
  const isWin = d.app.kind === 'winapp';
  // AppDeck uninstalls delegate to the launcher, which stops a running app
  // itself — only native apps must be quit first.
  const mustQuit = d.app.running && d.app.scope !== 'appdeck';
  const uninstallBtn = isWin
    ? `<button class="btn danger" id="winUninstall" ${d.app.uninstallString ? '' : 'disabled'}>Run uninstaller</button>`
    : `<button class="btn danger" id="uninstallBtn" ${mustQuit ? 'disabled' : ''}>
         ${mustQuit ? 'Quit the app first' : `🗑️ Uninstall ${esc(d.app.name)} (${fmtBytes(d.totalBytes)})`}
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
      ${d.app.scope === 'appdeck' ? `<p class="muted small">AppDeck app: uninstalling runs AppDeck's own uninstall (it stops the app and removes the app folder permanently); the checked leftovers above still move to the Trash.${d.app.source === 'registry' ? ' <b class="amber">This one is registered in AppDeck\'s apps.json — AppDeck will refuse until its entry is removed there.</b>' : ''}</p>` : ''}
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
    .filter(p => p !== (d.bundlePath || d.app.path));
  if (!checked.length) { toast('No leftover folders checked.', true); return; }
  const chosen = d.leftovers.filter(l => checked.includes(l.path));
  $('#udTitle').textContent = `Delete ${chosen.length} leftover location(s) of ${d.app.name}?`;
  $('#udList').innerHTML = chosen.map(l => `
    <div class="p"><span>${esc(l.path)}</span><span>${fmtBytes(l.sizeBytes)}</span></div>`).join('') + expertNote();
  const dlg = $('#uninstallDialog');
  dlg.returnValue = '';
  dlg.showModal();
  $('#udGo').onclick = async () => {
    dlg.close('yes');
    const box = logOpen(`Deleting leftovers of ${d.app.name}…`);
    try {
      const res = await api('/api/app/leftovers/delete', { path: d.app.path, paths: checked });
      logRender(box, res.log);
      const failed = (res.failed || []).length;
      const skipped = (res.skipped || []).length;
      let summary = `${res.removed} location(s) · ${fmtBytes(res.bytes)} → Trash` +
        `${failed ? ' · ' + failed + ' failed' : ''}${skipped ? ' · ' + skipped + ' skipped' : ''}`;
      if (res.logPath) summary += ` · log: ${res.logPath}`;
      logDone('Leftovers deleted', box, summary);
      toast(`Deleted ${summary}`, failed > 0);
      loadJournalCount();
      openApp(d.app.path);
    } catch (e) {
      if (e.payload && e.payload.log) logRender(box, e.payload.log);
      logDone('Delete failed', box, e.message);
      toast('Delete failed: ' + e.message, true);
    }
  };
}

// operation log modal — shows the timestamped step trail the backend now
// returns for uninstall / leftover deletion, styled like the deck's import log
function logOpen(title) {
  $('#logTitle').textContent = title;
  const box = $('#logLines');
  box.innerHTML = '<div class="log-line"><span class="log-msg">working…</span></div>';
  $('#logClose').disabled = true;
  $('#logDialog').showModal();
  return box;
}
function logRender(box, steps) {
  box.innerHTML = (steps || []).map(s => {
    // Success lines end in ", 0 failed"/"0 skipped" — a bare word match turned
    // every one of them red. Real problems carry uppercase FAILED/REFUSED/
    // SKIPPED markers, or a non-zero count before the word.
    const bad = /\b(FAILED|REFUSED|SKIPPED)\b/.test(s.msg) ||
      /\b[1-9]\d* (failed|skipped)\b/i.test(s.msg);
    const ok = /^ok\b/.test(s.msg);
    return `<div class="log-line${bad ? ' is-bad' : ok ? ' is-ok' : ''}">` +
      `<span class="log-time">${esc(s.at)}</span><span class="log-msg">${esc(s.msg)}</span></div>`;
  }).join('') || '<div class="log-line"><span class="log-msg">(no step log — older server)</span></div>';
  box.scrollTop = box.scrollHeight;
}
function logDone(title, box, summary) {
  $('#logTitle').textContent = title;
  if (summary) {
    box.insertAdjacentHTML('beforeend', `<div class="log-line log-summary"><span class="log-msg">${esc(summary)}</span></div>`);
    box.scrollTop = box.scrollHeight;
  }
  $('#logClose').disabled = false;
}
function failuresToLine(failed) {
  const f = failed || [];
  if (!f.length) return '';
  const first = f[0].error ? ` — ${f[0].path}: ${f[0].error}` : '';
  return `${f.length} failed${first}`;
}

function uninstallFlow(d) {
  const checked = [...document.querySelectorAll('#leftoverList input:checked')].map(cb => cb.dataset.leftover);
  if (!checked.length) { toast('Nothing selected.', true); return; }
  $('#udTitle').textContent = `Uninstall ${d.app.name}?`;
  $('#udList').innerHTML = `
    <div class="p"><span>${esc(d.bundlePath || d.app.path)}</span><span>${fmtBytes(d.bundleBytes)}</span></div>
    ${d.leftovers.filter(l => checked.includes(l.path)).map(l => `
      <div class="p"><span>${esc(l.path)}</span><span>${fmtBytes(l.sizeBytes)}</span></div>`).join('')}
    ${expertNote()}`;
  const dlg = $('#uninstallDialog');
  dlg.returnValue = '';
  dlg.showModal();
  $('#udGo').onclick = async () => {
    dlg.close('yes');
    const box = logOpen(`Uninstalling ${d.app.name}…`);
    try {
      const res = await api('/api/app/uninstall', { path: d.app.path, confirm: true });
      logRender(box, res.log);
      const failed = (res.failed || []).length;
      let summary = `${res.files} items · ${fmtBytes(res.bytes)} → Trash${failed ? ' · ' + failuresToLine(res.failed) : ''}`;
      if (res.logPath) summary += ` · log: ${res.logPath}`;
      logDone(`Uninstalled ${res.app}`, box, summary);
      toast(`Uninstalled ${res.app}: ${summary}`, failed > 0);
      appsCache = null;
      $('#appDetail').hidden = true;
      loadApps(true);
      loadJournalCount();
    } catch (e) {
      if (e.payload && e.payload.log) logRender(box, e.payload.log);
      logDone('Uninstall failed', box, e.message);
      toast('Uninstall failed: ' + e.message, true);
    }
  };
}

/* ---------- batch uninstall ---------- */

// One confirmed dialog, one POST, per-app results streamed into the log.
// AppDeck apps are skipped server-side with a pointer back to the launcher
// (their uninstall is permanent — never bundled into a Trash-restorable
// batch), and running apps are skipped with a quit-it-first note.
function uninstallBatchFlow() {
  const sel = [...appSelected]
    .map(p => (appsCache || []).find(a => a.path === p))
    .filter(Boolean);
  if (!sel.length) { toast('Nothing selected.', true); return; }
  $('#udTitle').textContent = `Uninstall ${sel.length} application${sel.length === 1 ? '' : 's'}?`;
  $('#udList').innerHTML =
    sel.map(a => `
      <div class="p"><span>${esc(a.name)}</span><span class="muted">${esc(a.id || '')}${a.running ? ' · running (will be skipped)' : ''}</span></div>`).join('') +
    `<div class="p muted small">Each app moves to the Trash with its leftovers — one restorable
      journal entry per app. AppDeck apps are skipped: uninstall those from the launcher
      (permanent there).</div>
     ${expertNote()}`;
  const dlg = $('#uninstallDialog');
  dlg.returnValue = '';
  dlg.showModal();
  $('#udGo').onclick = async () => {
    dlg.close('yes');
    const box = logOpen(`Uninstalling ${sel.length} applications…`);
    try {
      const res = await api('/api/apps/uninstall', { paths: sel.map(a => a.path) });
      logRender(box, res.log);
      const skipped = (res.skipped || []).length;
      let summary = `${res.uninstalled} app${res.uninstalled === 1 ? '' : 's'} · ${fmtBytes(res.bytes)} → Trash` +
        (skipped ? ` · ${skipped} skipped` : '');
      if (res.logPath) summary += ` · log: ${res.logPath}`;
      logDone('Batch uninstall finished', box, summary);
      toast(`Uninstalled ${res.uninstalled} app${res.uninstalled === 1 ? '' : 's'}: ${summary}`, res.uninstalled === 0);
      appSelected.clear();
      appsCache = null;
      $('#appDetail').hidden = true;
      loadApps(true);
      loadJournalCount();
    } catch (e) {
      if (e.payload && e.payload.log) logRender(box, e.payload.log);
      logDone('Batch uninstall failed', box, e.message);
      toast('Batch uninstall failed: ' + e.message, true);
    }
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
  if (!Array.isArray(d.traces)) d.traces = []; // older servers send null when nothing is found
  $('#tracesNote').textContent = d.note || $('#tracesNote').textContent;
  $('#tracesMeta').textContent = d.traces.length
    ? `${d.traces.length} trace(s) · ${fmtBytes(d.bytes)} total`
    : 'no traces — every leftover location belongs to an installed app';
  $('#tracesSearch').hidden = d.traces.length === 0;
  $('#tracesKind').hidden = d.traces.length === 0;
  // A rescan (or a scan finishing while the user was already working)
  // rebuilds the table — preserve their checked paths and filter state.
  const prevChecked = new Set(
    [...document.querySelectorAll('.trace-check:checked')].map(cb => cb.dataset.trace));
  const prevSearch = $('#tracesSearch').value;
  const prevKind = $('#tracesKind').value;
  const kinds = [...new Set(d.traces.map(t => t.kind))].sort();
  $('#tracesKind').innerHTML = '<option value="">All kinds</option>' +
    kinds.map(k => `<option value="${esc(k)}">${esc(k)}</option>`).join('');
  const tb = $('#tbl-traces').tBodies[0];
  tb.innerHTML = d.traces.map((t) => `
    <tr class="trace-row" data-search="${esc(t.path.toLowerCase())}" data-kind="${esc(t.kind)}">
      <td><input type="checkbox" class="trace-check" data-trace="${esc(t.path)}" data-size="${t.sizeBytes}"></td>
      <td class="mono" title="${esc(t.path)}">${esc(t.path)}</td>
      <td title="${esc(t.kind)}"><span class="chip">${esc(t.kind)}</span></td>
      <td><span class="chip size">${fmtBytes(t.sizeBytes)}</span></td>
      <td class="actions">
        <button class="btn small ghost icon" data-reveal="${esc(t.path)}" title="Show this folder in your file manager">📂</button>
        <button class="btn small ghost icon" data-exclude="${esc(t.path)}" title="Never scan or delete this folder">🚫</button>
      </td>
    </tr>`).join('') ||
    '<tr><td colspan="5" class="muted">nothing to clean</td></tr>';
  document.querySelectorAll('.trace-check').forEach(cb => {
    cb.checked = prevChecked.has(cb.dataset.trace);
    cb.addEventListener('change', updateTracesSelection);
  });
  tb.querySelectorAll('[data-exclude]').forEach(b =>
    b.addEventListener('click', () => excludeTrace(b.dataset.exclude)));
  tb.querySelectorAll('[data-reveal]').forEach(b =>
    b.addEventListener('click', () => revealPath(b.dataset.reveal)));
  $('#tracesSearch').value = prevSearch;
  $('#tracesKind').value = prevKind;
  applyTraceFilters();
  updateTracesSelection();
}

/* ---------- trace exclusions (never scan / never delete) ---------- */

// The Exclusions tab: everything currently on the never-scan list, each
// row with a one-click restore back into the scannable world.
async function loadExclusions() {
  const tb = $('#tbl-exclusions').tBodies[0];
  try {
    const d = await api('/api/traces/exclusions');
    // {"exclusions": ["<path>", …]} in entered spelling
    const list = Array.isArray(d.exclusions) ? d.exclusions : Object.keys(d.exclusions || {});
    list.sort();
    $('#exclMeta').textContent = list.length
      ? `${list.length} folder(s) excluded`
      : 'nothing excluded — every leftover location is scanned';
    $('#exclAll').hidden = list.length === 0;
    $('#exclRestore').hidden = list.length === 0;
    tb.innerHTML = list.map(p => `
      <tr class="excl-row">
        <td><input type="checkbox" class="excl-check" data-excl="${esc(p)}"></td>
        <td class="mono" title="${esc(p)}">${esc(p)}</td>
        <td class="actions">
          <button class="btn small ghost icon" data-reveal="${esc(p)}" title="Show this folder in your file manager">📂</button>
          <button class="btn small ghost icon" data-unexclude="${esc(p)}" title="Restore to the scan — this folder becomes visible to Cleanup again">↩️</button>
        </td>
      </tr>`).join('') ||
      '<tr><td colspan="3" class="muted">no exclusions — use the 🚫 button next to a trace, or check traces and choose “Exclude selected”</td></tr>';
    $('#exclAll').checked = false;
    $('#exclRestore').disabled = true;
    tb.querySelectorAll('.excl-check').forEach(cb =>
      cb.addEventListener('change', updateExclSelection));
    tb.querySelectorAll('[data-reveal]').forEach(b =>
      b.addEventListener('click', () => revealPath(b.dataset.reveal)));
    tb.querySelectorAll('[data-unexclude]').forEach(b =>
      b.addEventListener('click', async () => {
        try {
          await api('/api/traces/exclusions/remove', { path: b.dataset.unexclude });
          toast('Restored to scan: ' + b.dataset.unexclude);
          loadExclusions();
        } catch (err) { toast(err.message, true); }
      }));
  } catch (e) {
    $('#exclMeta').textContent = '';
    toast('Could not load the exclusion list: ' + e.message, true);
  }
}

function updateExclSelection() {
  const checked = [...document.querySelectorAll('.excl-check:checked')];
  $('#exclRestore').disabled = !checked.length;
  $('#exclAll').checked = checked.length > 0 &&
    checked.length === document.querySelectorAll('.excl-check').length;
}

// Batch restore: remove every checked exclusion in one pass, then reload.
$('#exclRestore').addEventListener('click', async () => {
  const checked = [...document.querySelectorAll('.excl-check:checked')]
    .map(cb => cb.dataset.excl);
  if (!checked.length) return;
  let ok = 0, failed = 0;
  for (const p of checked) {
    try {
      await api('/api/traces/exclusions/remove', { path: p });
      ok++;
    } catch (e) { failed++; }
  }
  toast(`Restored ${ok} folder(s) to the scan${failed ? ` · ${failed} failed` : ''}.`, failed > 0);
  loadExclusions();
});

$('#exclAll').addEventListener('change', e => {
  document.querySelectorAll('.excl-check').forEach(cb => { cb.checked = e.target.checked; });
  updateExclSelection();
});

$('#exclReload').addEventListener('click', loadExclusions);

async function excludeTrace(path) {
  try {
    await api('/api/traces/exclusions/add', { path });
    toast('Excluded from future scans: ' + path);
    loadTraces();
  } catch (e) { toast(e.message, true); }
}

// The live path search and the kind filter share one pass; hidden rows keep
// any checked state so clearing a filter restores exactly what was selected.
function applyTraceFilters() {
  const q = $('#tracesSearch').value.trim().toLowerCase();
  const kind = $('#tracesKind').value;
  let visible = 0;
  document.querySelectorAll('.trace-row').forEach(tr => {
    const hit = (!q || tr.dataset.search.includes(q)) && (!kind || tr.dataset.kind === kind);
    tr.style.display = hit ? '' : 'none';
    if (hit) visible++;
  });
  const total = document.querySelectorAll('.trace-row').length;
  if (!tracesCache) return;
  $('#tracesMeta').textContent = (q || kind)
    ? `${visible} of ${total} shown`
    : `${total} trace(s) · ${fmtBytes(tracesCache.bytes)} total`;
}

$('#tracesSearch').addEventListener('input', applyTraceFilters);
$('#tracesKind').addEventListener('change', applyTraceFilters);

function updateTracesSelection() {
  const checked = [...document.querySelectorAll('.trace-check:checked')];
  $('#tracesDelete').disabled = !checked.length;
  $('#tracesExclude').disabled = !checked.length;
  $('#tracesAll').checked = checked.length > 0 &&
    checked.length === document.querySelectorAll('.trace-check').length;
  const bytes = checked.reduce((n, cb) => n + (parseInt(cb.dataset.size, 10) || 0), 0);
  $('#tracesMeta').textContent = checked.length
    ? `${checked.length} selected · ${fmtBytes(bytes)}`
    : `${tracesCache ? tracesCache.traces.length : 0} trace(s) · ${fmtBytes(tracesCache ? tracesCache.bytes : 0)} total`;
}

$('#tracesAll').addEventListener('change', (e) => {
  // with an active filter, select-all covers the visible rows only
  document.querySelectorAll('.trace-row').forEach(tr => {
    if (tr.style.display !== 'none') {
      tr.querySelector('.trace-check').checked = e.target.checked;
    }
  });
  updateTracesSelection();
});

$('#tracesReload').addEventListener('click', loadTraces);

// Batch exclude: move every checked trace to the never-scan list in one
// round trip, then reload so they disappear from the scan.
$('#tracesExclude').addEventListener('click', async () => {
  const checked = [...document.querySelectorAll('.trace-check:checked')]
    .map(cb => cb.dataset.trace);
  if (!checked.length) return;
  let ok = 0, failed = 0;
  for (const p of checked) {
    try {
      await api('/api/traces/exclusions/add', { path: p });
      ok++;
    } catch (e) { failed++; }
  }
  toast(`Excluded ${ok} folder(s)${failed ? ` · ${failed} failed` : ''} — they no longer appear in the Cleanup scan.`, failed > 0);
  loadTraces();
});

$('#tracesDelete').addEventListener('click', () => {
  const checked = [...document.querySelectorAll('.trace-check:checked')]
    .map(cb => cb.dataset.trace);
  if (!checked.length) return;
  const chosen = (tracesCache.traces || []).filter(t => checked.includes(t.path));
  $('#udTitle').textContent = `Delete ${checked.length} trace(s)?`;
  $('#udList').innerHTML = chosen.map(t => `
    <div class="p"><span>${esc(t.path)}</span><span>${fmtBytes(t.sizeBytes)}</span></div>`).join('') + expertNote();
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
$('#logClose').addEventListener('click', () => $('#logDialog').close());
$('#appSearch').addEventListener('input', renderApps);
$('#appsReload').addEventListener('click', () => { appsCache = null; appSelected.clear(); loadApps(true); });
$('#appsAll').addEventListener('change', () => {
  const on = $('#appsAll').checked;
  document.querySelectorAll('#appsList .app-check').forEach(cb => {
    cb.checked = on;
    if (on) appSelected.add(cb.dataset.app); else appSelected.delete(cb.dataset.app);
    cb.closest('.app-card').classList.toggle('selected', on);
  });
  updateAppsBar();
});
$('#appsDeselect').addEventListener('click', () => {
  appSelected.clear();
  document.querySelectorAll('#appsList .app-check').forEach(cb => { cb.checked = false; cb.closest('.app-card').classList.remove('selected'); });
  $('#appsAll').checked = false;
  updateAppsBar();
});
$('#appsUninstall').addEventListener('click', uninstallBatchFlow);
$('#trustBtn').addEventListener('click', () => $('#trustDialog').showModal());
$('#trustClose').addEventListener('click', () => $('#trustDialog').close());

init();

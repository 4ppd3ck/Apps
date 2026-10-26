'use strict';

const OS_LABELS = { windows: 'Windows', macos: 'macOS', linux: 'Linux', android: 'Android', ios: 'iOS' };
const USER_OS = detectUserOs();
const state = { q: '', os: 'all', sort: 'best', page: 1, binaries: false, active: false, minStars: 0 };

const els = {
  form: document.getElementById('search-form'),
  input: document.getElementById('search-input'),
  chips: document.getElementById('os-chips'),
  filterChips: document.getElementById('filter-chips'),
  sort: document.getElementById('sort-select'),
  status: document.getElementById('status'),
  suggestions: document.getElementById('suggestions'),
  trending: document.getElementById('trending'),
  results: document.getElementById('results'),
  pager: document.getElementById('pager'),
  prev: document.getElementById('prev-page'),
  next: document.getElementById('next-page'),
  pageLabel: document.getElementById('page-label'),
  themeToggle: document.getElementById('theme-toggle'),
  bulkToggle: document.getElementById('bulk-toggle'),
  bulkPanel: document.getElementById('bulk-panel'),
  bulkUser: document.getElementById('bulk-user'),
  bulkLoad: document.getElementById('bulk-load'),
  bulkList: document.getElementById('bulk-list'),
  bulkSummary: document.getElementById('bulk-summary'),
  bulkDownload: document.getElementById('bulk-download'),
  bulkProgress: document.getElementById('bulk-progress'),
  bulkBar: document.getElementById('bulk-bar'),
  bulkProgressLabel: document.getElementById('bulk-progress-label'),
  bulkCancel: document.getElementById('bulk-cancel'),
  bulkRetry: document.getElementById('bulk-retry'),
  bulkInstall: document.getElementById('bulk-install'),
  saveMode: document.getElementById('save-mode'),
  saveFolderBtn: document.getElementById('save-folder-btn'),
  toasts: document.getElementById('toasts'),
};

let controller = null;
let lastQuery = '';
let saveFolder = null;
const SAVE_MODE_KEY = 'repolens-save-mode';

/* ---------- theme ---------- */

function applyTheme(t) {
  document.documentElement.dataset.theme = t;
  els.themeToggle.textContent = t === 'dark' ? '☀️' : '🌙';
  els.themeToggle.title = t === 'dark' ? 'Switch to light theme' : 'Switch to dark theme';
}

els.themeToggle.addEventListener('click', () => {
  const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
  try { localStorage.setItem('repolens-theme', next); } catch {}
  applyTheme(next);
});

applyTheme(document.documentElement.dataset.theme || 'dark');

/* ---------- helpers ---------- */

function detectUserOs() {
  const ua = navigator.userAgent;
  if (/Android/i.test(ua)) return 'android';
  if (/iPhone|iPad|iPod/i.test(ua)) return 'ios';
  if (/Mac OS X|Macintosh/.test(ua)) return 'macos';
  if (/Windows/.test(ua)) return 'windows';
  if (/Linux/.test(ua)) return 'linux';
  return null;
}

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function fmtNum(n) {
  if (n == null) return '–';
  if (n >= 1e9) return (n / 1e9).toFixed(1) + 'B';
  if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(1) + 'k';
  return String(n);
}

function fmtBytes(bytes) {
  if (!bytes && bytes !== 0) return '?';
  const units = ['B', 'KB', 'MB', 'GB'];
  let i = 0, v = bytes;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}

function timeAgo(iso) {
  if (!iso) return '';
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  const units = [['year', 31536000], ['month', 2592000], ['week', 604800], ['day', 86400], ['hour', 3600], ['minute', 60]];
  for (const [name, sec] of units) {
    if (s >= sec) {
      const v = Math.floor(s / sec);
      return `${v} ${name}${v > 1 ? 's' : ''} ago`;
    }
  }
  return 'just now';
}

function shortFolder(p) {
  if (!p) return '';
  const parts = p.split('/').filter(Boolean);
  return parts.length > 2 ? '…/' + parts.slice(-2).join('/') : p;
}

/* ---------- toasts ---------- */

function toast(message, kind = 'info', ms = 4200) {
  const el = document.createElement('div');
  el.className = `toast ${kind}`;
  el.textContent = message;
  els.toasts.appendChild(el);
  requestAnimationFrame(() => el.classList.add('show'));
  const hide = () => {
    el.classList.remove('show');
    setTimeout(() => el.remove(), 350);
  };
  if (ms > 0) setTimeout(hide, ms);
  return hide;
}

function toastWithAction(message, actionLabel, onAction, ms = 8000) {
  const el = document.createElement('div');
  el.className = 'toast info';
  const span = document.createElement('span');
  span.textContent = message;
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.textContent = actionLabel;
  btn.addEventListener('click', () => { onAction(); hide(); });
  el.append(span, btn);
  els.toasts.appendChild(el);
  requestAnimationFrame(() => el.classList.add('show'));
  const hide = () => {
    el.classList.remove('show');
    setTimeout(() => el.remove(), 350);
  };
  if (ms > 0) setTimeout(hide, ms);
  return hide;
}

/* ---------- save mode / download plumbing ---------- */

const SAVE_MODES = ['browser', 'folder', 'ask'];

function getSaveMode() {
  let m = 'browser';
  try { m = localStorage.getItem(SAVE_MODE_KEY) || 'browser'; } catch {}
  return SAVE_MODES.includes(m) ? m : 'browser';
}

function setSaveMode(m) {
  if (!SAVE_MODES.includes(m)) return;
  try { localStorage.setItem(SAVE_MODE_KEY, m); } catch {}
  els.saveMode.value = m;
  els.saveFolderBtn.classList.toggle('hidden', m !== 'folder');
  if (m === 'folder' && !saveFolder) pickFolder();
}

async function apiJSON(url, opts) {
  const res = await fetch(url, opts);
  let data = null;
  try { data = await res.json(); } catch {}
  if (!res.ok) throw new Error((data && data.error) || `Request failed (${res.status})`);
  return data;
}

async function pickFolder() {
  try {
    const d = await apiJSON('/api/pick-folder', { method: 'POST' });
    if (d && d.unsupported) {
      toast('Choosing a folder needs the native app (macOS or Windows).', 'error');
      return null;
    }
    if (!d || d.canceled || !d.path) return null;
    saveFolder = d.path;
    els.saveFolderBtn.textContent = `📁 ${shortFolder(saveFolder)}`;
    els.saveFolderBtn.title = saveFolder;
    return saveFolder;
  } catch (err) {
    toast(`Folder picker failed: ${err.message}`, 'error');
    return null;
  }
}

function proxyUrl(url, name) {
  return `/api/download?url=${encodeURIComponent(url)}&name=${encodeURIComponent(name || '')}`;
}

async function ensureFolder() {
  if (saveFolder) return saveFolder;
  return pickFolder();
}

async function saveAs(url, name) {
  let target;
  try {
    const d = await apiJSON('/api/pick-file', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name }),
    });
    if (d && d.unsupported) {
      toast('Save As needs the native app (macOS or Windows).', 'error');
      return;
    }
    if (!d || d.canceled || !d.path) return;
    target = d.path;
  } catch (err) {
    toast(`Save dialog failed: ${err.message}`, 'error');
    return;
  }
  try {
    toast(`Saving ${name}…`);
    await apiJSON('/api/save', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, file: target }),
    });
    toast(`Saved to ${target}`, 'success', 6000);
  } catch (err) {
    toast(`Save failed: ${err.message}`, 'error', 6000);
  }
}

async function saveToFolder(url, name) {
  const dir = await ensureFolder();
  if (!dir) return;
  try {
    const res = await apiJSON('/api/save', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, name, dir }),
    });
    if (res && res.canceled) return;
    toastWithAction(`Saved ${res && res.name ? res.name : name}`, 'Open folder', () => openFolder(dir));
  } catch (err) {
    toast(`Save failed: ${err.message}`, 'error', 6000);
  }
}

async function openFolder(dir) {
  try {
    await apiJSON('/api/open', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path: dir }),
    });
  } catch {}
}

async function downloadItem(url, name) {
  const mode = getSaveMode();
  if (mode === 'folder') return saveToFolder(url, name);
  if (mode === 'ask') return saveAs(url, name);
  const a = document.createElement('a');
  a.href = proxyUrl(url, name);
  a.download = name || '';
  document.body.appendChild(a);
  a.click();
  a.remove();
}

/* ---------- URL state (shareable searches) ---------- */

function stateToParams() {
  const p = new URLSearchParams();
  if (state.q) p.set('q', state.q);
  if (state.os !== 'all') p.set('os', state.os);
  if (state.sort !== 'best') p.set('sort', state.sort);
  if (state.binaries) p.set('binaries', '1');
  if (state.active) p.set('active', '1');
  if (state.minStars) p.set('stars', String(state.minStars));
  if (state.page > 1) p.set('page', String(state.page));
  return p;
}

function paramsToState(p) {
  state.q = (p.get('q') || '').trim();
  state.os = OS_LABELS[p.get('os')] ? p.get('os') : 'all';
  state.sort = ['best', 'downloads', 'stars', 'activity'].includes(p.get('sort')) ? p.get('sort') : 'best';
  state.binaries = p.get('binaries') === '1';
  state.active = p.get('active') === '1';
  state.minStars = p.get('stars') === '50' || p.get('stars') === '200' ? Number(p.get('stars')) : 0;
  state.page = Math.max(1, Number.parseInt(p.get('page'), 10) || 1);
}

function syncControls() {
  els.input.value = state.q;
  els.sort.value = state.sort;
  for (const btn of els.filterChips.querySelectorAll('.chip')) {
    const f = btn.dataset.filter;
    const on =
      (f === 'binaries' && state.binaries) ||
      (f === 'active' && state.active) ||
      (f === 'stars50' && state.minStars === 50) ||
      (f === 'stars200' && state.minStars === 200);
    btn.classList.toggle('active', on);
  }
  buildChips();
}

function updateUrl(push) {
  const qs = stateToParams().toString();
  const url = location.pathname + (qs ? '?' + qs : '');
  if (push) history.pushState({}, '', url);
  else history.replaceState({}, '', url);
}

window.addEventListener('popstate', () => {
  paramsToState(new URLSearchParams(location.search));
  syncControls();
  if (state.q) run({ push: false });
  else goHome();
});

/* ---------- chips ---------- */

function buildChips(osCounts = {}) {
  const chips = [['all', 'All OSes'], ...Object.entries(OS_LABELS)];
  els.chips.innerHTML = '';
  for (const [value, label] of chips) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'chip' + (state.os === value ? ' active' : '');
    btn.dataset.os = value;
    const count = osCounts[value];
    btn.textContent = label + (count ? ` · ${count}` : '');
    if (value === USER_OS) btn.title = 'Your OS';
    btn.addEventListener('click', () => {
      if (state.os === value) return;
      state.os = value;
      state.page = 1;
      run();
    });
    els.chips.appendChild(btn);
  }
}

for (const btn of els.filterChips.querySelectorAll('.chip')) {
  btn.addEventListener('click', () => {
    const f = btn.dataset.filter;
    if (f === 'binaries') state.binaries = !state.binaries;
    else if (f === 'active') state.active = !state.active;
    else if (f === 'stars50') state.minStars = state.minStars === 50 ? 0 : 50;
    else if (f === 'stars200') state.minStars = state.minStars === 200 ? 0 : 200;
    state.page = 1;
    run();
  });
}

/* ---------- search ---------- */

async function run({ push = true } = {}) {
  if (!state.q) return;
  if (controller) controller.abort();
  controller = new AbortController();
  const { signal } = controller;

  lastQuery = state.q;
  els.suggestions.classList.add('hidden');
  els.trending.classList.add('hidden');
  renderSkeletons();
  updateUrl(push);

  const params = stateToParams();
  params.set('page', String(state.page));
  let data;
  try {
    const res = await fetch(`/api/search?${params}`, { signal });
    data = await res.json();
    if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  } catch (err) {
    if (err.name === 'AbortError') return;
    els.status.innerHTML = '';
    els.results.innerHTML = '';
    showError(err.message);
    return;
  }
  render(data);
}

function goHome() {
  els.status.innerHTML = '';
  els.results.innerHTML = '';
  els.pager.classList.add('hidden');
  els.suggestions.classList.remove('hidden');
  updateUrl(false);
  loadTrending();
}

function renderSkeletons() {
  els.status.textContent = 'Scanning GitHub releases…';
  els.pager.classList.add('hidden');
  els.results.innerHTML = Array.from({ length: 4 }, () => '<div class="card skeleton"></div>').join('');
}

function render(data) {
  buildChips(data.osCounts || {});
  const filterNotes = [];
  if (state.os !== 'all') filterNotes.push(`shipping for ${OS_LABELS[state.os]}`);
  if (state.binaries) filterNotes.push('ships installers');
  if (state.active) filterNotes.push('actively maintained');
  if (state.minStars) filterNotes.push(`★ ${state.minStars}+`);
  els.status.innerHTML =
    `≈ ${fmtNum(data.totalCount)} repos match <b>${esc(data.query)}</b>` +
    (filterNotes.length ? ` · ${filterNotes.join(' · ')}` : '') +
    (data.warning ? `<br><span class="warn">⚠ ${esc(data.warning)}</span>` : '');

  if (!data.results.length) {
    els.results.innerHTML =
      `<div class="empty"><p><b>No results.</b></p>` +
      `<p>Try fewer words, a different phrasing, or relax the filters.</p></div>`;
    els.pager.classList.add('hidden');
    return;
  }

  els.results.innerHTML = data.results.map(cardHtml).join('');

  const hasPrev = data.page > 1;
  const hasNext = data.totalCount > data.page * data.perPage;
  els.pager.classList.toggle('hidden', !hasPrev && !hasNext);
  els.prev.disabled = !hasPrev;
  els.next.disabled = !hasNext;
  els.pageLabel.textContent = `Page ${data.page}`;
}

function zipballUrl(r) {
  return `https://github.com/${r.fullName}/zipball/${encodeURIComponent(r.latestTag || 'HEAD')}`;
}

function cardHtml(r) {
  const meta = [];
  if (r.language) meta.push(esc(r.language));
  if (r.license) meta.push(`${esc(r.license)} license`);
  if (r.pushedAt) meta.push('updated ' + timeAgo(r.pushedAt));
  if (r.archived) meta.push('⚠ archived');
  const installed = APPDECK_LAUNCHER && isInstalledOnDeck(r.name);
  if (installed) meta.push('<span class="deck-badge">✓ on AppDeck</span>');

  const osBadges = r.oses.length
    ? r.oses.map((o) =>
        `<span class="os-badge">${OS_LABELS[o] || esc(o)} <b>${fmtNum(r.downloadsByOs[o] || 0)}</b></span>`).join('')
    : '<span class="os-badge none">no prebuilt binaries — see repo for install steps</span>';

  const tags = (r.topics || []).slice(0, 5).map((t) => `<span class="topic">${esc(t)}</span>`).join('');

  const releaseInfo = r.latestRelease
    ? `<span class="release-info">${r.latestRelease.prerelease ? 'pre-release' : 'release'} ` +
      `${esc(r.latestRelease.tag)} · ${timeAgo(r.latestRelease.publishedAt)}</span>`
    : '<span class="release-info">no releases</span>';

  return `
  <article class="card" data-repo="${esc(r.fullName)}">
    <div class="head">
      <img class="avatar" src="${r.owner ? `https://github.com/${esc(r.owner)}.png?size=64` : ''}" alt="" loading="lazy">
      <div class="title">
        <a href="${esc(r.htmlUrl)}" target="_blank" rel="noopener noreferrer">${esc(r.fullName)}</a>
        <div class="meta">${meta.map((m) => `<span>${m}</span>`).join('<span class="dot">·</span>')}</div>
      </div>
      <div class="stats">
        <span class="stars" title="${fmtNum(r.stars)} stars">★ ${fmtNum(r.stars)}</span>
        <span class="downloads" title="${fmtNum(r.totalDownloads)} release downloads">⬇ ${fmtNum(r.totalDownloads)}</span>
      </div>
    </div>
    ${r.description ? `<p class="desc">${esc(r.description)}</p>` : ''}
    <div class="os-row">${osBadges}</div>
    ${tags ? `<div class="topics">${tags}</div>` : ''}
    <div class="actions">
      ${primaryAction(r)}
      ${installButton(r, installed)}
      ${releaseInfo}
      <button type="button" class="ghost dl" data-url="${esc(zipballUrl(r))}" data-name="${esc(r.name)}-source.zip">⬇ .zip source</button>
      <a class="ghost" href="${esc(r.htmlUrl)}/releases" target="_blank" rel="noopener noreferrer">All releases ↗</a>
    </div>
  </article>`;
}

function bestOSAsset(r) {
  if (!USER_OS || !r.latestAssets?.length) return null;
  const candidates = r.latestAssets.filter((a) => a.os === USER_OS).sort((a, b) => b.downloads - a.downloads);
  return candidates[0] || null;
}

function primaryAction(r) {
  const best = bestOSAsset(r);
  if (best) {
    return `<button type="button" class="primary dl" data-url="${esc(best.url)}" data-name="${esc(best.name)}">⬇ Download for ${OS_LABELS[USER_OS]} (${fmtBytes(best.size)})</button>`;
  }
  if (r.latestRelease) {
    return `<button type="button" class="primary subtle dl" data-url="${esc(r.latestRelease.url)}" data-name="${esc(r.name)}-release.zip">⬇ Get latest release</button>`;
  }
  return `<a class="primary subtle" href="${esc(r.htmlUrl)}" target="_blank" rel="noopener noreferrer">View on GitHub ↗</a>`;
}

// The card's AppDeck install action: the OS asset when one exists, otherwise
// the backend hands the repo URL to AppDeck for a git import. Empty until the
// platform probe confirms RepoLens runs under AppDeck.
function installButton(r, installed) {
  if (!APPDECK_LAUNCHER) return '';
  const best = bestOSAsset(r);
  return `<button type="button" class="ghost install" data-repo="${esc(r.fullName)}" data-name="${esc(r.name)}" data-url="${esc(best ? best.url : '')}" title="${installed ? 'Reinstall the latest version into AppDeck' : 'Install this app into the AppDeck dashboard'}">${installed ? '🔄 Update on AppDeck' : '🧩 Install on AppDeck'}</button>`;
}

function showError(message) {
  els.results.innerHTML = `<div class="error"><b>Search failed.</b> ${esc(message)}</div>`;
}

/* ---------- click handling (downloads + analytics) ---------- */

els.results.addEventListener('click', (e) => {
  const card = e.target.closest('article.card');
  const inst = e.target.closest('button.install');
  if (inst && card) {
    installOnAppDeck(inst);
    return;
  }
  const dl = e.target.closest('button.dl');
  if (dl && card) {
    trackClick(card.dataset.repo || '', dl.classList.contains('primary') ? 'download' : 'source', dl.dataset.url);
    downloadItem(dl.dataset.url, dl.dataset.name);
    return;
  }
  const a = e.target.closest('a');
  if (!a || !card) return;
  const action = a.classList.contains('primary') ? 'repo' : a.classList.contains('ghost') ? 'releases' : 'repo';
  trackClick(card.dataset.repo || '', action, a.href);
});

function trackClick(repo, action, href) {
  const payload = JSON.stringify({ type: 'click', repo, action, query: lastQuery });
  try {
    navigator.sendBeacon('/api/track', new Blob([payload], { type: 'application/json' }));
  } catch {
    fetch('/api/track', { method: 'POST', body: payload, keepalive: true }).catch(() => {});
  }
}

/* ---------- install on AppDeck ---------- */

let APPDECK_LAUNCHER = '';
const installedDeckIds = new Set();
const installedDeckNames = new Set();
const activeInstalls = new Map(); // repo full name → { jobId, btn, timer }

function slugifyId(s) {
  return String(s).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 63);
}

// AppDeck slugifies the manifest id, so the repo name usually lands as the
// app id; the display-name match covers the cases where it doesn't.
function isInstalledOnDeck(name) {
  return installedDeckIds.has(slugifyId(name)) || installedDeckNames.has(String(name).toLowerCase());
}

// One-shot platform probe: turns the install UI on and loads the installed
// set. Buttons rendered before it lands are painted by the boot re-run.
async function loadPlatform() {
  try {
    const d = await apiJSON('/api/platform');
    if (d && d.appdeck && d.launcher) {
      APPDECK_LAUNCHER = d.launcher;
      await refreshInstalledApps();
    }
  } catch {}
  els.bulkInstall.classList.toggle('hidden', !APPDECK_LAUNCHER);
}

// The launcher's app list is deliberately CORS-open, so the page reads it
// straight from the dashboard — no backend round-trip for the badge.
async function refreshInstalledApps() {
  if (!APPDECK_LAUNCHER) return;
  try {
    const res = await fetch(`${APPDECK_LAUNCHER}/api/apps`);
    const apps = await res.json();
    installedDeckIds.clear();
    installedDeckNames.clear();
    for (const a of Array.isArray(apps) ? apps : []) {
      if (a.id) installedDeckIds.add(a.id);
      if (a.name) installedDeckNames.add(String(a.name).toLowerCase());
    }
  } catch {}
}

async function installOnAppDeck(btn) {
  if (!APPDECK_LAUNCHER) return;
  const repo = btn.dataset.repo;
  if (!repo) return;
  if (activeInstalls.has(repo)) {
    cancelInstall(repo, 'Install canceled.'); // clicking a running install cancels it
    return;
  }
  const payload = { repo: `https://github.com/${repo}`, name: btn.dataset.name || '' };
  if (btn.dataset.url) payload.url = btn.dataset.url;
  let d;
  try {
    d = await apiJSON('/api/appdeck/install', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
  } catch (err) {
    toast(`Install failed: ${err.message}`, 'error', 6000);
    return;
  }
  activeInstalls.set(repo, { jobId: d.job, btn });
  btn.classList.add('pending');
  btn.textContent = '⏳ Starting…';
  pollInstall(repo);
}

function pollInstall(repo) {
  const rec = activeInstalls.get(repo);
  if (!rec) return;
  rec.timer = setTimeout(async () => {
    if (activeInstalls.get(repo) !== rec) return;
    let d;
    try {
      d = await apiJSON(`/api/appdeck/install?id=${encodeURIComponent(rec.jobId)}`);
    } catch (err) {
      if (String(err.message || '').includes('Unknown install job')) {
        activeInstalls.delete(repo);
        restoreInstallBtn(rec.btn);
        toast(`Install failed: ${err.message}`, 'error', 6000);
        return;
      }
      pollInstall(repo); // transient — keep polling
      return;
    }
    if (activeInstalls.get(repo) !== rec) return;
    if (!d.done) {
      rec.btn.textContent = d.note || '⏳ Installing…';
      pollInstall(repo);
      return;
    }
    activeInstalls.delete(repo);
    if (d.ok) {
      const name = (d.result && d.result.name) || repo.split('/').pop();
      toastWithAction(`Installed ${name} on AppDeck`, 'Open AppDeck', () => {
        if (d.result?.dashboard) window.open(d.result.dashboard, '_blank');
      });
      await refreshInstalledApps();
      setCardInstalled(rec.btn.closest('article.card'), true);
      restoreInstallBtn(rec.btn);
    } else {
      restoreInstallBtn(rec.btn);
      toast(`Install failed: ${d.error || 'unknown error'}`, 'error', 8000);
    }
  }, 1000);
}

async function cancelInstall(repo, message) {
  const rec = activeInstalls.get(repo);
  if (!rec) return;
  activeInstalls.delete(repo);
  clearTimeout(rec.timer);
  try {
    await apiJSON('/api/appdeck/install/cancel', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: rec.jobId }),
    });
  } catch {}
  restoreInstallBtn(rec.btn);
  if (message) toast(message);
}

function restoreInstallBtn(btn) {
  if (!btn) return;
  btn.classList.remove('pending');
  const installed = isInstalledOnDeck(btn.dataset.name || '');
  btn.classList.toggle('update', installed);
  btn.textContent = installed ? '🔄 Update on AppDeck' : '🧩 Install on AppDeck';
}

// The badge lives in the card's meta row; flipping it in place shows a
// finished install without re-running the search.
function setCardInstalled(card, installed) {
  if (!card) return;
  const meta = card.querySelector('.meta');
  if (!meta) return;
  let badge = meta.querySelector('.deck-badge');
  if (installed && !badge) {
    badge = document.createElement('span');
    badge.className = 'deck-badge';
    badge.textContent = '✓ on AppDeck';
    meta.appendChild(badge);
  } else if (!installed && badge) {
    badge.remove();
  }
}

/* ---------- bulk download by user ---------- */

let bulkRepos = [];
let bulkJobId = null;
let bulkPollTimer = null;
let bulkRunning = false;

function updateBulkSummary() {
  const checked = els.bulkList.querySelectorAll('input[type="checkbox"]:checked').length;
  els.bulkSummary.textContent = `${checked} of ${bulkRepos.length} selected`;
  els.bulkDownload.disabled = checked === 0 || bulkRunning;
  els.bulkInstall.disabled = checked === 0 || bulkRunning || bulkInstalling;
}

async function loadUserRepos() {
  const user = els.bulkUser.value.trim();
  if (!user) {
    toast('Enter a GitHub username first.', 'error');
    return;
  }
  els.bulkLoad.disabled = true;
  els.bulkList.innerHTML = '<div class="bulk-loading">Loading repositories…</div>';
  els.bulkSummary.textContent = '';
  els.bulkDownload.disabled = true;
  try {
    const d = await apiJSON(`/api/user-repos?user=${encodeURIComponent(user)}`);
    bulkRepos = d.repos || [];
    if (!bulkRepos.length) {
      els.bulkList.innerHTML = '<div class="bulk-loading">No public repositories found.</div>';
      return;
    }
    els.bulkList.innerHTML = bulkRepos.map((r) => `
      <label class="bulk-row${r.fork ? ' fork' : ''}">
        <input type="checkbox" data-name="${esc(r.name)}" data-fullname="${esc(r.fullName)}" data-branch="${esc(r.defaultBranch || 'HEAD')}">
        <span class="bulk-name" title="${esc(r.fullName)}">${esc(r.name)}</span>
        ${r.fork ? '<span class="bulk-tag">fork</span>' : ''}
        ${r.archived ? '<span class="bulk-tag">archived</span>' : ''}
        <span class="bulk-meta">★ ${fmtNum(r.stars)}${r.pushedAt ? ' · ' + timeAgo(r.pushedAt) : ''}</span>
        ${r.description ? `<span class="bulk-desc">${esc(r.description)}</span>` : ''}
      </label>`).join('');
    els.bulkSummary.textContent = `0 of ${bulkRepos.length} selected` + (d.truncated ? ' (first 300 by recent activity)' : '');
    els.bulkDownload.disabled = false;
    els.bulkInstall.disabled = false;
    for (const cb of els.bulkList.querySelectorAll('input[type="checkbox"]')) {
      cb.addEventListener('change', updateBulkSummary);
    }
  } catch (err) {
    els.bulkList.innerHTML = '';
    toast(`Could not list repositories: ${err.message}`, 'error', 6000);
  } finally {
    els.bulkLoad.disabled = false;
  }
}

async function startBulkDownload() {
  if (bulkRunning) return;
  const dir = await ensureFolder();
  if (!dir) return;
  const items = [...els.bulkList.querySelectorAll('input[type="checkbox"]:checked')].map((cb) => ({
    url: zipballUrl({ fullName: cb.dataset.fullname, latestTag: cb.dataset.branch || 'HEAD' }),
    name: `${cb.dataset.name}-source.zip`,
  }));
  if (!items.length) return;
  els.bulkDownload.disabled = true;
  els.bulkProgress.classList.remove('hidden');
  els.bulkBar.style.width = '0%';
  els.bulkProgressLabel.textContent = 'Starting…';
  els.bulkRetry.classList.add('hidden');
  try {
    const d = await apiJSON('/api/batch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ dir, items }),
    });
    bulkJobId = d.jobId;
    bulkRunning = true;
    els.bulkCancel.classList.remove('hidden');
    pollBulkJob();
  } catch (err) {
    els.bulkProgress.classList.add('hidden');
    toast(`Bulk download failed to start: ${err.message}`, 'error', 6000);
    updateBulkSummary();
  }
}

function pollBulkJob() {
  if (!bulkJobId) return;
  clearInterval(bulkPollTimer);
  bulkPollTimer = setInterval(async () => {
    let d;
    try {
      d = await apiJSON(`/api/job?id=${encodeURIComponent(bulkJobId)}`);
    } catch {
      return; // transient — keep polling
    }
    const pct = d.total ? Math.round(((d.done + d.failed) / d.total) * 100) : 0;
    els.bulkBar.style.width = pct + '%';
    els.bulkProgressLabel.textContent =
      d.state === 'running'
        ? `${d.done + d.failed}/${d.total} done${d.current ? ` · fetching ${d.current}` : ''}`
        : d.state === 'canceled'
          ? `Canceled at ${d.done + d.failed}/${d.total}`
          : `${d.done}/${d.total} saved${d.failed ? ` · ${d.failed} failed` : ''} · ${fmtBytes(d.bytes)} into ${shortFolder(d.dir)}`;
    if (d.state !== 'running') {
      clearInterval(bulkPollTimer);
      bulkPollTimer = null;
      bulkRunning = false;
      bulkJobId = null;
      els.bulkCancel.classList.add('hidden');
      if (d.failed) {
        els.bulkRetry.classList.remove('hidden');
        els.bulkRetry.textContent = `↻ Retry ${d.failed} failed`;
        els.bulkRetry.dataset.errors = JSON.stringify(d.errors || []);
      }
      const kind = d.state === 'canceled' ? 'error' : d.failed ? 'error' : 'success';
      toast(
        d.state === 'canceled' ? 'Bulk download canceled.'
        : d.failed ? `Bulk download finished with ${d.failed} failure${d.failed > 1 ? 's' : ''}.`
        : `Saved ${d.done} repositor${d.done === 1 ? 'y' : 'ies'} to ${shortFolder(d.dir)}`,
        kind, 7000,
      );
      updateBulkSummary();
    }
  }, 800);
}

els.bulkCancel.addEventListener('click', async () => {
  if (!bulkJobId) return;
  try {
    await apiJSON('/api/job/cancel', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: bulkJobId }),
    });
    els.bulkProgressLabel.textContent = 'Canceling…';
  } catch {}
});

els.bulkRetry.addEventListener('click', async () => {
  let errors = [];
  try { errors = JSON.parse(els.bulkRetry.dataset.errors || '[]'); } catch {}
  if (!errors.length) return;
  const dir = await ensureFolder();
  if (!dir) return;
  els.bulkDownload.disabled = true;
  els.bulkRetry.classList.add('hidden');
  els.bulkProgress.classList.remove('hidden');
  els.bulkBar.style.width = '0%';
  els.bulkProgressLabel.textContent = 'Retrying…';
  try {
    const d = await apiJSON('/api/batch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ dir, items: errors.map((e) => ({ url: e.url, name: e.name })) }),
    });
    bulkJobId = d.jobId;
    bulkRunning = true;
    els.bulkCancel.classList.remove('hidden');
    pollBulkJob();
  } catch (err) {
    els.bulkProgress.classList.add('hidden');
    toast(`Retry failed: ${err.message}`, 'error');
    updateBulkSummary();
  }
});

/* ---------- bulk install on AppDeck ---------- */

// Bulk installs are always source imports (the user-repo list carries no
// release enrichment): AppDeck git-clones each repo and generates the
// manifest. Runs sequentially through the same per-repo install jobs the
// cards use; the button doubles as the cancel control.
let bulkInstalling = false;
let bulkInstallCancel = false;
let bulkInstallJobId = null;

els.bulkInstall.addEventListener('click', () => {
  if (bulkInstalling) {
    bulkInstallCancel = true;
    if (bulkInstallJobId) {
      apiJSON('/api/appdeck/install/cancel', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: bulkInstallJobId }),
      }).catch(() => {});
    }
    els.bulkProgressLabel.textContent = 'Canceling…';
    return;
  }
  startBulkInstall();
});

async function startBulkInstall() {
  if (bulkInstalling || !APPDECK_LAUNCHER) return;
  const checked = [...els.bulkList.querySelectorAll('input[type="checkbox"]:checked')];
  if (!checked.length) return;
  bulkInstalling = true;
  bulkInstallCancel = false;
  els.bulkDownload.disabled = true;
  els.bulkInstall.disabled = false;
  els.bulkInstall.textContent = '✕ Cancel installs';
  els.bulkProgress.classList.remove('hidden');
  els.bulkBar.style.width = '0%';
  els.bulkRetry.classList.add('hidden');
  const total = checked.length;
  let okCount = 0;
  let failCount = 0;
  let lastError = '';
  for (let i = 0; i < total; i++) {
    if (bulkInstallCancel) break;
    const cb = checked[i];
    const name = cb.dataset.name || '';
    els.bulkBar.style.width = Math.round((i / total) * 100) + '%';
    els.bulkProgressLabel.textContent = `Installing ${i + 1}/${total}: ${name}…`;
    try {
      const d = await apiJSON('/api/appdeck/install', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repo: `https://github.com/${cb.dataset.fullname}`, name }),
      });
      bulkInstallJobId = d.job;
      const res = await waitInstallDone(d.job);
      if (res.ok) okCount++;
      else { failCount++; lastError = res.error || lastError; }
    } catch (err) {
      failCount++;
      lastError = err.message;
    }
    bulkInstallJobId = null;
  }
  const canceled = bulkInstallCancel;
  bulkInstalling = false;
  bulkInstallJobId = null;
  els.bulkProgress.classList.add('hidden');
  els.bulkInstall.textContent = '🧩 Install selected on AppDeck';
  updateBulkSummary();
  await refreshInstalledApps();
  if (canceled) toast(`Install run canceled — ${okCount} installed.`, 'info', 6000);
  else if (failCount) toast(`Installed ${okCount}/${total} · ${failCount} failed${lastError ? ` — ${lastError}` : ''}`, 'error', 8000);
  else toast(`Installed ${okCount} repositor${okCount === 1 ? 'y' : 'ies'} on AppDeck.`, 'success', 7000);
}

function waitInstallDone(jobId) {
  return new Promise((resolve) => {
    const tick = async () => {
      let d;
      try {
        d = await apiJSON(`/api/appdeck/install?id=${encodeURIComponent(jobId)}`);
      } catch (err) {
        if (String(err.message || '').includes('Unknown install job')) {
          resolve({ ok: false, error: err.message });
          return;
        }
        setTimeout(tick, 1200);
        return;
      }
      if (!d.done) {
        setTimeout(tick, 1200);
        return;
      }
      resolve({ ok: !!d.ok, error: d.error || '' });
    };
    tick();
  });
}

/* ---------- trending (from local history) ---------- */

async function loadTrending() {
  let d;
  try {
    const res = await fetch('/api/trending');
    d = await res.json();
  } catch {
    return;
  }
  const searches = d.searches || [];
  const repos = d.repos || [];
  if (!searches.length && !repos.length) return;

  let html = '<p class="hint">From your recent searches:</p>';
  if (searches.length) {
    html += `<div class="chips suggestion-chips">` + searches.map((s) =>
      `<button type="button" class="trend-search" data-q="${esc(s.query)}">${esc(s.query)} <b>· ${s.hits}</b></button>`).join('') + `</div>`;
  }
  if (repos.length) {
    html += `<p class="hint" style="margin-top:14px">Most opened:</p><div class="chips suggestion-chips">` +
      repos.map((r) =>
        `<a class="chip trend-repo" href="https://github.com/${esc(r.repo)}" target="_blank" rel="noopener noreferrer">${esc(r.repo)} <b>· ${r.hits}</b></a>`).join('') +
      `</div>`;
  }
  els.trending.innerHTML = html;
  els.trending.classList.remove('hidden');
  for (const btn of els.trending.querySelectorAll('.trend-search')) {
    btn.addEventListener('click', () => {
      els.input.value = btn.dataset.q;
      state.q = btn.dataset.q;
      state.page = 1;
      run();
    });
  }
}

/* ---------- events ---------- */

els.form.addEventListener('submit', (e) => {
  e.preventDefault();
  const q = els.input.value.trim();
  if (!q) return;
  state.q = q;
  state.page = 1;
  run();
});

els.sort.addEventListener('change', () => {
  state.sort = els.sort.value;
  state.page = 1;
  run();
});

els.prev.addEventListener('click', () => { state.page -= 1; run(); });
els.next.addEventListener('click', () => { state.page += 1; run(); });

for (const btn of document.querySelectorAll('.suggestion-chips button')) {
  btn.addEventListener('click', () => {
    els.input.value = btn.dataset.q;
    state.q = btn.dataset.q;
    state.page = 1;
    run();
  });
}

els.bulkToggle.addEventListener('click', () => {
  const open = els.bulkPanel.classList.toggle('hidden');
  els.bulkToggle.textContent = open ? '⬇ Download repos by user' : '✕ Close';
  els.bulkToggle.setAttribute('aria-expanded', String(!open));
});

els.bulkLoad.addEventListener('click', loadUserRepos);
els.bulkUser.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') { e.preventDefault(); loadUserRepos(); }
});
els.bulkDownload.addEventListener('click', startBulkDownload);

/* ---------- boot ---------- */

setSaveMode(getSaveMode());
els.saveMode.addEventListener('change', () => setSaveMode(els.saveMode.value));
els.saveFolderBtn.addEventListener('click', pickFolder);

// Platform probe enables the AppDeck install UI; if cards are already on
// screen, re-run the view so they pick up the buttons and badges.
loadPlatform().then(() => {
  if (els.results.querySelector('article.card')) run({ push: false });
});

paramsToState(new URLSearchParams(location.search));
syncControls();
if (state.q) run({ push: false });
else loadTrending();

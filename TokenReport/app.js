/* TokenReport — app logic: sources (folder pickers), scan+parse, filters,
 * aggregation, rendering, pricing, CSV export, local archive.
 * Everything runs in the browser against local files — zero AI tokens.
 */
(function () {
  'use strict';

  var P = window.TR_PARSERS;
  var $ = function (sel) { return document.querySelector(sel); };
  var $$ = function (sel) { return Array.prototype.slice.call(document.querySelectorAll(sel)); };

  // True when the dashboard runs inside another page (e.g. embedded in the
  // AppDeck dashboard tab) — browsers restrict folder permission prompts in
  // cross-origin frames, so restore may only work from a standalone window.
  var EMBEDDED = false;
  try { EMBEDDED = window.self !== window.top; } catch (e) { EMBEDDED = true; }

  // ---------- constants ----------

  var SKIP_DIR = /^(node_modules|\.git|Cache|Code Cache|GPUCache|DawnGraphiteCache|DawnWebGPUCache|chrome-ext|blob_storage|Shared Dictionary|Session Storage|SharedStorage|WebStorage|IndexedDB|Local Storage|cache|dist|release)$/i;
  var MAX_FILES = 4000;
  var MAX_BYTES = 300 * 1024 * 1024;
  var AGENT_NAMES = {
    'zcode': 'ZCode',
    'claude-code': 'Claude Code',
    'codex': 'Codex CLI',
    'copilot': 'Copilot CLI',
    'openclaw': 'OpenClaw / AutoClaw',
    'generic': 'Custom agent'
  };
  var TEMPLATES = [
    { id: 'zcode', name: 'ZCode', hint: 'Pick: %USERPROFILE%\\.zcode\\cli\\rollout' },
    { id: 'claude-code', name: 'Claude Code', hint: 'Pick: %USERPROFILE%\\.claude\\projects (or one project folder)' },
    { id: 'codex', name: 'Codex CLI', hint: 'Pick: %USERPROFILE%\\.codex\\sessions' },
    { id: 'copilot', name: 'Copilot CLI', hint: 'Pick: ~/.copilot (reads session-store.db or data.db)' },
    { id: 'openclaw', name: 'OpenClaw / AutoClaw', hint: 'Pick: ~/.openclaw-autoclaw (agent folders with session .jsonl)' },
    { id: 'generic', name: 'Custom / new agent', hint: 'Pick any folder containing .jsonl / .json logs' }
  ];
  var RANGES = [
    { id: '5m', label: 'Last 5 minutes', ms: 5 * 60e3 },
    { id: '15m', label: 'Last 15 minutes', ms: 15 * 60e3 },
    { id: '1h', label: 'Last 1 hour', ms: 60 * 60e3 },
    { id: '12h', label: 'Last 12 hours', ms: 12 * 60 * 60e3 },
    { id: '24h', label: 'Last 24 hours', ms: 24 * 60 * 60e3 },
    { id: '7d', label: 'Last 7 days', ms: 7 * 24 * 60 * 60e3 },
    { id: 'all', label: 'All time on disk', ms: null },
    { id: 'custom', label: 'Custom range…', ms: 'custom' }
  ];

  var DEFAULT_PRICES = {
    _help: 'USD per 1M tokens. cacheReadRatio/cacheWriteRatio multiply the input price. Longest name that appears in the model id wins; "default" catches the rest. Estimates — edit to match your plan.',
    'default': { input: 0.6, output: 2.2, cacheReadRatio: 0.1, cacheWriteRatio: 1.25 },
    'glm-5.3': { input: 0.6, output: 2.2, cacheReadRatio: 0.1, cacheWriteRatio: 1.25 },
    'glm-4': { input: 0.6, output: 2.2, cacheReadRatio: 0.1, cacheWriteRatio: 1.25 },
    'claude-sonnet': { input: 3, output: 15, cacheReadRatio: 0.1, cacheWriteRatio: 1.25 },
    'claude-opus': { input: 15, output: 75, cacheReadRatio: 0.1, cacheWriteRatio: 1.25 },
    'claude-haiku': { input: 0.8, output: 4, cacheReadRatio: 0.1, cacheWriteRatio: 1.25 },
    'gpt-4o-mini': { input: 0.15, output: 0.6, cacheReadRatio: 0.5, cacheWriteRatio: 1 },
    'gpt-4o': { input: 2.5, output: 10, cacheReadRatio: 0.5, cacheWriteRatio: 1 },
    'gpt-4.1-mini': { input: 0.4, output: 1.6, cacheReadRatio: 0.25, cacheWriteRatio: 1 },
    'gpt-4.1': { input: 2, output: 8, cacheReadRatio: 0.25, cacheWriteRatio: 1 },
    'gpt-5-mini': { input: 0.25, output: 2, cacheReadRatio: 0.1, cacheWriteRatio: 1 },
    'gpt-5': { input: 1.25, output: 10, cacheReadRatio: 0.1, cacheWriteRatio: 1 },
    'o3': { input: 2, output: 8, cacheReadRatio: 0.5, cacheWriteRatio: 1 },
    'gemini-2.5-pro': { input: 1.25, output: 10, cacheReadRatio: 0.1, cacheWriteRatio: 1 },
    'gemini-2.5-flash': { input: 0.3, output: 2.5, cacheReadRatio: 0.1, cacheWriteRatio: 1 },
    'deepseek': { input: 0.27, output: 1.1, cacheReadRatio: 0.1, cacheWriteRatio: 1 },
    'qwen': { input: 0.4, output: 1.2, cacheReadRatio: 0.2, cacheWriteRatio: 1 },
    'llama': { input: 0.35, output: 0.4, cacheReadRatio: 0.5, cacheWriteRatio: 1 }
  };

  // ---------- state ----------

  var state = {
    sources: [],          // {id, agent, name, handle|demo, status:'ok'|'reconnect'|'error', files, lastScan, demoPath}
    records: [],          // normalized, current scan
    sessionTasks: {},     // agentType:session -> task label
    range: '24h',
    customFrom: null,
    customTo: null,
    agentFilter: 'all',
    includeArchive: false,
    archiveHandle: null,
    archiveText: null,    // embedded mode: archive content held in memory
    archiveName: null,    // embedded mode: name of the loaded/downloaded archive
    prices: null,
    scanning: false,
    lastRefresh: null,
    view: 'report',       // 'report' | 'peak'
    peakMetric: 'tokens', // 'tokens' | 'cost' | 'output' | 'requests'
    peakStart: 10,        // peak window start hour (local)
    peakEnd: 16,          // peak window end hour (exclusive, local)
    peakWeekdaysOnly: true,
    hourSort: 'hour',     // 'hour' | 'tokens' | 'cost' | 'avg'
    theme: 'dark',        // 'dark' | 'light'
    sourceCache: {},      // id -> last good scan {ts, records, files} (mirrored in IDB)
    autoAttachDone: false, // default agent folders attached once per install
    trendMetric: 'tokens',    // 'tokens' | 'cost' | 'output' | 'requests'
    trendCumulative: false,
    budgetAmount: 0,      // 0 = no budget tracking
    budgetPeriod: 'month',// 'day' | 'week' | 'month'
    projectFilter: 'all',
    autoArchive: true,    // append new records to the archive file on scan
    archivedCount: 0      // records covered by the last archive write
  };

  // ---------- IndexedDB (persist folder handles across sessions) ----------

  var db = null;
  var DB_VERSION = 2; // v2 adds the per-source last-good-scan cache
  function openDb() {
    return new Promise(function (resolve, reject) {
      var req = indexedDB.open('tokenreport', DB_VERSION);
      req.onupgradeneeded = function () {
        var st = req.result;
        if (!st.objectStoreNames.contains('sources')) st.createObjectStore('sources', { keyPath: 'id' });
        if (!st.objectStoreNames.contains('meta')) st.createObjectStore('meta');
        if (!st.objectStoreNames.contains('cache')) st.createObjectStore('cache', { keyPath: 'id' });
      };
      req.onsuccess = function () { resolve(req.result); };
      req.onerror = function () { reject(req.error); };
    });
  }
  function idb(store, mode, fn) {
    return new Promise(function (resolve, reject) {
      var tx = db.transaction(store, mode);
      var out = fn(tx.objectStore(store));
      tx.oncomplete = function () { resolve(out && 'result' in out ? out.result : out); };
      tx.onerror = function () { reject(tx.error); };
    });
  }

  // ---------- localStorage helpers ----------

  function loadPrefs() {
    try {
      var p = JSON.parse(localStorage.getItem('tokenreport.prefs') || '{}');
      state.range = p.range || '24h';
      state.agentFilter = p.agentFilter || 'all';
      state.includeArchive = !!p.includeArchive;
      state.customFrom = p.customFrom || null;
      state.customTo = p.customTo || null;
      state.view = (p.view === 'peak' || p.view === 'mix' || p.view === 'guide') ? p.view : 'report';
      state.peakMetric = p.peakMetric || 'tokens';
      state.peakStart = Number.isFinite(p.peakStart) ? p.peakStart : 10;
      state.peakEnd = Number.isFinite(p.peakEnd) ? p.peakEnd : 16;
      state.peakWeekdaysOnly = p.peakWeekdaysOnly !== false;
      state.hourSort = p.hourSort || 'hour';
      state.theme = p.theme === 'light' ? 'light' : 'dark';
      state.trendMetric = ['tokens', 'cost', 'output', 'requests'].indexOf(p.trendMetric) !== -1 ? p.trendMetric : 'tokens';
      state.trendCumulative = !!p.trendCumulative;
      state.budgetAmount = Number.isFinite(p.budgetAmount) && p.budgetAmount >= 0 ? p.budgetAmount : 0;
      state.budgetPeriod = ['day', 'week', 'month'].indexOf(p.budgetPeriod) !== -1 ? p.budgetPeriod : 'month';
      state.projectFilter = p.projectFilter || 'all';
      state.autoArchive = p.autoArchive !== false;
      state.autoAttachDone = !!p.autoAttachDone;
    } catch (e) { /* defaults */ }
    try {
      state.prices = JSON.parse(localStorage.getItem('tokenreport.prices') || 'null') || JSON.parse(JSON.stringify(DEFAULT_PRICES));
    } catch (e) { state.prices = JSON.parse(JSON.stringify(DEFAULT_PRICES)); }
  }
  function savePrefs() {
    localStorage.setItem('tokenreport.prefs', JSON.stringify({
      range: state.range, agentFilter: state.agentFilter,
      includeArchive: state.includeArchive, customFrom: state.customFrom, customTo: state.customTo,
      view: state.view, peakMetric: state.peakMetric,
      peakStart: state.peakStart, peakEnd: state.peakEnd,
      peakWeekdaysOnly: state.peakWeekdaysOnly, hourSort: state.hourSort,
      theme: state.theme,
      trendMetric: state.trendMetric, trendCumulative: state.trendCumulative,
      budgetAmount: state.budgetAmount, budgetPeriod: state.budgetPeriod,
      projectFilter: state.projectFilter, autoArchive: state.autoArchive,
      autoAttachDone: !!state.autoAttachDone
    }));
  }

  // ---------- file system access ----------

  function fsaSupported() { return typeof window.showDirectoryPicker === 'function'; }

  function pickDirectory() {
    return window.showDirectoryPicker({ mode: 'read' });
  }

  async function walkDir(dir, path, depth, out, extRe) {
    extRe = extRe || /\.(jsonl|json)$/i;
    if (depth > 8 || out.files.length >= MAX_FILES || out.bytes > MAX_BYTES) return;
    for await (var entry of dir.values()) {
      if (out.files.length >= MAX_FILES) return;
      if (entry.kind === 'file') {
        if (extRe.test(entry.name)) {
          var f = await entry.getFile();
          out.files.push({ handle: entry, path: path + entry.name, size: f.size });
          out.bytes += f.size;
        }
      } else if (entry.kind === 'directory' && !SKIP_DIR.test(entry.name)) {
        await walkDir(entry, path + entry.name + '/', depth + 1, out, extRe);
      }
    }
  }

  // ---------- scanning + parsing ----------

  async function scanSource(src) {
    var out = { files: 0, bytes: 0, records: [], sessions: {}, errors: 0, error: null };
    try {
      // Chromium resets File System Access permissions on every browser
      // session, so a handle restored from IndexedDB comes back as 'prompt'
      // (reads would throw NotAllowedError). Detect that up front and report
      // it as reconnect-needed instead of a scan error.
      if (!src.demo && src.handle) {
        var perm0 = await src.handle.queryPermission({ mode: 'read' });
        if (perm0 !== 'granted') { src.status = 'reconnect'; out.error = 'reconnect'; return out; }
      } else if (!src.demo && !src.handle && src.serverPath) {
        // Auto-attached agent home (e.g. ~/.zcode/cli/rollout): scanned via
        // the launcher's allow-listed reader. Survives reloads because no
        // FSA handle is involved — nothing to reconnect.
        return scanServerSource(src, out);
      } else if (!src.demo && !src.handle) {
        // webkitdirectory fallback sources carry their files, not a handle —
        // they're refreshed via scanFallbackSource only. A refresh hitting
        // this path means the page lost the picked files (reload): say so
        // instead of throwing a TypeError that reads as a scan error.
        src.status = 'error';
        out.error = 're-pick the folder (browser reload cleared the file list)';
        return out;
      }
      if (src.demo) {
        if (src.agent === 'copilot') {
          var dbuf = await (await fetch(src.demoPath)).arrayBuffer();
          var pdemo = window.TR_COPILOT.parseStore(new Uint8Array(dbuf), null);
          out.files = 1;
          out.records = pdemo.records;
          Object.assign(out.sessions, pdemo.sessions);
          out.errors = pdemo.errors;
          src.status = 'ok';
          return out;
        }
        var res = await fetch(src.demoPath);
        var text = await res.text();
        var parsed = P.parseFile(text, src.agent, src.name + '/demo.jsonl');
        out.files = 1;
        out.records = parsed.records;
        Object.assign(out.sessions, parsed.sessions);
        out.errors = parsed.errors;
        src.status = 'ok';
        return out;
      }
      if (src.agent === 'copilot') {
        var w = { files: [], bytes: 0 };
        await walkDir(src.handle, '', 0, w, /\.db$|\.db-wal$/i);
        out.files = w.files.length;
        out.bytes = w.bytes;
        // Layouts differ by Copilot CLI build (OS/arch/version): the old
        // store is session-store.db[.wal], the current one is data.db[.wal].
        // Accept both, prefer the old when both exist.
        var mainF = null, walF = null, dataF = null, dataWalF = null;
        w.files.forEach(function (f) {
          var p = f.path.toLowerCase();
          if (/session-store\.db$/.test(p)) mainF = f;
          else if (/session-store\.db-wal$/.test(p)) walF = f;
          else if (/data\.db$/.test(p)) dataF = f;
          else if (/data\.db-wal$/.test(p)) dataWalF = f;
        });
        if (!mainF) { mainF = dataF; walF = dataWalF; }
        if (!mainF) {
          src.status = 'error';
          out.error = 'session-store.db / data.db not found in the picked folder';
          return out;
        }
        var mainBuf = await (await mainF.handle.getFile()).arrayBuffer();
        var walBuf = walF ? await (await walF.handle.getFile()).arrayBuffer() : null;
        var pc = window.TR_COPILOT.parseStore(new Uint8Array(mainBuf), walBuf ? new Uint8Array(walBuf) : null, mainF.path);
        out.records = pc.records;
        Object.assign(out.sessions, pc.sessions);
        out.errors = pc.errors;
        if (pc.error) out.error = pc.error;
        src.status = 'ok';
        src.files = out.files;
        return out;
      }
      var perm = await src.handle.queryPermission({ mode: 'read' });
      if (perm !== 'granted') { src.status = 'reconnect'; out.error = 'reconnect'; return out; }
      var walk = { files: [], bytes: 0 };      await walkDir(src.handle, '', 0, walk);
      out.files = walk.files.length;
      out.bytes = walk.bytes;
      for (var i = 0; i < walk.files.length; i++) {
        var fh = walk.files[i];
        try {
          var file = await fh.handle.getFile();
          if (file.size > 64 * 1024 * 1024) { out.errors++; continue; }
          var txt = await file.text();
          var p2 = P.parseFile(txt, src.parseAs || src.agent, fh.path);
          // Claude Code lays logs out per project (~/.claude/projects/<slug>/),
          // so the first path segment names the project when the log itself
          // doesn't carry one.
          if (src.agent === 'claude-code') {
            var seg = fh.path.split('/')[0];
            p2.records.forEach(function (r) { if (!r.project) r.project = seg; });
          }
          out.records.push.apply(out.records, p2.records);
          for (var k in p2.sessions) {
            if (!out.sessions[k]) out.sessions[k] = p2.sessions[k];
          }
          out.errors += p2.errors;
        } catch (e) { out.errors++; }
      }
      src.status = 'ok';
      src.files = out.files;
    } catch (e) {
      src.status = 'error';
      out.error = String(e && e.message || e);
    }
    return out;
  }

  // Server-side scan of an auto-attached agent home: /list names the files,
  // /read streams each one; both are loopback-only and allow-listed to the
  // five agent homes, so no pick/no reconnect is ever needed for these.
  async function scanServerSource(src, out) {
    try {
      var enc = encodeURIComponent(src.serverPath);
      var lr = await fetch('/__tokenreport__/list?path=' + enc);
      var listing = lr.ok ? await lr.json() : null;
      var names = listing && listing.ok ? listing.names || [] : [];
      if (!names.length) {
        src.status = 'ok';
        src.files = 0;
        out.error = null;
        return out;
      }
      for (var i = 0; i < names.length && i < MAX_FILES; i++) {
        var rel = names[i];
        var base = rel.split('/').pop();
        try {
          var rr = await fetch('/__tokenreport__/read?path=' + enc + '&file=' + encodeURIComponent(rel));
          if (!rr.ok) { out.errors++; continue; }
          if (src.agent === 'copilot') {
            var n = base.toLowerCase();
            var buf = await rr.arrayBuffer();
            if (/session-store\.db$/.test(n)) { src._copilotMain = buf; src._copilotMainName = rel; }
            else if (/session-store\.db-wal$/.test(n)) { src._copilotWal = buf; }
            else if (/data\.db$/.test(n) && !src._copilotMain) { src._copilotMain = buf; src._copilotMainName = rel; }
            else if (/data\.db-wal$/.test(n) && !src._copilotWal) { src._copilotWal = buf; }
            out.files++;
            continue;
          }
          var text = await rr.text();
          var parsed = P.parseFile(text, src.parseAs || src.agent, rel);
          out.records.push.apply(out.records, parsed.records);
          for (var k in parsed.sessions) {
            if (!out.sessions[k]) out.sessions[k] = parsed.sessions[k];
          }
          out.errors += parsed.errors;
          out.files++;
        } catch (e) { out.errors++; }
      }
      if (src.agent === 'copilot') {
        if (src._copilotMain) {
          var pc = window.TR_COPILOT.parseStore(new Uint8Array(src._copilotMain),
            src._copilotWal ? new Uint8Array(src._copilotWal) : null, src._copilotMainName);
          out.records.push.apply(out.records, pc.records);
          Object.assign(out.sessions, pc.sessions);
          out.errors += pc.errors;
          delete src._copilotMain; delete src._copilotWal; delete src._copilotMainName;
        } else {
          out.error = 'session-store.db / data.db not found in ' + src.serverPath;
        }
      }
      src.status = 'ok';
      src.files = out.files;
    } catch (e) {
      src.status = 'error';
      out.error = String(e && e.message || e);
    }
    return out;
  }

  function recordKey(r) {
    return [r.ts, r.session, r.model, r.input, r.output, r.cacheRead, r.requestId].join('|');
  }

  async function refreshAll() {
    if (state.scanning) return;
    state.scanning = true;
    setStatus('Scanning sources…', true);
    var all = [];
    var tasks = {};
    var fileCount = 0, errCount = 0, demo = false, stale = 0;
    var srcResults = [];
    var staleNoCache = 0;
    for (var i = 0; i < state.sources.length; i++) {
      var src = state.sources[i];
      var res = await scanSource(src);
      // A source that lost folder access (browser restart) must not erase its
      // data: fall back to the last good scan from the IDB cache so the
      // report survives restarts, and just flag the source as stale.
      if (src.status !== 'ok' && !src.demo && state.sourceCache[src.id]) {
        var cached = state.sourceCache[src.id];
        res.records = cached.records;
        res.files = cached.files;
        res.cached = true;
      } else if (src.status === 'ok' && !src.demo) {
        var entry = { id: src.id, ts: Date.now(), records: res.records, files: res.files };
        state.sourceCache[src.id] = entry;
        idb('cache', 'readwrite', function (st) { st.put(entry); return {}; })
          .catch(function () { /* cache write failures are non-fatal */ });
      }
      if (src.status !== 'ok' && !src.demo) {
        stale++;
        if (!state.sourceCache[src.id]) staleNoCache++;
      }
      else { src.lastScan = Date.now(); src.recCount = res.records.length; }
      fileCount += res.files;
      errCount += res.errors;
      if (src.demo) demo = true;
      srcResults.push({ src: src, res: res });
    }
    // session→task labels must be global before assigning to records
    srcResults.forEach(function (sr) {
      for (var k in sr.res.sessions) {
        var key = sr.src.agent + ':' + k;
        if (!tasks[key]) tasks[key] = sr.res.sessions[k];
      }
    });
    srcResults.forEach(function (sr) {
      sr.res.records.forEach(function (r) {
        r.agent = sr.src.agent;
        r.source = sr.src.name;
        r.task = tasks[sr.src.agent + ':' + r.session] || r.task || '';
      });
      all.push.apply(all, sr.res.records);
    });
    // archive (older, saved history) — kept across refresh failures: if the
    // archive file's permission is pending this round, keep showing the last
    // copy in memory instead of silently dropping the history from the view.
    var archived = 0;
    if (state.includeArchive && state.archiveHandle) {
      try {
        var perm = await state.archiveHandle.queryPermission({ mode: 'read' });
        if (perm !== 'granted') perm = await state.archiveHandle.requestPermission({ mode: 'read' });
        if (perm === 'granted') {
          var af = await state.archiveHandle.getFile();
          var at = await af.text();
          var parsedA = P.parseFile(at, 'auto', 'archive.jsonl');
          parsedA.records.forEach(function (r) {
            r.agent = r.agentType;
            r.source = 'archive';
          });
          state.lastArchiveRecords = parsedA.records;
          archived = parsedA.records.length;
          all.push.apply(all, parsedA.records);
        } else if (state.lastArchiveRecords) {
          archived = state.lastArchiveRecords.length;
          all.push.apply(all, state.lastArchiveRecords);
        }
      } catch (e) {
        if (state.lastArchiveRecords) {
          archived = state.lastArchiveRecords.length;
          all.push.apply(all, state.lastArchiveRecords);
        }
      }
    }
    // dedup (live + archive overlap)
    var seen = {};
    state.records = all.filter(function (r) {
      var k = recordKey(r);
      if (seen[k]) return false;
      seen[k] = true;
      return true;
    });
    state.sessionTasks = tasks;
    state.lastRefresh = new Date();
    state.scanning = false;
    setStatus((state.records.length ? state.records.length.toLocaleString() + ' requests' : 'no records') +
      ' · ' + fileCount + ' files' + (archived ? ' · ' + archived + ' archived' : '') +
      (errCount ? ' · ' + errCount + ' unparseable lines' : '') +
      (stale ? ' · ' + stale + ' source' + (stale > 1 ? 's' : '') + ' need reconnect' +
        (stale === staleNoCache ? '' : ' (cached data shown)') : '') +
      (demo ? ' · DEMO data' : '') +
      ' · refreshed ' + state.lastRefresh.toLocaleTimeString(), false);
    updateReconnectBanner(stale, staleNoCache);
    renderSources();
    render();
    autoArchiveIfNew();
  }

    // Keep the archive file current without manual saves: whenever the live
    // record set grew past what was last archived, append the new records
    // (saveToArchive dedups against the file content itself). A null return
    // means the archive wasn't writable this round (permission pending) —
    // leave archivedCount alone so it retries once access is restored.
    async function autoArchiveIfNew() {
      if (!state.autoArchive || !state.archiveHandle || state.scanning) return;
      if (state.records.length <= state.archivedCount) return;
      try {
        var added = await saveToArchive(true);
        if (added != null) state.archivedCount = state.records.length;
      } catch (e) { /* archive write failure stays silent; manual save still works */ }
    }

  // Show the one-click "Restore access" banner whenever any live source needs
  // its folder permission re-granted (Chromium drops FSA grants per session).
  function updateReconnectBanner(stale, staleNoCache) {
    var bn = $('#reconnectBanner');
    if (!bn) return;
    var n = state.sources.filter(function (s) {
      return !s.demo && s.handle && s.status !== 'ok';
    }).length; // serverPath (auto) sources never need reconnect
    if (n) {
      $('#reconnectMsg').textContent =
        n + ' source' + (n > 1 ? 's' : '') + ' lost folder access (browser restart) — ' +
        (staleNoCache
          ? 'click restore and pick the folders again if prompted; data returns on reconnect.'
          : 'the report below is the last cached scan.') +
        (EMBEDDED ? ' Folder prompts cannot appear inside an embedded dashboard tab — open this app in its own window or a browser tab to restore.' : '');
      bn.hidden = false;
    } else {
      bn.hidden = true;
    }
  }

  async function reconnectAll() {
    // requestPermission needs a user gesture; run every source's grant inside
    // this single click's activation, then rescan. Auto-attached (serverPath)
    // sources need no permission at all — refreshAll re-reads them directly.
    var granted = 0, denied = 0, blocked = 0;
    for (var i = 0; i < state.sources.length; i++) {
      var s = state.sources[i];
      if (s.demo || s.serverPath || !s.handle || s.status === 'ok') continue;
      try {
        var p = await s.handle.requestPermission({ mode: 'read' });
        if (p === 'granted') { granted++; s.status = 'ok'; }
        else if (EMBEDDED) blocked++; // prompt could not show inside the frame
        else denied++;
      } catch (e) {
        // Browsers refuse folder prompts inside cross-origin frames (the
        // dashboard's embedded tab) — report that instead of staying silent.
        if (EMBEDDED || (e && (e.name === 'SecurityError' || /cross.origin/i.test(e.message || '')))) blocked++;
        else denied++; // dismissed — stays stale, cached data remains shown
      }
    }
    await refreshAll();
    if (blocked) {
      toast('Folder prompts cannot appear inside an embedded dashboard tab — open Token Report in its own window (🪟) or a browser tab (🌐) and click Restore there.');
    } else if (granted && !denied) {
      toast('Folder access restored — fresh data loaded. Pick “Allow on every visit” when prompted to keep it across browser restarts.');
    } else if (denied) {
      toast('Folder access wasn\u2019t granted for ' + denied + ' source' + (denied > 1 ? 's' : '') + ' — showing the last cached scan.');
    }
  }

  // ---------- pricing ----------

  function priceFor(model) {
    var m = String(model || '').toLowerCase();
    var best = state.prices['default'] || { input: 0.6, output: 2.2, cacheReadRatio: 0.1, cacheWriteRatio: 1.25 };
    var bestLen = 0;
    for (var k in state.prices) {
      if (k === '_help' || k === 'default') continue;
      if (m.indexOf(k.toLowerCase()) !== -1 && k.length > bestLen) { best = state.prices[k]; bestLen = k.length; }
    }
    return best;
  }

  function renderPriceEditor() {
    var box = $('#priceTable');
    if (!box) return;
    var keys = Object.keys(state.prices).filter(function (k) { return k !== '_help'; }).sort();
    box.innerHTML = '<table class="report price-tbl"><thead><tr>' +
      '<th>Model match</th><th class="num">In $/M</th><th class="num">Out $/M</th>' +
      '<th class="num">Cache read ×</th><th class="num">Cache write ×</th><th></th></tr></thead><tbody>' +
      keys.map(function (k) {
        var p = state.prices[k];
        return '<tr>' +
          '<td><input class="pin" data-f="k" value="' + esc(k) + '" spellcheck="false"></td>' +
          '<td><input class="pin num" data-f="input" type="number" step="0.05" min="0" value="' + (+p.input || 0) + '"></td>' +
          '<td><input class="pin num" data-f="output" type="number" step="0.05" min="0" value="' + (+p.output || 0) + '"></td>' +
          '<td><input class="pin num" data-f="cacheReadRatio" type="number" step="0.05" min="0" value="' + (p.cacheReadRatio != null ? p.cacheReadRatio : 0.1) + '"></td>' +
          '<td><input class="pin num" data-f="cacheWriteRatio" type="number" step="0.05" min="0" value="' + (p.cacheWriteRatio != null ? p.cacheWriteRatio : 1.25) + '"></td>' +
          '<td><button class="btn small danger pdel" data-k="' + esc(k) + '" title="Remove">✕</button></td>' +
          '</tr>';
      }).join('') + '</tbody></table>';
    $$('#priceTable .pdel').forEach(function (b) {
      b.onclick = function () { delete state.prices[b.getAttribute('data-k')]; renderPriceEditor(); };
    });
  }

  function collectPrices() {
    var out = {};
    $$('#priceTable tbody tr').forEach(function (tr) {
      var k = (tr.querySelector('[data-f="k"]').value || '').trim();
      if (!k) return;
      out[k] = {
        input: Number(tr.querySelector('[data-f="input"]').value) || 0,
        output: Number(tr.querySelector('[data-f="output"]').value) || 0,
        cacheReadRatio: Number(tr.querySelector('[data-f="cacheReadRatio"]').value),
        cacheWriteRatio: Number(tr.querySelector('[data-f="cacheWriteRatio"]').value)
      };
    });
    if (!Object.keys(out).length) return JSON.parse(JSON.stringify(DEFAULT_PRICES));
    if (!out['default']) out['default'] = JSON.parse(JSON.stringify(DEFAULT_PRICES['default']));
    return out;
  }

  function costOf(r) {
    var p = priceFor(r.model);
    return (r.input * p.input +
      r.output * p.output +
      r.cacheRead * p.input * (p.cacheReadRatio != null ? p.cacheReadRatio : 0.1) +
      r.cacheWrite * p.input * (p.cacheWriteRatio != null ? p.cacheWriteRatio : 1.25)) / 1e6;
  }

  // ---------- filtering ----------

  function rangeWindow() {
    var now = Date.now();
    var r = RANGES.find(function (x) { return x.id === state.range; }) || RANGES[3];
    if (r.id === 'all') return { from: null, to: null };
    if (r.id === 'custom') {
      var from = state.customFrom ? Date.parse(state.customFrom) : null;
      var to = state.customTo ? Date.parse(state.customTo) : null;
      return { from: isNaN(from) ? null : from, to: isNaN(to) ? null : to };
    }
    return { from: now - r.ms, to: null };
  }

  function filteredRecords() {
    var w = rangeWindow();
    return state.records.filter(function (r) {
      if (state.agentFilter !== 'all' && r.agent !== state.agentFilter) return false;
      if (state.projectFilter !== 'all' && (r.project || '') !== state.projectFilter) return false;
      if (w.from != null && (r.ts == null || r.ts < w.from)) return false;
      if (w.to != null && (r.ts == null || r.ts > w.to)) return false;
      return true;
    });
  }

  // ---------- aggregation ----------

  function aggregate(recs) {
    var agg = {
      total: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, cost: 0, requests: 0 },
      byTask: {},   // agent:session -> {task, input, output, cacheRead, cacheWrite, cost, requests, models:{}}
      byModel: {},
      byAgent: {},
      byProject: {},
      latest: 0, earliest: Infinity
    };
    recs.forEach(function (r) {
      var c = costOf(r);
      var aiu = r.aiu || 0;
      agg.total.input += r.input; agg.total.output += r.output;
      agg.total.cacheRead += r.cacheRead; agg.total.cacheWrite += r.cacheWrite;
      agg.total.cost += c; agg.total.requests++;
      agg.total.aiu = (agg.total.aiu || 0) + aiu;
      if (r.ts) { if (r.ts > agg.latest) agg.latest = r.ts; if (r.ts < agg.earliest) agg.earliest = r.ts; }
      var tk = (r.agent || 'unknown') + ':' + (r.session || 'unknown');
      var t = agg.byTask[tk] || (agg.byTask[tk] = {
        key: tk, agent: r.agent, session: r.session, task: r.task || '(unlabeled session)',
        input: 0, output: 0, cacheRead: 0, cacheWrite: 0, cost: 0, requests: 0, models: {}, last: 0, aiu: 0
      });
      t.input += r.input; t.output += r.output; t.cacheRead += r.cacheRead; t.cacheWrite += r.cacheWrite;
      t.cost += c; t.requests++; t.aiu += aiu;
      t.models[r.model] = (t.models[r.model] || 0) + 1;
      if (r.ts && r.ts > t.last) t.last = r.ts;
      t.effectiveTokens = t.input + t.output + t.cacheRead + t.cacheWrite;
      var mo = agg.byModel[r.model] || (agg.byModel[r.model] = { model: r.model, input: 0, output: 0, cacheRead: 0, cacheWrite: 0, cost: 0, requests: 0, aiu: 0 });
      mo.input += r.input; mo.output += r.output; mo.cacheRead += r.cacheRead; mo.cacheWrite += r.cacheWrite;
      mo.cost += c; mo.requests++; mo.aiu += aiu;
      var ag = agg.byAgent[r.agent] || (agg.byAgent[r.agent] = { agent: r.agent, tokens: 0, cost: 0, requests: 0, aiu: 0 });
      ag.tokens += r.input + r.output + r.cacheRead + r.cacheWrite;
      ag.cost += c; ag.requests++; ag.aiu += aiu;
      var pk = r.project || '';
      var pj = agg.byProject[pk] || (agg.byProject[pk] = {
        project: pk || '(no project)', input: 0, output: 0, cacheRead: 0, cacheWrite: 0,
        cost: 0, requests: 0, sessions: {}
      });
      pj.input += r.input; pj.output += r.output; pj.cacheRead += r.cacheRead; pj.cacheWrite += r.cacheWrite;
      pj.cost += c; pj.requests++;
      pj.sessions[tk] = true;
      pj.effectiveTokens = pj.input + pj.output + pj.cacheRead + pj.cacheWrite;
    });
    agg.tasks = Object.values(agg.byTask).sort(function (a, b) { return b.effectiveTokens - a.effectiveTokens; });
    agg.models = Object.values(agg.byModel).sort(function (a, b) {
      return (b.input + b.output + b.cacheRead + b.cacheWrite) - (a.input + a.output + a.cacheRead + a.cacheWrite);
    });
    agg.agents = Object.values(agg.byAgent).sort(function (a, b) { return b.tokens - a.tokens; });
    agg.projects = Object.values(agg.byProject).sort(function (a, b) { return b.effectiveTokens - a.effectiveTokens; });
    Object.keys(agg.byProject).forEach(function (k) { agg.byProject[k].sessions = Object.keys(agg.byProject[k].sessions).length; });
    return agg;
  }

  // ---------- formatting ----------

  function fmt(n) {
    if (n == null || isNaN(n)) return '—';
    if (n >= 1e9) return (n / 1e9).toFixed(2) + 'B';
    if (n >= 1e6) return (n / 1e6).toFixed(2) + 'M';
    if (n >= 1e3) return (n / 1e3).toFixed(1) + 'k';
    return String(Math.round(n));
  }
  function fmtMoney(n) {
    if (n == null || isNaN(n)) return '—';
    if (n >= 1) return '$' + n.toFixed(2);
    if (n >= 0.01) return '$' + n.toFixed(3);
    return '$' + n.toFixed(4);
  }
  // Copilot billing units: total_nano_aiu is 1e-9 AIU per unit
  function fmtAiu(nano) {
    if (!nano || isNaN(nano)) return '';
    var aiu = nano / 1e9;
    if (aiu >= 100) return aiu.toFixed(0) + ' AIU';
    if (aiu >= 1) return aiu.toFixed(2) + ' AIU';
    return aiu.toFixed(3) + ' AIU';
  }
  function localTzLabel() {
    var tz = 'local time';
    try { tz = Intl.DateTimeFormat().resolvedOptions().timeZone || tz; } catch (e) { /* keep */ }
    var off = -new Date().getTimezoneOffset();
    var sign = off >= 0 ? '+' : '-';
    var h = Math.floor(Math.abs(off) / 60), m = Math.abs(off) % 60;
    return tz + ' (UTC' + sign + h + (m ? ':' + String(m).padStart(2, '0') : '') + ')';
  }
  function fmtTime(ts) {
    if (!ts) return '—';
    var d = new Date(ts);
    var now = new Date();
    var sameDay = d.toDateString() === now.toDateString();
    return sameDay ? d.toLocaleTimeString() : d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  // ---------- rendering ----------

  function setStatus(msg, busy) {
    var el = $('#status');
    el.textContent = msg;
    el.classList.toggle('busy', !!busy);
  }

  function renderSources() {
    var box = $('#sourceList');
    if (!state.sources.length) {
      box.innerHTML = '<div class="empty">No sources yet. Click <b>+ Add source</b> and point it at an agent\'s log folder.</div>';
      return;
    }
    box.innerHTML = state.sources.map(function (s) {
      var status = s.status === 'reconnect'
        ? '<span class="tag warn">reconnect needed</span>'
        : s.status === 'error' ? '<span class="tag err">error</span>'
        : '<span class="tag ok">' + (s.files != null ? s.files + ' files' : 'ready') + '</span>';
      return '<div class="source" data-id="' + esc(s.id) + '">' +
        '<div class="source-main"><b>' + esc(s.name) + '</b> <span class="muted">' + esc(AGENT_NAMES[s.agent] || s.agent) + (s.demo ? ' · demo' : '') + '</span>' +
        (s.lastScan ? '<div class="muted small">' + (s.recCount != null ? fmt(s.recCount) + ' records · last scan ' + new Date(s.lastScan).toLocaleTimeString() : '') + '</div>' : '') +
        '</div>' +
        '<div class="source-side">' + status +
        (s.demo ? '' : '<button class="btn small reconnect" data-id="' + esc(s.id) + '">Reconnect</button>') +
        '<button class="btn small danger remove" data-id="' + esc(s.id) + '">Remove</button></div>' +
        '</div>';
    }).join('');
    $$('#sourceList .remove').forEach(function (b) {
      b.onclick = async function () {
        var id = b.getAttribute('data-id');
        state.sources = state.sources.filter(function (s) { return s.id !== id; });
        delete state.sourceCache[id];
        await idb('sources', 'readwrite', function (st) { st.delete(id); return {}; });
        await idb('cache', 'readwrite', function (st) { st.delete(id); return {}; });
        renderSources(); refreshAll();
      };
    });
    $$('#sourceList .reconnect').forEach(function (b) {
      b.onclick = async function () {
        var s = state.sources.find(function (x) { return x.id === b.getAttribute('data-id'); });
        if (s && s.handle) {
          var p = await s.handle.requestPermission({ mode: 'read' });
          if (p === 'granted') { s.status = 'ok'; refreshAll(); }
        }
      };
    });
  }

  function kpiCard(label, value, sub, cls) {
    return '<div class="kpi ' + (cls || '') + '"><div class="kpi-label">' + label + '</div>' +
      '<div class="kpi-value">' + value + '</div>' +
      (sub ? '<div class="kpi-sub">' + sub + '</div>' : '') + '</div>';
  }

  function renderKpis(agg, recs) {
    var t = agg.total;
    var effective = t.input + t.output + t.cacheRead + t.cacheWrite;
    var top = agg.tasks[0];
    var cachePct = effective ? Math.round(100 * t.cacheRead / effective) : 0;
    var peak = peakHour(recs, 'tokens');
    $('#kpis').innerHTML =
      kpiCard('Total tokens', fmt(effective), 'input+output+cache' +
        deltaSub(prevPeriodDelta(recs, function (r) { return r.input + r.output + r.cacheRead + r.cacheWrite; }))) +
      kpiCard('Est. cost', fmtMoney(t.cost), 'from editable prices' +
        deltaSub(prevPeriodDelta(recs, costOf)), 'accent') +
      budgetCard(recs) +
      kpiCard('Requests', fmt(t.requests), recs.length ? new Date(agg.earliest === Infinity ? Date.now() : agg.earliest).toLocaleString() + ' → ' + (agg.latest ? new Date(agg.latest).toLocaleTimeString() : '') : '') +
      kpiCard('Cache reads', fmt(t.cacheRead), cachePct + '% of all tokens (cheap)') +
      kpiCard('Output', fmt(t.output), 'the expensive side') +
      kpiCard('🔥 Top task', top ? esc(trunc(top.task, 34)) : '—', top ? fmt(top.effectiveTokens) + ' tokens · ' + fmtMoney(top.cost) + ' · ' + esc(top.agent) : 'no data', 'accent') +
      kpiCard('⏰ Peak hour', peak ? peak.label : '—', peak ? fmt(peak.tokens) + ' tokens · ' + localTzLabel() : 'no data yet') +
      (t.aiu ? kpiCard('Copilot credits', fmtAiu(t.aiu), 'from Copilot CLI usage events') : '');
  }

  // ---------- budget + period-over-period deltas ----------

  // % change of a metric vs the equally-long window immediately before the
  // selected range. null when the range is open-ended or there's no history.
  function prevPeriodDelta(recs, fn) {
    var w = rangeWindow();
    if (w.from == null) return null;
    var to = w.to != null ? w.to : Date.now();
    var cur = 0, prev = 0;
    recs.forEach(function (r) {
      if (!r.ts) return;
      if (r.ts >= w.from && r.ts <= to) cur += fn(r);
      else if (r.ts >= w.from - (to - w.from) && r.ts < w.from) prev += fn(r);
    });
    if (!prev) return null;
    return Math.round(100 * (cur - prev) / prev);
  }

  function deltaSub(pct) {
    if (pct == null) return '';
    var up = pct >= 0;
    return ' · <span style="color:' + (up ? 'var(--danger)' : 'var(--accent2)') + '">' +
      (up ? '▲' : '▼') + ' ' + Math.abs(pct) + '% vs prev</span>';
  }

  function budgetCard(recs) {
    if (!(state.budgetAmount > 0)) return '';
    var now = new Date();
    var start, end;
    if (state.budgetPeriod === 'day') {
      start = new Date(now.getFullYear(), now.getMonth(), now.getDate());
      end = new Date(start.getTime() + 86400e3);
    } else if (state.budgetPeriod === 'week') {
      start = new Date(now.getFullYear(), now.getMonth(), now.getDate());
      start.setDate(start.getDate() - ((start.getDay() + 6) % 7)); // Monday
      end = new Date(start.getTime() + 7 * 86400e3);
    } else {
      start = new Date(now.getFullYear(), now.getMonth(), 1);
      end = new Date(now.getFullYear(), now.getMonth() + 1, 1);
    }
    var spent = 0;
    recs.forEach(function (r) { if (r.ts && r.ts >= start.getTime() && r.ts < end.getTime()) spent += costOf(r); });
    var pct = Math.min(999, Math.round(100 * spent / state.budgetAmount));
    // pace: average daily cost across the last 7 days of data
    var wCost = 0, wStart = now.getTime() - 7 * 86400e3;
    state.records.forEach(function (r) { if (r.ts && r.ts >= wStart) wCost += costOf(r); });
    var forecast = spent + (wCost / 7) * Math.max(0, (end.getTime() - now.getTime()) / 86400e3);
    var cls = pct >= 100 ? 'err' : pct >= 80 ? 'warn' : '';
    return kpiCard('Budget · ' + state.budgetPeriod, fmtMoney(spent) + ' / ' + fmtMoney(state.budgetAmount),
      pct + '% used · pace → ' + fmtMoney(forecast) + ' by ' + end.toLocaleDateString([], { month: 'short', day: 'numeric' }), cls);
  }

  // ---------- token mix (individual kinds) ----------

  var MIX_KINDS = [
    { k: 'input', label: 'Input', color: 'rgba(88, 166, 255, .92)', hint: 'fresh prompt + context tokens' },
    { k: 'output', label: 'Output', color: 'rgba(63, 185, 80, .92)', hint: 'generated tokens — the expensive side' },
    { k: 'cacheRead', label: 'Cache read', color: 'rgba(210, 153, 34, .92)', hint: 'reused context · roughly 10× cheaper' },
    { k: 'cacheWrite', label: 'Cache write', color: 'rgba(248, 81, 73, .88)', hint: 'first-time context written to the cache' }
  ];

  function renderMix(agg) {
    var t = agg.total;
    var total = t.input + t.output + t.cacheRead + t.cacheWrite;
    $('#mixKpis').innerHTML = MIX_KINDS.map(function (k) {
      var v = t[k.k] || 0;
      var pct = total ? Math.round(100 * v / total) : 0;
      return kpiCard(k.label, fmt(v), pct + '% of all tokens · ' + k.hint);
    }).join('') + kpiCard('Total (combined)', fmt(total), fmt(t.requests) + ' requests · ' + fmtMoney(t.cost), 'accent');

    if (!total) {
      $('#mixSplit').innerHTML = '<span class="muted small">No data in this range.</span>';
      $('#mixLegend').innerHTML = '';
    } else {
      $('#mixSplit').innerHTML = MIX_KINDS.map(function (k) {
        var pct = 100 * (t[k.k] || 0) / total;
        return '<div style="width:' + pct + '%;background:' + k.color + '" title="' + k.label + ': ' + fmt(t[k.k] || 0) + ' (' + Math.round(pct) + '%)"></div>';
      }).join('');
      $('#mixLegend').innerHTML = MIX_KINDS.map(function (k) {
        return '<span><span class="sw" style="background:' + k.color + '"></span>' +
          k.label + ' ' + Math.round(100 * (t[k.k] || 0) / total) + '%</span>';
      }).join('');
    }

    var maxT = agg.tasks.length ? agg.tasks[0].effectiveTokens : 1;
    $('#mixTasksBody').innerHTML = agg.tasks.slice(0, 25).map(function (x, i) {
      var tot = x.effectiveTokens;
      return '<tr>' +
        '<td class="num">' + (i + 1) + '</td>' +
        '<td><div class="task-name" title="' + esc(x.task) + '">' + esc(trunc(x.task, 90)) + '</div>' +
        '<div class="muted small">' + esc(x.agent) + ' · last ' + fmtTime(x.last) + '</div></td>' +
        '<td class="num">' + fmt(x.input) + '</td>' +
        '<td class="num">' + fmt(x.output) + '</td>' +
        '<td class="num">' + fmt(x.cacheRead) + '</td>' +
        '<td class="num">' + fmt(x.cacheWrite) + '</td>' +
        '<td class="num">' + fmt(tot) + '</td>' +
        '<td>' + bar(100 * tot / maxT) + '</td>' +
        '</tr>';
    }).join('') || '<tr><td colspan="8" class="empty">No data in this range</td></tr>';

    var maxM = agg.models.length ? (agg.models[0].input + agg.models[0].output + agg.models[0].cacheRead + agg.models[0].cacheWrite) : 1;
    $('#mixModelsBody').innerHTML = agg.models.slice(0, 25).map(function (m) {
      var tot = m.input + m.output + m.cacheRead + m.cacheWrite;
      return '<tr>' +
        '<td>' + esc(m.model) + '</td>' +
        '<td class="num">' + fmt(m.input) + '</td>' +
        '<td class="num">' + fmt(m.output) + '</td>' +
        '<td class="num">' + fmt(m.cacheRead) + '</td>' +
        '<td class="num">' + fmt(m.cacheWrite) + '</td>' +
        '<td class="num">' + fmt(tot) + '</td>' +
        '<td>' + bar(100 * tot / maxM) + '</td>' +
        '</tr>';
    }).join('') || '<tr><td colspan="7" class="empty">No data in this range</td></tr>';
  }

  // ---------- peak-hours aggregation (local time) ----------

  function metricValue(r, metric) {
    if (metric === 'cost') return costOf(r);
    if (metric === 'output') return r.output;
    if (metric === 'requests') return 1;
    return r.input + r.output + r.cacheRead + r.cacheWrite;
  }
  var METRIC_LABEL = { tokens: 'tokens', cost: 'est. cost', output: 'output tokens', requests: 'requests' };

  function peakHour(recs, metric) {
    var byHour = new Array(24).fill(0);
    var byCost = new Array(24).fill(0);
    var byReq = new Array(24).fill(0);
    recs.forEach(function (r) {
      if (r.ts == null) return;
      var h = new Date(r.ts).getHours();
      byHour[h] += r.input + r.output + r.cacheRead + r.cacheWrite;
      byCost[h] += costOf(r);
      byReq[h] += 1;
    });
    var vals = metric === 'cost' ? byCost : metric === 'requests' ? byReq : byHour;
    var best = -1, bestV = 0;
    for (var h = 0; h < 24; h++) if (vals[h] > bestV) { bestV = vals[h]; best = h; }
    if (best < 0) return null;
    return {
      hour: best,
      label: String(best).padStart(2, '0') + ':00–' + String((best + 1) % 24).padStart(2, '0') + ':00',
      tokens: byHour[best], cost: byCost[best], requests: byReq[best]
    };
  }

  function renderPeak(recs) {
    var metric = state.peakMetric || 'tokens';
    var byHour = new Array(24).fill(0);
    var byCost = new Array(24).fill(0);
    var byReq = new Array(24).fill(0);
    var byWeek = []; // 7 (Mon-first) × 24, tokens
    for (var w = 0; w < 7; w++) byWeek.push(new Array(24).fill(0));
    var weekCost = [], weekReq = [];
    for (w = 0; w < 7; w++) { weekCost.push(new Array(24).fill(0)); weekReq.push(new Array(24).fill(0)); }
    recs.forEach(function (r) {
      if (r.ts == null) return;
      var d = new Date(r.ts);
      var h = d.getHours();
      var wd = (d.getDay() + 6) % 7; // Mon=0..Sun=6
      byHour[h] += r.input + r.output + r.cacheRead + r.cacheWrite;
      byCost[h] += costOf(r);
      byReq[h] += 1;
      byWeek[wd][h] += r.input + r.output + r.cacheRead + r.cacheWrite;
      weekCost[wd][h] += costOf(r);
      weekReq[wd][h] += 1;
    });
    var vals = byHour, weekVals = byWeek;
    if (metric === 'cost') { vals = byCost; weekVals = weekCost; }
    else if (metric === 'requests') { vals = byReq; weekVals = weekReq; }

    var max = Math.max.apply(null, vals);
    $('#hourChart').innerHTML = vals.map(function (v, h) {
      var pct = max ? Math.round(100 * v / max) : 0;
      return '<div class="tbar' + (v === max && max > 0 ? ' peakbar' : '') + '" title="' +
        String(h).padStart(2, '0') + ':00–' + String((h + 1) % 24).padStart(2, '0') + ':00 — ' +
        fmt(byHour[h]) + ' tokens · ' + fmtMoney(byCost[h]) + ' · ' + byReq[h] + ' requests">' +
        '<div class="tbar-fill' + (v === max && max > 0 ? ' peakfill' : '') + '" style="height:' + pct + '%"></div></div>';
    }).join('');
    $('#hourLabels').innerHTML = vals.map(function (_, h) {
      return '<span>' + (h % 3 === 0 ? String(h).padStart(2, '0') : '') + '</span>';
    }).join('');
    $('#tzLabel').textContent = 'Times bucketed in ' + localTzLabel();

    var ranked = vals.map(function (v, h) { return { h: h, v: v, tokens: byHour[h], cost: byCost[h], requests: byReq[h] }; })
      .filter(function (x) { return x.v > 0; })
      .sort(function (a, b) { return b.v - a.v; });
    if (!ranked.length) {
      $('#peakCallout').innerHTML = '<span class="muted">No data in this range.</span>';
    } else {
      var rows = ranked.slice(0, 3).map(function (x, i) {
        return '<div class="peak-row' + (i === 0 ? ' top' : '') + '">' +
          '<span class="peak-rank">' + (i + 1) + '</span>' +
          '<b>' + String(x.h).padStart(2, '0') + ':00–' + String((x.h + 1) % 24).padStart(2, '0') + ':00</b>' +
          '<span>' + fmt(x.tokens) + ' tokens · ' + fmtMoney(x.cost) + ' · ' + x.requests + ' requests</span>' +
          '</div>';
      }).join('');
      $('#peakCallout').innerHTML = '<div class="peak-main">🔥 Peak hour: <b>' +
        String(ranked[0].h).padStart(2, '0') + ':00–' + String((ranked[0].h + 1) % 24).padStart(2, '0') + ':00</b> — ' +
        fmt(ranked[0].tokens) + ' tokens · ' + fmtMoney(ranked[0].cost) + ' · ' + ranked[0].requests + ' requests</div>' + rows;
    }

    var wMax = 0;
    weekVals.forEach(function (row) { row.forEach(function (v) { if (v > wMax) wMax = v; }); });
    var dayNames = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
    var html = '<div class="heat-row heat-head"><span class="heat-day"></span>' +
      vals.map(function (_, h) { return '<span class="heat-hour">' + (h % 3 === 0 ? String(h).padStart(2, '0') : '') + '</span>'; }).join('') +
      '</div>';
    for (var d = 0; d < 7; d++) {
      html += '<div class="heat-row"><span class="heat-day">' + dayNames[d] + '</span>';
      for (var hh = 0; hh < 24; hh++) {
        var v = weekVals[d][hh];
        var alpha = v && wMax ? (0.07 + 0.93 * Math.sqrt(v / wMax)) : 0;
        html += '<span class="heat-cell" style="background:' + (alpha ? 'rgba(240,136,62,' + alpha.toFixed(3) + ')' : 'transparent') + '" title="' +
          dayNames[d] + ' ' + String(hh).padStart(2, '0') + ':00–' + String((hh + 1) % 24).padStart(2, '0') + ':00 — ' +
          fmt(byWeek[d][hh]) + ' tokens · ' + fmtMoney(weekCost[d][hh]) + ' · ' + weekReq[d][hh] + ' requests"></span>';
      }
      html += '</div>';
    }
    $('#heatGrid').innerHTML = html;
    renderPeakTables(recs);
  }

  // ---------- peak vs off-peak + hourly breakdown tables ----------

  function inPeakWindow(d) {
    if (state.peakWeekdaysOnly) {
      var wd = d.getDay();
      if (wd === 0 || wd === 6) return false;
    }
    var h = d.getHours(), s = state.peakStart, e = state.peakEnd;
    if (s === e) return true; // degenerate window = all hours
    return s < e ? (h >= s && h < e) : (h >= s || h < e);
  }

  function peakDefLabel() {
    var fmtH = function (h) { return String(h).padStart(2, '0') + ':00'; };
    return (state.peakWeekdaysOnly ? 'Weekdays ' : 'All days ') +
      fmtH(state.peakStart) + '–' + fmtH(state.peakEnd) + ' · ' + localTzLabel();
  }

  function blankBucket() {
    return { requests: 0, tokens: 0, cached: 0, output: 0, cost: 0, aiu: 0 };
  }
  function addToBucket(b, r) {
    b.requests++;
    b.tokens += r.input + r.output + r.cacheRead + r.cacheWrite;
    b.cached += r.cacheRead;
    b.output += r.output;
    b.cost += costOf(r);
    b.aiu += r.aiu || 0;
  }

  function renderPeakTables(recs) {
    var peak = blankBucket(), off = blankBucket();
    var hourly = [];
    for (var h = 0; h < 24; h++) hourly.push(blankBucket());
    var hourlyHasPeak = new Array(24).fill(false);
    recs.forEach(function (r) {
      if (r.ts == null) return;
      var d = new Date(r.ts);
      var isPeak = inPeakWindow(d);
      addToBucket(isPeak ? peak : off, r);
      addToBucket(hourly[d.getHours()], r);
      if (isPeak) hourlyHasPeak[d.getHours()] = true;
    });

    $('#peakDefLabel').textContent = peakDefLabel();

    // summary: peak vs off-peak
    var rowHtml = function (name, b, cls) {
      var avgTok = b.requests ? b.tokens / b.requests : 0;
      var avgCost = b.requests ? b.cost / b.requests : 0;
      return '<tr' + (cls ? ' class="' + cls + '"' : '') + '>' +
        '<td>' + name + '</td>' +
        '<td class="num">' + b.requests + '</td>' +
        '<td class="num">' + fmt(b.tokens) + '</td>' +
        '<td class="num">' + fmtMoney(b.cost) + '</td>' +
        '<td class="num">' + (b.requests ? fmt(avgTok) : '—') + '</td>' +
        '<td class="num">' + (b.requests ? fmtMoney(avgCost) : '—') + '</td>' +
        '<td class="num">' + (b.aiu ? fmtAiu(b.aiu) : '—') + '</td>' +
        '</tr>';
    };
    $('#peakSplitBody').innerHTML =
      rowHtml('🔺 Peak', peak, 'peak-row-tr') +
      rowHtml('🔻 Off-peak', off, '');

    // delta sentence
    var deltaEl = $('#peakDelta');
    if (peak.requests && off.requests) {
      var pct = Math.round((peak.tokens / peak.requests / (off.tokens / off.requests) - 1) * 100);
      var pctCost = Math.round((peak.cost / peak.requests / (off.cost / off.requests) - 1) * 100);
      deltaEl.textContent = 'Peak-hour requests average ' + (pct >= 0 ? '+' : '') + pct +
        '% tokens and ' + (pctCost >= 0 ? '+' : '') + pctCost + '% est. cost per request vs off-peak.';
    } else if (peak.requests || off.requests) {
      deltaEl.textContent = 'No requests in the ' + (peak.requests ? 'off-peak' : 'peak') +
        ' window for this range — widen the range or the window to compare.';
    } else {
      deltaEl.textContent = '';
    }

    // hourly table
    var sort = state.hourSort || 'hour';
    var order = hourly.map(function (b, h) { return { h: h, b: b, peak: hourlyHasPeak[h] }; });
    if (sort === 'tokens') order.sort(function (a, b) { return b.b.tokens - a.b.tokens; });
    else if (sort === 'cost') order.sort(function (a, b) { return b.b.cost - a.b.cost; });
    else if (sort === 'avg') order.sort(function (a, b) {
      return (b.b.requests ? b.b.tokens / b.b.requests : 0) - (a.b.requests ? a.b.tokens / a.b.requests : 0);
    });
    $('#hourlyBody').innerHTML = order.map(function (o) {
      var b = o.b;
      var avgTok = b.requests ? fmt(b.tokens / b.requests) : '—';
      var avgCost = b.requests ? fmtMoney(b.cost / b.requests) : '—';
      return '<tr>' +
        '<td class="num">' + String(o.h).padStart(2, '0') + ':00–' + String((o.h + 1) % 24).padStart(2, '0') + ':00</td>' +
        '<td>' + (o.peak ? '<span class="tag peak">peak</span>' : '<span class="tag off">off</span>') + '</td>' +
        '<td class="num">' + b.requests + '</td>' +
        '<td class="num">' + fmt(b.tokens) + '</td>' +
        '<td class="num">' + fmt(b.cached) + '</td>' +
        '<td class="num">' + fmt(b.output) + '</td>' +
        '<td class="num">' + avgTok + '</td>' +
        '<td class="num">' + fmtMoney(b.cost) + '</td>' +
        '<td class="num">' + avgCost + '</td>' +
        '<td class="num">' + (b.aiu ? fmtAiu(b.aiu) : '—') + '</td>' +
        '</tr>';
    }).join('');
  }

  function trunc(s, n) { s = String(s || ''); return s.length > n ? s.slice(0, n - 1) + '…' : s; }

  function bar(pct, cls) {
    return '<div class="bar"><div class="bar-fill ' + (cls || '') + '" style="width:' + Math.max(1, Math.min(100, pct)).toFixed(1) + '%"></div></div>';
  }

  function renderTasks(agg) {
    var rows = agg.tasks.slice(0, 25);
    var max = agg.tasks.length ? agg.tasks[0].effectiveTokens : 1;
    if (!rows.length) { $('#tasksBody').innerHTML = '<tr><td colspan="6" class="empty">No data in this range</td></tr>'; return; }
    $('#tasksBody').innerHTML = rows.map(function (t, i) {
      var models = Object.keys(t.models).map(function (m) { return m + '×' + t.models[m]; }).join(', ');
      return '<tr class="clickable" data-agent="' + esc(t.agent) + '" data-session="' + esc(t.session) + '" title="Click for the request-by-request breakdown">' +
        '<td class="num">' + (i + 1) + '</td>' +
        '<td><div class="task-name" title="' + esc(t.task) + '">' + esc(trunc(t.task, 90)) + '</div>' +
        '<div class="muted small">' + esc(t.agent) + ' · ' + esc(trunc(models, 60)) + ' · last ' + fmtTime(t.last) + (t.aiu ? ' · ' + fmtAiu(t.aiu) : '') + '</div></td>' +
        '<td class="num">' + fmt(t.effectiveTokens) + '<div class="muted small">' + fmt(t.cacheRead) + ' cached · ' + fmt(t.output) + ' out</div></td>' +
        '<td class="num">' + fmtMoney(t.cost) + '</td>' +
        '<td class="num">' + t.requests + '</td>' +
        '<td>' + bar(100 * t.effectiveTokens / max) + '</td>' +
        '</tr>';
    }).join('');
  }

  function renderModels(agg) {
    var rows = agg.models.slice(0, 10);
    if (!rows.length) { $('#modelsBody').innerHTML = '<tr><td colspan="5" class="empty">No data</td></tr>'; return; }
    var max = rows[0].input + rows[0].output + rows[0].cacheRead + rows[0].cacheWrite;
    $('#modelsBody').innerHTML = rows.map(function (m) {
      var eff = m.input + m.output + m.cacheRead + m.cacheWrite;
      return '<tr>' +
        '<td title="' + esc(m.model) + '">' + esc(trunc(m.model, 34)) + '</td>' +
        '<td class="num">' + fmt(eff) + '<div class="muted small">' + fmt(m.cacheRead) + ' cached · ' + fmt(m.output) + ' out' + (m.aiu ? ' · ' + fmtAiu(m.aiu) : '') + '</div></td>' +
        '<td class="num">' + fmtMoney(m.cost) + '</td>' +
        '<td class="num">' + m.requests + '</td>' +
        '<td>' + bar(100 * eff / max, 'alt') + '</td>' +
        '</tr>';
    }).join('');
  }

  function renderTrend(recs) {
    var w = rangeWindow();
    var now = Date.now();
    var from = w.from != null ? w.from : (state.records.length ? Math.min.apply(null, state.records.map(function (r) { return r.ts || now; })) : now - 3600e3);
    var to = w.to != null ? w.to : Math.max(now, from + 60e3);
    var span = to - from;
    var bucketMs, fmtLbl;
    if (span <= 20 * 60e3) { bucketMs = 30e3; fmtLbl = function (d) { return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }); }; }
    else if (span <= 3 * 3600e3) { bucketMs = 60e3; fmtLbl = function (d) { return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }); }; }
    else if (span <= 48 * 3600e3) { bucketMs = 3600e3; fmtLbl = function (d) { return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }); }; }
    else { bucketMs = 24 * 3600e3; fmtLbl = function (d) { return d.toLocaleDateString([], { month: 'short', day: 'numeric' }); }; }
    var metric = state.trendMetric;
    var buckets = [];
    var t0 = Math.floor(from / bucketMs) * bucketMs;
    for (var t = t0; t <= to && buckets.length < 400; t += bucketMs) buckets.push({ t: t, v: 0, out: 0 });
    var idx = {};
    buckets.forEach(function (b) { idx[b.t] = b; });
    recs.forEach(function (r) {
      if (!r.ts) return;
      var b = idx[Math.floor(r.ts / bucketMs) * bucketMs];
      if (b) { b.v += metricValue(r, metric); b.out += r.output; }
    });
    if (state.trendCumulative) {
      var run = 0;
      buckets.forEach(function (b) { run += b.v; b.v = run; });
    }
    var max = Math.max.apply(null, buckets.map(function (b) { return b.v; }).concat([1]));
    var unit = metric === 'cost' ? '' : ' ' + (METRIC_LABEL[metric] || '');
    $('#trend').innerHTML = buckets.map(function (b) {
      var h = Math.round(100 * b.v / max);
      var val = metric === 'cost' ? fmtMoney(b.v) : fmt(b.v);
      return '<div class="tbar" title="' + fmtLbl(new Date(b.t)) + ' — ' + val + unit +
        (b.out && metric === 'tokens' ? ' (' + fmt(b.out) + ' output)' : '') + '">' +
        '<div class="tbar-fill" style="height:' + h + '%"></div></div>';
    }).join('');
    $('#trendLabels').innerHTML = '<span>' + fmtLbl(new Date(buckets[0].t)) + '</span><span>' + fmtLbl(new Date(buckets[buckets.length - 1].t)) + '</span>';
  }

  function renderRecent(recs) {
    var rows = recs.slice().sort(function (a, b) { return (b.ts || 0) - (a.ts || 0); }).slice(0, 100);
    if (!rows.length) { $('#recentBody').innerHTML = '<tr><td colspan="6" class="empty">No requests in this range</td></tr>'; return; }
    $('#recentBody').innerHTML = rows.map(function (r) {
      return '<tr>' +
        '<td class="num">' + fmtTime(r.ts) + '</td>' +
        '<td>' + esc(r.agent) + '</td>' +
        '<td title="' + esc(r.model) + '">' + esc(trunc(r.model, 22)) + '</td>' +
        '<td class="num">' + fmt(r.input) + '<span class="muted small"> / ' + fmt(r.cacheRead) + 'c</span></td>' +
        '<td class="num">' + fmt(r.output) + '</td>' +
        '<td class="num">' + fmtMoney(costOf(r)) + '</td>' +
        '</tr>';
    }).join('');
  }

  function render() {
    var recs = filteredRecords();
    var agg = aggregate(recs);
    renderKpis(agg, recs);
    renderTasks(agg);
    renderModels(agg);
    renderProjects(agg);
    renderTrend(recs);
    renderRecent(recs);
    renderMix(agg);
    renderPeak(recs);
    renderAgentOptions();
    renderProjectOptions();
  }

  function renderAgentOptions() {
    var sel = $('#agentFilter');
    var agents = {};
    state.records.forEach(function (r) { agents[r.agent] = true; });
    Object.keys(agents).sort().forEach(function (a) {
      if (!sel.querySelector('option[value="' + a + '"]')) {
        var o = document.createElement('option');
        o.value = a; o.textContent = AGENT_NAMES[a] || a;
        sel.appendChild(o);
      }
    });
    Array.prototype.slice.call(sel.options).forEach(function (o) {
      if (o.value !== 'all' && !agents[o.value]) o.remove();
    });
  }

  function renderProjectOptions() {
    var sel = $('#projectFilter');
    if (!sel) return;
    var want = { all: true };
    state.records.forEach(function (r) { want[r.project || '(no project)'] = true; });
    Array.prototype.slice.call(sel.options).forEach(function (o) { if (!want[o.value]) o.remove(); });
    Object.keys(want).forEach(function (p) {
      if (p === 'all') return;
      if (!sel.querySelector('option[value="' + p.replace(/"/g, '&quot;') + '"]')) {
        var o = document.createElement('option');
        o.value = p; o.textContent = p;
        sel.appendChild(o);
      }
    });
    sel.value = state.projectFilter;
    if (sel.selectedIndex === -1) sel.value = 'all';
  }

  function renderProjects(agg) {
    var max = agg.projects.length ? agg.projects[0].effectiveTokens : 1;
    $('#projectsBody').innerHTML = agg.projects.slice(0, 15).map(function (p, i) {
      return '<tr>' +
        '<td class="num">' + (i + 1) + '</td>' +
        '<td><div class="task-name" title="' + esc(p.project) + '">' + esc(trunc(p.project, 80)) + '</div>' +
        '<div class="muted small">' + p.sessions + ' session' + (p.sessions === 1 ? '' : 's') + ' · ' + p.requests + ' requests</div></td>' +
        '<td class="num">' + fmt(p.input) + '</td>' +
        '<td class="num">' + fmt(p.output) + '</td>' +
        '<td class="num">' + fmt(p.cacheRead) + '</td>' +
        '<td class="num">' + fmtMoney(p.cost) + '</td>' +
        '<td class="num">' + fmt(p.effectiveTokens) + '</td>' +
        '<td>' + bar(100 * p.effectiveTokens / max) + '</td>' +
        '</tr>';
    }).join('') || '<tr><td colspan="8" class="empty">No data in this range</td></tr>';
  }

  // ---------- Markdown digest ----------

  function exportMarkdown() {
    var recs = filteredRecords();
    var agg = aggregate(recs);
    var t = agg.total;
    var eff = t.input + t.output + t.cacheRead + t.cacheWrite;
    var r = RANGES.find(function (x) { return x.id === state.range; });
    var rangeLbl = state.range === 'custom' ? 'custom range' : (r ? r.label : state.range);
    var L = [];
    L.push('## Token Report — ' + rangeLbl);
    L.push('_' + new Date().toLocaleString() + ' · agent: ' +
      (state.agentFilter === 'all' ? 'all' : state.agentFilter) +
      (state.projectFilter !== 'all' ? ' · project: ' + state.projectFilter : '') + '_');
    L.push('');
    L.push('- **Tokens:** ' + fmt(eff) + ' (in ' + fmt(t.input) + ' · out ' + fmt(t.output) +
      ' · cache read ' + fmt(t.cacheRead) + ' · cache write ' + fmt(t.cacheWrite) + ')');
    L.push('- **Est. cost:** ' + fmtMoney(t.cost) + ' across ' + fmt(t.requests) + ' requests');
    if (state.budgetAmount > 0) {
      L.push('- **Budget (' + state.budgetPeriod + '):** ' + fmtMoney(state.budgetAmount) +
        (agg.earliest !== Infinity ? '' : ''));
    }
    if (agg.models.length) {
      L.push('');
      L.push('| Model | Tokens | Est. cost | Reqs |');
      L.push('|---|---:|---:|---:|');
      agg.models.slice(0, 8).forEach(function (m) {
        L.push('| ' + m.model + ' | ' + fmt(m.input + m.output + m.cacheRead + m.cacheWrite) +
          ' | ' + fmtMoney(m.cost) + ' | ' + m.requests + ' |');
      });
    }
    if (agg.tasks.length) {
      L.push('');
      L.push('**Top tasks**');
      agg.tasks.slice(0, 5).forEach(function (x) {
        L.push('- ' + trunc(x.task, 80).replace(/\n/g, ' ') + ' — ' + fmt(x.effectiveTokens) + ' tok · ' + fmtMoney(x.cost));
      });
    }
    var md = L.join('\n');
    navigator.clipboard && navigator.clipboard.writeText(md)
      .then(function () { toast('Markdown summary copied to clipboard', 'ok'); })
      .catch(function () { downloadMd(md); });
    if (!(navigator.clipboard && navigator.clipboard.writeText)) downloadMd(md);

    function downloadMd(text) {
      var a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([text], { type: 'text/markdown' }));
      a.download = 'token-report-' + new Date().toISOString().slice(0, 16).replace(/[:T]/g, '-') + '.md';
      a.click();
      setTimeout(function () { URL.revokeObjectURL(a.href); }, 5000);
      toast('Markdown summary downloaded', 'ok');
    }
  }

  // ---------- task drill-down ----------

  function openTask(agent, session) {
    var recs = state.records.filter(function (r) {
      return r.agent === agent && r.session === session;
    }).sort(function (a, b) { return (a.ts || 0) - (b.ts || 0); });
    if (!recs.length) return;
    var inTok = 0, outTok = 0, cr = 0, cw = 0, cost = 0;
    recs.forEach(function (r) { inTok += r.input; outTok += r.output; cr += r.cacheRead; cw += r.cacheWrite; cost += costOf(r); });
    $('#taskDialogTitle').textContent = trunc(recs[0].task || '(unlabeled session)', 80);
    $('#taskDialogMeta').textContent =
      (AGENT_NAMES[agent] || agent) + ' · session ' + trunc(session, 18) +
      ' · ' + recs.length + ' requests · ' + fmt(inTok + outTok + cr + cw) + ' tokens · ' + fmtMoney(cost) +
      ' · last ' + fmtTime(recs[recs.length - 1].ts);
    $('#taskDialogBody').innerHTML = recs.map(function (r) {
      return '<tr>' +
        '<td class="num">' + (r.ts ? new Date(r.ts).toLocaleTimeString() : '—') + '</td>' +
        '<td>' + esc(r.model) + '</td>' +
        '<td class="num">' + fmt(r.input) + '</td>' +
        '<td class="num">' + fmt(r.cacheRead) + '</td>' +
        '<td class="num">' + fmt(r.output) + '</td>' +
        '<td class="num">' + fmtMoney(costOf(r)) + '</td>' +
        '</tr>';
    }).join('');
    document.getElementById('taskDialog').showModal();
  }

  // ---------- CSV export ----------

  function exportCsv() {
    var recs = filteredRecords().sort(function (a, b) { return (a.ts || 0) - (b.ts || 0); });
    var head = 'timestamp,agent,session,task,model,provider,input,output,cache_read,cache_write,cost_usd,request_id';
    var lines = recs.map(function (r) {
      return [r.ts != null ? new Date(r.ts).toISOString() : '', r.agent, r.session, r.task, r.model, r.provider,
        r.input, r.output, r.cacheRead, r.cacheWrite, costOf(r).toFixed(6), r.requestId]
        .map(function (v) { v = String(v == null ? '' : v); return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; })
        .join(',');
    });
    var blob = new Blob([head + '\n' + lines.join('\n')], { type: 'text/csv' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'token-report-' + new Date().toISOString().slice(0, 16).replace(/[:T]/g, '-') + '.csv';
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 5000);
  }

  // ---------- archive (save history to a local file) ----------

  async function pickArchive() {
    if (EMBEDDED) {
      // Browsers block file pickers inside cross-origin frames (the dashboard
      // tab) — fall back to a classic file input to open an existing archive.
      $('#archiveFallback').click();
      return;
    }
    if (!fsaSupported()) { toast('Your browser does not support file writing'); return; }
    try {
      var h = await window.showSaveFilePicker({
        suggestedName: 'tokenreport-archive.jsonl',
        types: [{ description: 'JSONL', accept: { 'application/jsonl': ['.jsonl'] } }]
      });
      state.archiveHandle = h;
      await idb('meta', 'readwrite', function (st) { st.put(h, 'archive'); return {}; });
      $('#archiveName').textContent = 'tokenreport-archive.jsonl';
      await saveToArchive(true);
    } catch (e) { /* user cancelled */ }
  }

  async function saveToArchive(quiet) {
    if (EMBEDDED) return saveToArchiveFile(quiet);
    if (!state.archiveHandle) { toast('Pick an archive file first'); return null; }
    var perm = await state.archiveHandle.queryPermission({ mode: 'readwrite' });
    // Quiet (auto) mode must never prompt and never toast: after a browser
    // restart the grant is 'prompt' again, and without a user gesture the
    // request just re-returns 'prompt' — retrying every refresh would spam
    // an error toast forever. Silence until the next manual save or
    // reconnect flow restores the grant.
    if (perm !== 'readwrite') {
      if (quiet) return null;
      try { perm = await state.archiveHandle.requestPermission({ mode: 'readwrite' }); }
      catch (e) { toast('Archive write permission denied'); return null; }
    }
    if (perm !== 'granted' && perm !== 'readwrite') { toast('Archive write permission denied'); return null; }
    // merge with existing archive content, dedup by record key
    var existing = {};
    try {
      var f = await state.archiveHandle.getFile();
      var txt = await f.text();
      txt.split('\n').forEach(function (l) {
        if (!l.trim()) return;
        try { existing[recordKey(JSON.parse(l))] = l; } catch (e) { /* skip */ }
      });
    } catch (e) { /* new file */ }
    var added = 0;
    state.records.forEach(function (r) {
      var k = recordKey(r);
      if (existing[k]) return;
      existing[k] = JSON.stringify(r);
      added++;
    });
    var w = await state.archiveHandle.createWritable();
    await w.write(Object.keys(existing).map(function (k) { return existing[k]; }).join('\n') + (added ? '\n' : ''));
    await w.close();
    if (!quiet) toast('Archive saved: +' + added + ' new requests');
    return added;
  }

  // Embedded (dashboard-tab) mode: browsers block file pickers in
  // cross-origin frames, so the archive lives in memory — auto-saves merge
  // silently and a manual save downloads the merged file.
  async function saveToArchiveFile(quiet) {
    var existing = {};
    (state.archiveText || '').split('\n').forEach(function (l) {
      if (!l.trim()) return;
      try { existing[recordKey(JSON.parse(l))] = l; } catch (e) { /* skip */ }
    });
    var added = 0;
    state.records.forEach(function (r) {
      var k = recordKey(r);
      if (existing[k]) return;
      existing[k] = JSON.stringify(r);
      added++;
    });
    state.archiveText = Object.keys(existing).map(function (k) { return existing[k]; }).join('\n') + (added ? '\n' : '');
    if (quiet) return added;
    if (!state.records.length && !state.archiveText) { toast('Nothing to archive yet'); return null; }
    var a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([state.archiveText], { type: 'application/jsonl' }));
    a.download = state.archiveName || 'tokenreport-archive.jsonl';
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 5000);
    toast('Archive downloaded: +' + added + ' new requests — keep the file as your archive');
    return added;
  }

  // ---------- theme ----------

  function applyTheme() {
    document.documentElement.setAttribute('data-theme', state.theme);
    var btn = $('#btnTheme');
    if (btn) {
      btn.textContent = state.theme === 'dark' ? '🌙' : '☀️';
      btn.title = state.theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme';
    }
  }

  // ---------- toast ----------

  var toastTimer = null;
  function toast(msg) {
    var el = $('#toast');
    el.textContent = msg;
    el.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { el.classList.remove('show'); }, 2600);
  }

  // ---------- sources management ----------

  var sourceCounter = 0;

  // A custom name (when given) becomes the agent identity everywhere — the
  // Agent dropdown, records, per-agent tables — while parseAs keeps the
  // parsing behavior (named parser for known templates, content sniffing for
  // the generic template).
  function sanitizeAgentName(s) {
    return String(s || '').replace(/["'\\]/g, '').trim().slice(0, 24);
  }

  async function addSource(agentType, handle, demoPath, customName) {
    var tpl = TEMPLATES.find(function (t) { return t.id === agentType; }) || TEMPLATES[3];
    var name = customName || tpl.name;
    try { if (handle && handle.name) name = customName || handle.name; } catch (e) { /* demo */ }
    var agent = customName || (agentType === 'generic' ? 'auto' : agentType);
    var src = {
      id: 'src' + Date.now() + '_' + (sourceCounter++),
      agent: agent, parseAs: agentType, name: name, handle: handle || null,
      demo: !!demoPath, demoPath: demoPath || null,
      status: demoPath ? 'ok' : 'new', files: null
    };
    state.sources.push(src);
    if (handle) {
      await idb('sources', 'readwrite', function (st) { st.put({ id: src.id, agent: agent, parseAs: agentType, name: name, handle: handle }); return {}; });
    }
    renderSources();
    await refreshAll();
  }

  // ---------- agent default folders ----------
  // Known per-OS homes of each agent's logs. Used by autoAttachDefaults to
  // scan them once per install so the report fills itself instead of asking
  // for a folder pick on every start. Paths are read through the launcher's
  // own file API (same origin, this machine only); browsers block plain
  // file:// pages from doing this, so there is no fallback there.
  var AGENT_DEFAULT_DIRS = [
    { agent: 'zcode',       template: 'zcode',       paths: ['~/.zcode/cli/rollout'] },
    { agent: 'claude-code', template: 'claude-code', paths: ['~/.claude/projects'] },
    { agent: 'codex',       template: 'codex',       paths: ['~/.codex/sessions'] },
    { agent: 'copilot',     template: 'copilot',     paths: ['~/.copilot'] },
    { agent: 'openclaw',    template: 'openclaw',    paths: ['~/.openclaw-autoclaw/agents'] }
  ];

  // The launcher resolves '~' itself (it knows the real home dir).
  function expandHome(p) { return p; }

  async function autoAttachDefaults() {
    // Runs whenever there is nothing to show: first visit, or after the user
    // removed every source. Already-tracked agents (and demo sources) are
    // never duplicated; "done" only stops the toast from re-announcing.
    var known = {};
    state.sources.forEach(function (s) {
      if (!s.demo) known[s.agent] = true;
    });
    if (Object.keys(known).length) return;
    var added = 0, attached = 0;
    for (var i = 0; i < AGENT_DEFAULT_DIRS.length; i++) {
      var def = AGENT_DEFAULT_DIRS[i];
      if (known[def.agent]) { attached++; continue; } // user already tracks this agent
      try {
        // Served on the app's own origin by the launcher (hostedHandler),
        // so a plain same-origin fetch reaches the deck API.
        var res = await fetch('/__tokenreport__/list?path=' + encodeURIComponent(def.paths[0]));
        if (!res.ok) continue; // folder absent on this machine/OS — skip silently
        var listing = await res.json();
        if (!listing || !listing.ok || !(listing.files > 0)) continue;
        var src = {
          id: 'src' + Date.now() + '_' + (sourceCounter++),
          agent: def.agent, parseAs: def.template,
          name: def.paths[0].replace('~/', ''), handle: null,
          demo: false, demoPath: null, status: 'new', files: listing.files,
          serverPath: def.paths[0], auto: true
        };
        state.sources.push(src);
        idb('sources', 'readwrite', function (st) {
          st.put({ id: src.id, agent: src.agent, parseAs: src.parseAs, name: src.name, serverPath: src.serverPath });
          return {};
        }).catch(function () { /* non-fatal */ });
        added++;
      } catch (e) { /* launcher API unreachable (plain browser tab) — skip */ }
    }
    if (added) {
      renderSources();
      await refreshAll();
      if (!state.autoAttachDone) {
        toast(added + ' agent folder' + (added > 1 ? 's' : '') + ' auto-detected and scanned', 'ok');
      }
    }
    state.autoAttachDone = true;
    savePrefs();
  }

  // restore persisted sources; handles need permission re-grant in some browsers
  async function restoreSources() {
    var rows = await idb('sources', 'readonly', function (st) { return st.getAll(); });
    (rows || []).forEach(function (row) {
      state.sources.push({
        id: row.id, agent: row.agent, parseAs: row.parseAs || row.agent,
        name: row.name, handle: row.handle,
        serverPath: row.serverPath || null, auto: !!row.auto,
        demo: false, demoPath: null, status: row.serverPath ? 'new' : 'new', files: null
      });
    });
    var arch = await idb('meta', 'readonly', function (st) { return st.get('archive'); });
    if (arch) {
      state.archiveHandle = arch;
      $('#archiveName').textContent = 'saved archive';
      if (EMBEDDED) {
        // The linked FSA file is still readable if its grant persisted —
        // load it into download-mode so merges keep working embedded.
        try {
          if (await arch.queryPermission({ mode: 'readwrite' }) === 'granted') {
            var af = await arch.getFile();
            state.archiveText = await af.text();
            state.archiveName = af.name;
            $('#archiveName').textContent = af.name;
          }
        } catch (e) { /* stays unlinked; download mode covers it */ }
      }
    }
    // last-good scans: shown when a source's folder permission needs re-grant
    try {
      var cached = await idb('cache', 'readonly', function (st) { return st.getAll(); });
      (cached || []).forEach(function (row) { state.sourceCache[row.id] = row; });
    } catch (e) { /* no cache yet */ }
  }

  // ---------- wiring ----------

  function fillRangeSelect() {
    var sel = $('#rangeFilter');
    sel.innerHTML = RANGES.map(function (r) {
      return '<option value="' + r.id + '"' + (r.id === state.range ? ' selected' : '') + '>' + r.label + '</option>';
    }).join('');
    updateCustomVisibility();
  }

  function updateCustomVisibility() {
    $('#customRange').style.display = state.range === 'custom' ? 'flex' : 'none';
  }

  function localIso(d) {
    if (!d) return '';
    var p = function (x) { return String(x).padStart(2, '0'); };
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + 'T' + p(d.getHours()) + ':' + p(d.getMinutes());
  }

  function wire() {
    $('#btnAddSource').onclick = function () { $('#settings').showModal(); };
    $('#btnReconnectAll').onclick = reconnectAll;
    $('#btnSettings').onclick = function () { $('#settings').showModal(); };

    // view tabs
    var applyView = function () {
      var v = state.view;
      $('#viewReport').hidden = v !== 'report';
      $('#viewMix').hidden = v !== 'mix';
      $('#viewPeak').hidden = v !== 'peak';
      $('#viewGuide').hidden = v !== 'guide';
      $('#tabReport').classList.toggle('active', v === 'report');
      $('#tabMix').classList.toggle('active', v === 'mix');
      $('#tabPeak').classList.toggle('active', v === 'peak');
      $('#tabGuide').classList.toggle('active', v === 'guide');
    };
    $('#tabReport').onclick = function () { state.view = 'report'; savePrefs(); applyView(); };
    $('#tabMix').onclick = function () { state.view = 'mix'; savePrefs(); applyView(); };
    $('#tabGuide').onclick = function () { state.view = 'guide'; savePrefs(); applyView(); };
    $('#tabPeak').onclick = function () { state.view = 'peak'; savePrefs(); applyView(); };
    $('#peakMetric').onchange = function () {
      state.peakMetric = $('#peakMetric').value; savePrefs(); render();
    };
    var clampHour = function (v, fallback) {
      v = Math.round(Number(v));
      return Number.isFinite(v) && v >= 0 && v <= 23 ? v : fallback;
    };
    $('#peakStart').onchange = function () {
      state.peakStart = clampHour($('#peakStart').value, state.peakStart);
      $('#peakStart').value = state.peakStart; savePrefs(); render();
    };
    $('#peakEnd').onchange = function () {
      state.peakEnd = clampHour($('#peakEnd').value, state.peakEnd);
      $('#peakEnd').value = state.peakEnd; savePrefs(); render();
    };
    $('#peakWeekdays').onchange = function () {
      state.peakWeekdaysOnly = $('#peakWeekdays').checked; savePrefs(); render();
    };
    $('#hourSort').onchange = function () {
      state.hourSort = $('#hourSort').value; savePrefs(); render();
    };
    $('#btnTheme').onclick = function () {
      state.theme = state.theme === 'dark' ? 'light' : 'dark';
      savePrefs(); applyTheme();
    };
    applyView();

    // add-source template picker + folder pick
    var tplSel = $('#templateSelect');
    tplSel.innerHTML = TEMPLATES.map(function (t) {
      return '<option value="' + t.id + '">' + t.name + '</option>';
    }).join('');
    var updateHint = function () {
      var t = TEMPLATES.find(function (x) { return x.id === tplSel.value; });
      $('#templateHint').textContent = t ? t.hint : '';
    };
    tplSel.onchange = updateHint; updateHint();

    $('#btnPickFolder').onclick = async function () {
      if (!fsaSupported() || EMBEDDED) {
        // fallback: <input webkitdirectory> (also used when embedded —
        // the FSA directory picker cannot show inside a cross-origin frame)
        $('#dirFallback').click();
        return;
      }
      try {
        var handle = await pickDirectory();
        var customName = sanitizeAgentName($('#customAgentName').value);
        await addSource(tplSel.value, handle, null, customName);
        $('#customAgentName').value = '';
        $('#settings').close();
      } catch (e) { /* cancelled */ }
    };

    // webkitdirectory fallback (also used by non-Chromium browsers)
    $('#dirFallback').onchange = async function (ev) {
      var files = Array.prototype.slice.call(ev.target.files || []);
      if (!files.length) return;
      var customName = sanitizeAgentName($('#customAgentName').value);
      var agent = customName || (tplSel.value === 'generic' ? 'auto' : tplSel.value);
      var parseAs = tplSel.value;
      // emulate a source from the picked file list
      var rootName = customName || (files[0].webkitRelativePath || files[0].name).split('/')[0];
      var src = {
        id: 'src' + Date.now(), agent: agent, parseAs: parseAs, name: rootName, handle: null,
        demo: false, demoPath: null, status: 'new', files: files.length, fallbackFiles: files
      };
      state.sources.push(src);
      renderSources();
      await scanFallbackSource(src);
      $('#customAgentName').value = '';
      $('#settings').close();
      ev.target.value = '';
    };

    // range + agent + actions
    $('#rangeFilter').onchange = function () {
      state.range = $('#rangeFilter').value;
      savePrefs(); updateCustomVisibility();
      if (state.range === 'custom') {
        var w = rangeWindow();
        $('#customFrom').value = state.customFrom || (w.from ? localIso(new Date(w.from)) : '');
        $('#customTo').value = state.customTo || '';
      }
      render();
    };
    $('#customFrom').onchange = function () { state.customFrom = $('#customFrom').value || null; savePrefs(); render(); };
    $('#customTo').onchange = function () { state.customTo = $('#customTo').value || null; savePrefs(); render(); };
    $('#agentFilter').onchange = function () { state.agentFilter = $('#agentFilter').value; savePrefs(); render(); };
    // Short ranges are live views: picking one rescans right away, and a 30s
    // auto-rescan keeps the 5m/15m window sliding while the tab is open.
    // The unguarded auto-refresh of the past is gone for good reasons, so
    // this one skips: hidden tabs, an in-flight scan, sources without
    // persistent handles (webkitdirectory picks are static), and any source
    // that needs reconnect — rescanning those only churned the permission
    // banner that got auto-refresh removed. Longer ranges keep the manual
    // model (open, source add/reconnect/remove, page reload).
    $('#rangeFilter').addEventListener('change', function () {
      if (state.range === '5m' || state.range === '15m') refreshAll();
    });
    setInterval(function () {
      if (document.hidden || state.scanning) return;
      if (state.range !== '5m' && state.range !== '15m') return;
      if (!state.sources.length) return;
      for (var i = 0; i < state.sources.length; i++) {
        var s = state.sources[i];
        if (s.demo || s.serverPath) continue; // auto sources scan server-side, always safe
        if (!s.handle || s.status !== 'ok') return; // stale/fallback: never auto-rescan
      }
      refreshAll();
    }, 30e3);
    $('#btnExport').onclick = exportCsv;

    // settings dialog
    $('#btnSavePrices').onclick = function () {
      state.prices = collectPrices();
      localStorage.setItem('tokenreport.prices', JSON.stringify(state.prices));
      renderPriceEditor(); render(); toast('Prices saved');
    };
    $('#btnResetPrices').onclick = function () {
      state.prices = JSON.parse(JSON.stringify(DEFAULT_PRICES));
      localStorage.removeItem('tokenreport.prices');
      renderPriceEditor(); render(); toast('Prices reset to defaults');
    };
    $('#btnAddPrice').onclick = function () {
      var i = 1;
      while (state.prices['new-model' + (i > 1 ? i : '')]) i++;
      state.prices['new-model' + (i > 1 ? i : '')] = { input: 1, output: 3, cacheReadRatio: 0.1, cacheWriteRatio: 1.25 };
      renderPriceEditor();
    };
    $('#btnPickArchive').onclick = pickArchive;
    $('#btnSaveArchive').onclick = function () { saveToArchive(); };
    // Embedded mode: classic file input replaces the blocked FSA pickers
    $('#archiveFallback').onchange = async function (ev) {
      var f = ev.target.files && ev.target.files[0];
      ev.target.value = '';
      if (!f) return;
      state.archiveText = await f.text();
      state.archiveName = f.name;
      $('#archiveName').textContent = f.name;
      toast('Archive loaded — “Save now” merges new requests and downloads it');
    };
    $('#includeArchive').onchange = function () {
      state.includeArchive = $('#includeArchive').checked; savePrefs(); refreshAll();
    };
    $('#autoArchive').onchange = function () {
      state.autoArchive = $('#autoArchive').checked; savePrefs();
      if (state.autoArchive) autoArchiveIfNew();
    };
    $('#budgetAmount').onchange = function () {
      state.budgetAmount = Math.max(0, Number($('#budgetAmount').value) || 0);
      savePrefs(); render();
    };
    $('#budgetPeriod').onchange = function () {
      state.budgetPeriod = $('#budgetPeriod').value; savePrefs(); render();
    };
    $('#projectFilter').onchange = function () {
      state.projectFilter = $('#projectFilter').value; savePrefs(); render();
    };
    $('#trendMetric').onchange = function () {
      state.trendMetric = $('#trendMetric').value; savePrefs(); render();
    };
    $('#trendCumulative').onchange = function () {
      state.trendCumulative = $('#trendCumulative').checked; savePrefs(); render();
    };
    $('#btnMd').onclick = exportMarkdown;
    $('#taskDialogClose').onclick = function () { document.getElementById('taskDialog').close(); };
    $('#tasksBody').addEventListener('click', function (e) {
      var tr = e.target.closest('tr[data-session]');
      if (!tr) return;
      openTask(tr.getAttribute('data-agent'), tr.getAttribute('data-session'));
    });
  }

  // scan for the webkitdirectory fallback (no persistent handles available)
  async function scanFallbackSource(src) {
    setStatus('Reading picked files…', true);
    var tasks = {}, recs = [];
    var files = src.fallbackFiles || [];
    if (src.agent === 'copilot') {
      var mainF = null, walF = null, dataF = null, dataWalF = null;
      files.forEach(function (f) {
        var n = f.name.toLowerCase();
        if (/session-store\.db$/.test(n)) mainF = f;
        else if (/session-store\.db-wal$/.test(n)) walF = f;
        else if (/data\.db$/.test(n)) dataF = f;
        else if (/data\.db-wal$/.test(n)) dataWalF = f;
      });
      if (!mainF) { mainF = dataF; walF = dataWalF; }
      if (mainF) {
        var mbuf = await mainF.arrayBuffer();
        var wbuf = walF ? await walF.arrayBuffer() : null;
        var pc = window.TR_COPILOT.parseStore(new Uint8Array(mbuf), wbuf ? new Uint8Array(wbuf) : null, mainF.name);
        recs = pc.records;
        tasks = pc.sessions;
      } else {
        toast('session-store.db / data.db not found in picked files');
      }
    } else {
      for (var i = 0; i < files.length && i < MAX_FILES; i++) {
        var f = files[i];
        if (f.size > 64 * 1024 * 1024) continue;
        try {
          var txt = await f.text();
          var rel = f.webkitRelativePath || f.name;
          var p = P.parseFile(txt, src.parseAs || src.agent, rel);
          recs.push.apply(recs, p.records);
          for (var k in p.sessions) if (!tasks[k]) tasks[k] = p.sessions[k];
        } catch (e) { /* skip unreadable */ }
      }
    }
    recs.forEach(function (r) {
      r.agent = src.agent === 'auto' ? (r.agentType || 'generic') : src.agent;
      r.source = src.name;
      r.task = tasks[r.session] || r.task || '';
    });
    // merge into global record set (replace this source's previous records)
    state.records = state.records.filter(function (r) { return r.source !== src.name; }).concat(recs);
    for (var k2 in tasks) state.sessionTasks[src.agent + ':' + k2] = state.sessionTasks[src.agent + ':' + k2] || tasks[k2];
    src.status = 'ok';
    setStatus(state.records.length.toLocaleString() + ' requests · refreshed ' + new Date().toLocaleTimeString(), false);
    renderSources(); render();
  }


  // ---------- boot ----------

  async function boot() {
    loadPrefs();
    db = await openDb();
    fillRangeSelect();
    $('#peakMetric').value = state.peakMetric;
    $('#peakStart').value = state.peakStart;
    $('#peakEnd').value = state.peakEnd;
    $('#peakWeekdays').checked = state.peakWeekdaysOnly;
    $('#hourSort').value = state.hourSort;
    $('#trendMetric').value = state.trendMetric;
    $('#trendCumulative').checked = state.trendCumulative;
    $('#budgetAmount').value = state.budgetAmount || '';
    $('#budgetPeriod').value = state.budgetPeriod;
    $('#autoArchive').checked = state.autoArchive;
    applyTheme();
    if (state.range === 'custom') {
      var w = rangeWindow();
      $('#customFrom').value = state.customFrom || (w.from ? localIso(new Date(w.from)) : '');
      $('#customTo').value = state.customTo || '';
    }
    $('#includeArchive').checked = state.includeArchive;
    renderPriceEditor();
    wire();
    await restoreSources();
    renderSources();
    if (state.sources.length) await refreshAll();
    else {
      // Nothing persisted (fresh start): probe the known per-OS agent log
      // folders once and attach what exists, so the report fills itself.
      await autoAttachDefaults();
      if (state.sources.length) await refreshAll();
      else setStatus('Add a source folder to begin.', false);
    }
  }

  document.addEventListener('DOMContentLoaded', function () {
    boot().catch(function (e) {
      console.error(e);
      setStatus('Startup error: ' + (e && e.message || e));
    });
  });
})();

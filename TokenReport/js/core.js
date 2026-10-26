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

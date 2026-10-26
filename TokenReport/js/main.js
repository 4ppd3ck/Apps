'use strict';
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
      state.theme = state.theme === 'dark' ? 'light'
        : state.theme === 'light' ? 'auto' : 'dark';
      savePrefs(); applyTheme();
    };
    var _tmq = window.matchMedia ? matchMedia('(prefers-color-scheme: light)') : null;
    if (_tmq) _tmq.addEventListener
      ? _tmq.addEventListener('change', function () { if (state.theme === 'auto') applyTheme(); })
      : _tmq.addListener(function () { if (state.theme === 'auto') applyTheme(); });
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

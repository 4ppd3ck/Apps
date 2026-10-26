'use strict';
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

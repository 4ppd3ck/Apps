'use strict';
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

'use strict';
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

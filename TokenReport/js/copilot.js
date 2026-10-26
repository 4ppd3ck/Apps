/* Copilot CLI parser — reads ~/.copilot SQLite stores into the same
 * normalized records the JSONL parsers produce. Two known layouts exist and
 * which one you get depends on the Copilot CLI build (version, OS, arch) —
 * so the format is detected from the database content, never from the
 * platform:
 *
 * Old (session-store.db, Copilot CLI 1.1.x):
 *   - assistant_usage_events: one row per model API request with input/output/
 *     cache_read/cache_write/reasoning token splits, total_nano_aiu (billing
 *     units), request_multiplier, created_at.
 *   - sessions: id, cwd, repository, branch, summary.
 *   - turns: per-turn user_message (task labels).
 *   Recent rows usually live in session-store.db-wal, so the caller passes both
 *   files and TR_SQLITE replays committed WAL frames.
 *
 * New (data.db, current Copilot CLI): no per-request usage table — the
 *   sessions table carries cumulative totals (total_input_tokens,
 *   total_output_tokens, total_cached_tokens, total_reasoning_tokens,
 *   total_nano_aiu) plus title/model/updated_at. One record per session,
 *   timestamped at its last activity; task label = session title.
 */
(function (root) {
  'use strict';

  var SQLITE = root.TR_SQLITE;
  var P = root.TR_PARSERS;

  function parseStore(dbBytes, walBytes, fileName) {
    var out = { records: [], sessions: {}, errors: 0, agentType: 'copilot', error: null };
    var srcFile = fileName || 'session-store.db';
    var snap;
    try {
      snap = new SQLITE.Snapshot(dbBytes, walBytes);
    } catch (e) {
      out.errors++;
      out.error = 'unreadable database: ' + (e && e.message || e);
      return out;
    }
    var usage = null, sessions = null, turns = null;
    try { usage = snap.readTable('assistant_usage_events'); } catch (e) { usage = null; }
    try { sessions = snap.readTable('sessions'); } catch (e) { sessions = null; }
    try { turns = snap.readTable('turns'); } catch (e) { turns = null; }

    // New layout (data.db): cumulative totals live on the sessions table and
    // there is no assistant_usage_events/turns. Detected from the columns
    // actually present — the same binary can write either layout depending
    // on OS/arch/version.
    if ((!usage || !usage.length) && sessions && sessions.length &&
        sessions[0] && sessions[0].total_input_tokens != null) {
      for (var n = 0; n < sessions.length; n++) {
        var ns = sessions[n];
        var nIn = Number(ns.total_input_tokens) || 0;
        var nOut = Number(ns.total_output_tokens) || 0;
        var nCache = Number(ns.total_cached_tokens) || 0;
        var nReason = Number(ns.total_reasoning_tokens) || 0;
        if (!nIn && !nOut && !nCache) continue; // empty/abandoned session
        out.records.push({
          ts: P.parseTs(ns.updated_at || ns.created_at),
          agentType: 'copilot',
          session: ns.id || 'unknown',
          model: ns.model || 'unknown',
          provider: 'github-copilot',
          input: nIn,
          output: nOut + nReason, // reasoning is billed as output
          cacheRead: nCache,
          cacheWrite: 0, // the new layout tracks no cache-write total
          reasoning: nReason,
          aiu: Number(ns.total_nano_aiu) || 0,
          multiplier: 1,
          requestId: (ns.id || '') + ':totals',
          file: srcFile,
          project: '',
          task: P.cleanTask(ns.title || '')
        });
        if (ns.id) out.sessions[ns.id] = P.cleanTask(ns.title || '');
      }
      return out;
    }

    if (!usage) {
      out.errors++;
      out.error = 'no usage/session tables found in the database';
      return out;
    }

    // task labels: session summary, else first user prompt
    for (var i = 0; i < sessions.length; i++) {
      var s = sessions[i];
      var label = s.summary || '';
      if (label) out.sessions[s.id] = P.cleanTask(label);
    }
    turns.sort(function (a, b) {
      return String(a.timestamp || '').localeCompare(String(b.timestamp || ''));
    });
    for (var j = 0; j < turns.length; j++) {
      var t = turns[j];
      if (!t.session_id || out.sessions[t.session_id]) continue;
      var msg = typeof t.user_message === 'string' ? t.user_message : '';
      if (msg && msg.trim()) out.sessions[t.session_id] = P.cleanTask(msg);
    }

    for (var k = 0; k < usage.length; k++) {
      var u = usage[k];
      var ts = P.parseTs(u.created_at);
      var input = Number(u.input_tokens) || 0;
      var output = Number(u.output_tokens) || 0;
      var reasoning = Number(u.reasoning_tokens) || 0;
      if (!input && !output && !Number(u.cache_read_tokens)) { out.errors++; continue; }
      out.records.push({
        ts: ts,
        agentType: 'copilot',
        session: u.session_id || 'unknown',
        model: u.model || u.copilot_usage_model || 'unknown',
        provider: 'github-copilot',
        input: input,
        output: output + reasoning, // reasoning is billed as output
        cacheRead: Number(u.cache_read_tokens) || 0,
        cacheWrite: Number(u.cache_write_tokens) || 0,
        reasoning: reasoning,
        aiu: Number(u.total_nano_aiu) || 0,
        multiplier: Number(u.request_multiplier) || 1,
        requestId: (u.session_id || '') + ':' + (u.turn_index != null ? u.turn_index : '') + ':' + (u.created_at || ''),
        file: srcFile,
        task: out.sessions[u.session_id] || ''
      });
    }
    return out;
  }

  root.TR_COPILOT = { parseStore: parseStore };
})(typeof window !== 'undefined' ? window : globalThis);

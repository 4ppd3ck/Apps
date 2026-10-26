/* TokenReport — log parsers (pure functions, no DOM).
 *
 * Every parser turns one log file into normalized records:
 *   { ts, agentType, session, model, provider, input, output, cacheRead,
 *     cacheWrite, requestId, file }
 * plus a per-file session→task map (task = first user prompt of the session).
 *
 * All parsing is plain code — no AI calls, no tokens burned.
 */
(function (root) {
  'use strict';

  var MAX_LINES = 200000;      // safety cap per file
  var TASK_MAX = 120;          // task label length

  // ---------- small helpers ----------

  function toNum(v) {
    var n = Number(v);
    return isFinite(n) && n >= 0 ? n : 0;
  }

  function parseTs(v) {
    if (v == null) return null;
    if (typeof v === 'number') {
      // seconds vs milliseconds heuristics
      if (v > 1e12) return v;            // ms
      if (v > 1e9) return v * 1000;      // s
      return null;
    }
    var s = String(v);
    if (!s) return null;
    var t = Date.parse(s);
    return isNaN(t) ? null : t;
  }

  function firstTs(o) {
    var keys = ['startedAt', 'timestamp', 'ts', 'createdAt', 'created_at',
      'completedAt', 'lastRequestAt', 'time'];
    for (var i = 0; i < keys.length; i++) {
      var t = parseTs(o && o[keys[i]]);
      if (t != null) return t;
    }
    return null;
  }

  function pick(obj, keys) {
    for (var i = 0; i < keys.length; i++) {
      var v = obj && obj[keys[i]];
      if (v !== undefined && v !== null && v !== '') return v;
    }
    return undefined;
  }

  // Extract a normal usage object from any of the known shapes.
  // Accepts camelCase (ZCode normalized) and snake_case (raw provider payloads).
  function extractUsage(u) {
    if (!u || typeof u !== 'object') return null;
    var input = pick(u, ['inputTokens', 'input_tokens', 'promptTokens', 'prompt_tokens', 'promptEvalCount']);
    var output = pick(u, ['outputTokens', 'output_tokens', 'completionTokens', 'completion_tokens', 'evalCount']);
    var cacheRead = pick(u, ['cacheReadTokens', 'cache_read_input_tokens', 'cache_read_tokens', 'cachedInputTokens', 'cached_input_tokens']);
    var cacheWrite = pick(u, ['cacheWriteTokens', 'cache_creation_input_tokens', 'cache_creation_tokens', 'cacheWriteInputTokens']);
    if (input === undefined && output === undefined) return null;
    return {
      input: toNum(input),
      output: toNum(output),
      cacheRead: toNum(cacheRead),
      cacheWrite: toNum(cacheWrite)
    };
  }

  // Deep-search an object (bounded depth) for the first usage-like object.
  function findUsageDeep(o, depth) {
    if (!o || typeof o !== 'object' || depth > 4) return null;
    var direct = extractUsage(o);
    if (direct) return direct;
    for (var k in o) {
      if (!Object.prototype.hasOwnProperty.call(o, k)) continue;
      var v = o[k];
      if (v && typeof v === 'object') {
        var found = findUsageDeep(v, depth + 1);
        if (found) return found;
      }
    }
    return null;
  }

  function findStringDeep(o, re, depth) {
    if (!o || typeof o !== 'object' || depth > 3) return undefined;
    for (var k in o) {
      if (!Object.prototype.hasOwnProperty.call(o, k)) continue;
      var v = o[k];
      if (typeof v === 'string' && re.test(k) && v.length < 200) return v;
      if (v && typeof v === 'object') {
        var found = findStringDeep(v, re, depth + 1);
        if (found !== undefined) return found;
      }
    }
    return undefined;
  }

  function sessionFromFileName(fileName) {
    var m = /sess[_-]([0-9a-fA-F-]{8,})/.exec(fileName);
    return m ? m[1] : null;
  }

  function cleanTask(text) {
    if (!text) return '';
    var s = String(text).replace(/\s+/g, ' ').trim();
    return s.length > TASK_MAX ? s.slice(0, TASK_MAX - 1) + '…' : s;
  }

  // Content of an Anthropic-style message → text
  function contentToText(content) {
    if (typeof content === 'string') return content;
    if (Array.isArray(content)) {
      var parts = [];
      for (var i = 0; i < content.length; i++) {
        var c = content[i];
        if (c && c.type === 'text' && typeof c.text === 'string') parts.push(c.text);
      }
      return parts.join(' ');
    }
    return '';
  }

  // Strip harness noise (system reminders, command wrappers) from a prompt
  function stripNoise(t) {
    return String(t || '')
      .replace(/<system-reminder>[\s\S]*?<\/system-reminder>/g, '')
      .replace(/<task-notification>[\s\S]*?<\/task-notification>/g, '')
      .replace(/<command-message>[\s\S]*?<\/command-message>/g, '');
  }

  function firstUserText(messages) {
    if (!Array.isArray(messages)) return '';
    var fallback = '';
    for (var i = 0; i < messages.length; i++) {
      var m = messages[i];
      var role = m && m.role;
      if (role !== 'user' && role !== 'human') continue;
      var raw = contentToText(m.content !== undefined ? m.content : m.text);
      if (!raw.trim()) continue;
      if (!fallback) fallback = raw;
      var t = stripNoise(raw).trim();
      if (t) return t;
    }
    return fallback;
  }

  // ---------- per-agent record builders ----------

  function mkRec(o, usage, fileName, agentType, extra) {
    if (!usage) return null;
    var session = pick(o, ['sessionId', 'session_id', 'conversationId', 'conversation_id']) ||
      sessionFromFileName(fileName) || (extra && extra.session) || 'unknown';
    return {
      ts: firstTs(o),
      agentType: agentType,
      session: session,
      model: (extra && extra.model) || findStringDeep(o, /^(modelId|model|modelName)$/i, 0) || 'unknown',
      provider: (extra && extra.provider) || '',
      input: usage.input,
      output: usage.output,
      cacheRead: usage.cacheRead,
      cacheWrite: usage.cacheWrite,
      requestId: pick(o, ['requestId', 'request_id', 'id', 'responseId']) || '',
      file: fileName,
      project: (function () {
        var p = pick(o, ['project', 'projectName', 'projectPath', 'project_path', 'workspace', 'workspaceDirectory']);
        if (p) return String(p);
        var cwd = pick(o, ['cwd', 'workingDirectory', 'working_directory']);
        if (cwd) {
          var parts = String(cwd).replace(/[\\/]+$/, '').split(/[\\/]/);
          return parts[parts.length - 1] || '';
        }
        return '';
      })()
    };
  }

  // ---------- OpenClaw / AutoClaw (agents/<name>/sessions/<uuid>.jsonl) ----------
  // Line types: {type:'session', id, cwd, timestamp} header, model changes
  // ({type:'model_change', modelId}), user/assistant messages. Assistant
  // messages carry usage {input, output, cacheRead, cacheWrite, reasoningTokens}
  // where reasoning is already counted inside output. One session per file;
  // project comes from the session header's cwd basename.

  function parseOpenClawFile(text, fileName, out) {
    var lines = text.split('\n');
    var sessionId = sessionFromFileName(fileName) || 'unknown';
    var cwd = '', model = '', task = '', started = null;
    var project = '';
    for (var i = 0; i < lines.length && i < MAX_LINES; i++) {
      var line = lines[i].trim();
      if (!line) continue;
      var o = tryJson(line);
      if (!o) continue;
      if (o.type === 'session') {
        if (o.id) sessionId = o.id;
        if (o.cwd) {
          cwd = String(o.cwd);
          var parts = cwd.replace(/[\\/]+$/, '').split(/[\\/]/);
          project = parts[parts.length - 1] || '';
        }
        started = parseTs(o.timestamp) || started;
        continue;
      }
      if (o.type === 'model_change' && o.modelId) { model = o.modelId; continue; }
      if (o.type === 'message' && o.message) {
        var msg = o.message;
        if (msg.role === 'user' && !task) {
          var c = msg.content;
          var s = typeof c === 'string' ? c : '';
          if (!s && Array.isArray(c)) {
            for (var j = 0; j < c.length; j++) {
              if (c[j] && typeof c[j].text === 'string') { s = c[j].text; break; }
            }
          }
          if (s) {
            // AutoClaw wraps each user turn in policy/system-reminder blocks
            // with the real request inside <<<AUTOCLAW_USER_AUTHORED_REQUEST_START>>>
            // … END>>> markers. Unwrap first; only fall back to the raw text
            // when it is genuinely authored (not an injected wrapper).
            var mStart = s.indexOf('<<<AUTOCLAW_USER_AUTHORED_REQUEST_START>>>');
            if (mStart >= 0) {
              var body = s.slice(mStart + 42);
              var mEnd = body.indexOf('<<<AUTOCLAW_USER_AUTHORED_REQUEST_END>>>');
              if (mEnd >= 0) body = body.slice(0, mEnd);
              task = cleanTask(body);
            } else if (!/^\s*(<system-reminder>|<\{|<<<)/i.test(s)) {
              task = cleanTask(s);
            }
          }
          continue;
        }
        if (msg.role === 'assistant' && msg.usage) {
          var u = msg.usage;
          var input = toNum(u.input), output = toNum(u.output);
          var cacheRead = toNum(u.cacheRead), cacheWrite = toNum(u.cacheWrite);
          if (!input && !output && !cacheRead) continue;
          out.records.push({
            ts: parseTs(o.timestamp) || started,
            agentType: 'openclaw',
            session: sessionId,
            model: model || 'unknown',
            provider: 'openclaw',
            input: input,
            output: output, // OpenClaw already includes reasoning in output
            cacheRead: cacheRead,
            cacheWrite: cacheWrite,
            requestId: o.id || '',
            file: fileName,
            project: project,
            task: task
          });
          if (task) out.sessions[sessionId] = task;
        }
      }
    }
  }



  // ---------- ZCode (model-io-*.jsonl) ----------
  function parseZCode(obj, fileName, out) {
    var usage = extractUsage(obj.response && obj.response.usage) ||
      extractUsage(obj.usage) ||
      extractUsage(obj.response && obj.response.providerMetadata &&
        obj.response.providerMetadata.anthropic && obj.response.providerMetadata.anthropic.usage);
    if (!usage) return false;
    var model = obj.model && obj.model.modelId ? obj.model.modelId :
      (obj.response && obj.response.modelId) || obj.modelId;
    var rec = mkRec(obj, usage, fileName, 'zcode', {
      model: model || undefined,
      provider: (obj.model && obj.model.providerId) || ''
    });
    if (!rec) return false;
    rec.session = obj.sessionId || sessionFromFileName(fileName) || 'no-session';
    out.records.push(rec);
    // first user prompt for this session → task label
    if (obj.sessionId && !out.sessions[obj.sessionId]) {
      var msgs = (obj.request && (obj.request.messages || (obj.request.body && obj.request.body.messages))) || [];
      var t = firstUserText(msgs);
      if (t) out.sessions[obj.sessionId] = cleanTask(t);
    }
    return true;
  }

  // ---------- Claude Code (~/.claude/projects/**/*.jsonl) ----------

  function parseClaude(obj, fileName, out) {
    var type = obj.type;
    if (type === 'assistant' && obj.message && extractUsage(obj.message.usage)) {
      var rec = mkRec(obj, extractUsage(obj.message.usage), fileName, 'claude-code', {
        model: obj.message.model || undefined
      });
      rec.session = obj.sessionId || sessionFromFileName(fileName) || 'unknown';
      if (!rec.ts && obj.timestamp) rec.ts = parseTs(obj.timestamp);
      out.records.push(rec);
      return true;
    }
    if (type === 'user' && obj.sessionId && !out.sessions[obj.sessionId]) {
      var c = obj.message && obj.message.content;
      // skip tool_result-only user turns
      var isToolResult = Array.isArray(c) && c.length &&
        c.every(function (b) { return b && b.type === 'tool_result'; });
      if (!isToolResult) {
        var t = cleanTask(contentToText(c));
        if (t && !/^caveat:/i.test(t)) out.sessions[obj.sessionId] = t;
      }
    }
    return false;
  }

  // ---------- OpenAI Codex CLI (~/.codex/sessions/**/*.jsonl) ----------

  function parseCodexFile(text, fileName, out) {
    // token_count events carry cumulative totals; keep the last seen to diff
    var prev = null;
    var lines = text.split('\n');
    for (var i = 0; i < lines.length && i < MAX_LINES; i++) {
      var line = lines[i].trim();
      if (!line) continue;
      var o = tryJson(line);
      if (!o) { out.errors++; continue; }
      var p = o.payload || {};
      if (o.type === 'session_meta') {
        out.meta.codexSession = p.id || sessionFromFileName(fileName);
        if (p.model) out.meta.codexModel = p.model;
        continue;
      }
      if (o.type === 'event_msg' && p.type === 'user_message' && p.message) {
        var sess = out.meta.codexSession || sessionFromFileName(fileName) || 'unknown';
        if (!out.sessions[sess]) out.sessions[sess] = cleanTask(p.message);
        continue;
      }
      var info = null;
      if (o.type === 'event_msg' && p.type === 'token_count') info = p.info;
      else if (p && p.type === 'token_count') info = p.info;
      else if (p && p.total_token_usage) info = p;
      if (!info) continue;
      var total = extractUsage(info.total_token_usage || {});
      var last = extractUsage(info.last_token_usage || {});
      var usage = null;
      if (last && (last.input || last.output || last.cacheRead)) usage = last;
      else if (total) {
        if (prev) {
          usage = {
            input: Math.max(0, total.input - prev.input),
            output: Math.max(0, total.output - prev.output),
            cacheRead: Math.max(0, total.cacheRead - prev.cacheRead),
            cacheWrite: Math.max(0, total.cacheWrite - prev.cacheWrite)
          };
        } else {
          usage = total;
        }
        prev = total;
      }
      if (!usage) continue;
      var rec = mkRec(o, usage, fileName, 'codex', {
        model: info.model || out.meta.codexModel || undefined,
        session: out.meta.codexSession || sessionFromFileName(fileName) || 'unknown'
      });
      if (rec) out.records.push(rec);
    }
    return true;
  }

  // ---------- generic auto-detect (any new agent's .jsonl) ----------

  function parseGeneric(obj, fileName, out) {
    var usage = findUsageDeep(obj, 0);
    if (!usage) return false;
    var rec = mkRec(obj, usage, fileName, 'generic', {});
    if (!rec) return false;
    var sess = findStringDeep(obj, /^(sessionId|session_id|conversationId|threadId)$/i, 0);
    if (sess) rec.session = sess;
    out.records.push(rec);
    if (rec.session !== 'unknown' && !out.sessions[rec.session]) {
      // try to label the task from an obvious user-message/prompt field
      var t = findStringDeep(obj, /^(prompt|userMessage|user_message|query|task)$/i, 0);
      if (t) out.sessions[rec.session] = cleanTask(t);
    }
    return true;
  }

  // ---------- detection ----------

  function tryJson(line) {
    try { return JSON.parse(line); } catch (e) { return null; }
  }

  function scoreLine(o) {
    if (!o || typeof o !== 'object') return null;
    if (o.type === 'session' && (o.cwd !== undefined || o.id) && o.version) return 'openclaw';
    if (o.type === 'model_change' && o.modelId) return 'openclaw';
    if (o.type === 'model_io' || (o.response && o.response.usage) ||
        (o.model && o.model.modelId)) return 'zcode';
    if (o.type === 'assistant' && o.message && o.message.usage) return 'claude-code';
    if (o.type === 'session_meta' ||
        (o.payload && (o.payload.type === 'token_count' || o.payload.type === 'session_meta'))) return 'codex';
    if (findUsageDeep(o, 0)) return 'generic';
    return null;
  }

  // Guess which agent produced a file from its first parseable lines.
  // Lines can be huge (full request/response bodies), so iterate by indexOf
  // and stop after a scan budget instead of slicing a fixed char window.
  function detect(text) {
    var counts = {};
    var pos = 0, parsed = 0, budget = 4 * 1024 * 1024;
    while (parsed < 40 && budget > 0) {
      var nl = text.indexOf('\n', pos);
      var end = nl === -1 ? text.length : nl;
      var line = text.slice(pos, end);
      pos = end + 1;
      budget -= line.length;
      if (line.trim()) {
        var kind = scoreLine(tryJson(line.trim()));
        if (kind) { counts[kind] = (counts[kind] || 0) + 1; parsed++; }
      }
      if (nl === -1) break;
    }
    var best = null, bestN = 0;
    ['zcode', 'claude-code', 'codex', 'openclaw'].forEach(function (k) {
      if ((counts[k] || 0) > bestN) { best = k; bestN = counts[k]; }
    });
    return best || (counts.generic ? 'generic' : null);
  }

  // ---------- file entry point ----------

  function parseFile(text, agentType, fileName) {
    var out = { records: [], sessions: {}, errors: 0, meta: {}, agentType: agentType };
    if (agentType === 'auto') {
      var guess = detect(text);
      agentType = guess || 'generic';
      out.agentType = agentType;
    }
    if (agentType === 'codex') {
      parseCodexFile(text, fileName, out);
      finish(out);
      return out;
    }
    if (agentType === 'openclaw') {
      parseOpenClawFile(text, fileName, out);
      finish(out);
      return out;
    }
    var perLine = agentType === 'zcode' ? parseZCode :
      agentType === 'claude-code' ? parseClaude : parseGeneric;
    var lines = text.split('\n');
    for (var i = 0; i < lines.length && i < MAX_LINES; i++) {
      var line = lines[i].trim();
      if (!line) continue;
      var o = tryJson(line);
      if (!o) { out.errors++; continue; }
      perLine(o, fileName, out);
    }
    finish(out);
    return out;
  }

  // JSON files that hold a single object or an array instead of JSONL:
  // try per-line first; if nothing parsed, treat the whole file as one JSON doc.
  function parseMaybeJson(text, agentType, fileName) {
    var out = parseFile(text, agentType, fileName);
    if (out.records.length === 0 && /\.json$/i.test(fileName)) {
      var o = tryJson(text.trim());
      if (o) {
        var arr = Array.isArray(o) ? o : [o];
        var out2 = { records: [], sessions: {}, errors: 0, meta: {}, agentType: agentType };
        var perLine = agentType === 'zcode' ? parseZCode :
          agentType === 'claude-code' ? parseClaude : parseGeneric;
        arr.forEach(function (item) { perLine(item, fileName, out2); });
        finish(out2);
        return out2;
      }
    }
    return out;
  }

  function finish(out) {
    out.records.forEach(function (r) {
      r.task = out.sessions[r.session] || '';
    });
  }

  root.TR_PARSERS = {
    parseFile: parseMaybeJson,
    detect: detect,
    extractUsage: extractUsage,
    parseTs: parseTs,
    cleanTask: cleanTask,
    _internals: {
      firstUserText: firstUserText,
      contentToText: contentToText,
      findUsageDeep: findUsageDeep
    }
  };
})(typeof window !== 'undefined' ? window : globalThis);

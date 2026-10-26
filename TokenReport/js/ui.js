'use strict';
  // ---------- theme ----------

  // Theme: dark → light → auto cycle (auto follows the device appearance).
  var themeMq = window.matchMedia ? matchMedia('(prefers-color-scheme: light)') : null;

  function applyTheme() {
    var mode = state.theme === 'dark' || state.theme === 'light' || state.theme === 'auto'
      ? state.theme : 'dark';
    var resolved = mode === 'auto'
      ? (themeMq && themeMq.matches ? 'light' : 'dark') : mode;
    document.documentElement.setAttribute('data-theme', resolved);
    var btn = $('#btnTheme');
    if (btn) {
      btn.textContent = mode === 'dark' ? '🌙' : mode === 'light' ? '☀️' : '🌗';
      btn.title = mode === 'dark' ? 'Dark theme — click for light'
        : mode === 'light' ? 'Light theme — click to follow this device\'s appearance'
        : 'Follows this device\'s appearance — click for dark';
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

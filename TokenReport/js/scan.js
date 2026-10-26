'use strict';
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

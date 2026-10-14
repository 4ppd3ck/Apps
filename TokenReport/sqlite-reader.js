/* Minimal read-only SQLite snapshot reader with WAL replay.
 *
 * Why hand-rolled: the browser cannot run the sqlite3 CLI, sql.js cannot
 * replay a -wal file, and agents (Copilot CLI) keep their newest rows in the
 * WAL — a main-db-only read would silently miss recent requests.
 *
 * Implements just enough of the file format for full table scans:
 *   - db header (page size, reserved bytes)
 *   - table b-trees (interior 0x05 / leaf 0x0D) with overflow chains
 *   - record decoding (varints + serial types), UTF-8 text
 *   - WAL: salt+checksum frame validation, commit-boundary page map
 * No writes, no indexes, no schema parsing beyond CREATE TABLE column names.
 */
(function (root) {
  'use strict';

  var textDecoder = typeof TextDecoder !== 'undefined' ? new TextDecoder('utf-8') : null;

  function utf8(u8) {
    if (textDecoder) return textDecoder.decode(u8);
    return decodeURIComponent(escape(String.fromCharCode.apply(null, u8)));
  }

  // ---------- varints & records ----------

  function readVarint(u8, pos) {
    var result = 0;
    for (var i = 0; i < 8; i++) {
      var b = u8[pos + i];
      result = result * 128 + (b & 0x7f);
      if (!(b & 0x80)) return { value: result, next: pos + i + 1 };
    }
    // 9th byte contributes all 8 bits
    result = result * 256 + u8[pos + 8];
    return { value: result, next: pos + 9 };
  }

  function decodeInt(u8, pos, n) {
    var v = 0;
    for (var i = 0; i < n; i++) v = v * 256 + u8[pos + i];
    // sign-extend
    var bits = n * 8;
    if (bits < 53 && v >= Math.pow(2, bits - 1)) v -= Math.pow(2, bits);
    return v;
  }

  function decodeRecord(payload) {
    var headerSize = readVarint(payload, 0);
    var types = [];
    var p = headerSize.next;
    while (p < headerSize.value) {
      var t = readVarint(payload, p);
      types.push(t.value);
      p = t.next;
    }
    var values = [];
    var body = headerSize.value;
    for (var i = 0; i < types.length; i++) {
      var st = types[i];
      if (st === 0) values.push(null);
      else if (st >= 1 && st <= 6) {
        var n = [null, 1, 2, 3, 4, 6, 8][st];
        values.push(decodeInt(payload, body, n));
        body += n;
      } else if (st === 7) {
        var b = payload;
        var off = body;
        // big-endian float64
        var buf = new ArrayBuffer(8), view = new DataView(buf);
        for (var k = 0; k < 8; k++) view.setUint8(k, b[off + k]);
        values.push(view.getFloat64(0));
        body += 8;
      } else if (st === 8) values.push(0);
      else if (st === 9) values.push(1);
      else if (st >= 12 && st % 2 === 0) {
        var len = (st - 12) / 2;
        values.push(payload.slice(body, body + len));
        body += len;
      } else {
        var len2 = (st - 13) / 2;
        values.push(utf8(payload.slice(body, body + len2)));
        body += len2;
      }
    }
    return values;
  }

  // ---------- SQLite snapshot ----------

  function Snapshot(dbBytes, walBytes) {
    this.db = dbBytes instanceof Uint8Array ? dbBytes : new Uint8Array(dbBytes);
    // An empty (-wal file can be 0 bytes) or truncated buffer is not a WAL —
    // and an empty Uint8Array is truthy, so it must be checked by length
    // before buildWalMap mounts a zero-length DataView (which throws
    // "Offset is outside the bounds of the DataView").
    this.wal = walBytes && walBytes.length ? (walBytes instanceof Uint8Array ? walBytes : new Uint8Array(walBytes)) : null;
    if (utf8(this.db.slice(0, 16)) !== 'SQLite format 3\x00') {
      throw new Error('not a SQLite database');
    }
    var ps = (this.db[16] << 8) | this.db[17];
    this.pageSize = ps === 1 ? 65536 : ps;
    this.reserved = this.db[20];
    this.usable = this.pageSize - this.reserved;
    this.walMap = this.wal ? this.buildWalMap(this.wal) : null;
    this.effectivePageSize = this.pageSize;
    this.pageCount = Math.floor(this.db.length / this.pageSize);
    if (this.walMap && this.walMap.dbSize) this.pageCount = Math.max(this.pageCount, this.walMap.dbSize);
  }

  Snapshot.prototype.page = function (no) {
    if (this.walMap && this.walMap.pages[no] != null) {
      var off = this.walMap.pages[no];
      return this.wal.subarray(off, off + this.pageSize);
    }
    if (no < 1 || no > this.pageCount) return null;
    var start = (no - 1) * this.pageSize;
    if (start + this.pageSize > this.db.length) return null;
    return this.db.subarray(start, start + this.pageSize);
  };

  // Walk WAL frames up to the last valid commit; later frames win per page.
  Snapshot.prototype.buildWalMap = function (wal) {
    if (!wal || wal.length < 32) return null; // not a usable WAL
    var dv = new DataView(wal.buffer, wal.byteOffset, wal.byteLength);
    var magic = dv.getUint32(0);
    if (magic !== 0x377f0682 && magic !== 0x377f0683) return null;
    var little = magic === 0x377f0682;
    var walPageSize = dv.getUint32(8);
    if (walPageSize !== this.pageSize) return null;
    var salt1 = dv.getUint32(16), salt2 = dv.getUint32(20);
    var s1 = 0, s2 = 0;
    // checksum covers the first 24 bytes of the wal header
    var c = walChecksum(wal, 0, 24, little, 0, 0);
    s1 = c[0]; s2 = c[1];
    var pages = {};
    var frameSize = 24 + this.pageSize;
    var pos = 32;
    var dbSize = 0;
    var frameNo = 0;
    var fdv = new DataView(wal.buffer, wal.byteOffset, wal.byteLength);
    while (pos + frameSize <= wal.length) {
      var pgno = fdv.getUint32(pos);
      var sizeAfter = fdv.getUint32(pos + 4);
      var fs1 = fdv.getUint32(pos + 8);
      var fs2 = fdv.getUint32(pos + 12);
      var fc1 = fdv.getUint32(pos + 16);
      var fc2 = fdv.getUint32(pos + 20);
      if (fs1 !== salt1 || fs2 !== salt2) break;          // stale frame from an older WAL generation
      // cumulative checksum: 8 bytes of frame header + page data
      c = walChecksum(wal, pos, 8, little, s1, s2);
      c = walChecksum(wal, pos + 24, this.pageSize, little, c[0], c[1]);
      if (c[0] !== fc1 || c[1] !== fc2) break;            // torn/partial write — stop at last good frame
      s1 = c[0]; s2 = c[1];
      frameNo++;
      pages[pgno] = pos + 24;
      if (sizeAfter !== 0) { dbSize = sizeAfter; }        // commit frame
      pos += frameSize;
    }
    return { pages: pages, dbSize: dbSize, frames: frameNo };
  };

  function walChecksum(u8, start, len, little, s1, s2) {
    var dv = new DataView(u8.buffer, u8.byteOffset + start, len);
    var words = Math.floor(len / 4);
    for (var i = 0; i < words; i += 2) {
      var w0 = little ? dv.getUint32(i * 4, true) : dv.getUint32(i * 4, false);
      var w1 = little ? dv.getUint32(i * 4 + 4, true) : dv.getUint32(i * 4 + 4, false);
      s1 = (s1 + w0 + s2) >>> 0;
      s2 = (s2 + w1 + s1) >>> 0;
    }
    return [s1, s2];
  }

  // ---------- table b-tree traversal ----------

  Snapshot.prototype.tableRows = function (rootPage) {
    var rows = [];
    this.walkBtree(rootPage, rows, 0);
    return rows;
  };

  Snapshot.prototype.walkBtree = function (pageNo, rows, depth) {
    if (depth > 30) return;
    var pg = this.page(pageNo);
    if (!pg) return;
    var hdr = pageNo === 1 ? 100 : 0;
    var type = pg[hdr];
    var nCells = (pg[hdr + 3] << 8) | pg[hdr + 4];
    var i, cellOff;
    if (type === 5) { // interior table
      var rightmost = (pg[hdr + 8] << 24) | (pg[hdr + 9] << 16) | (pg[hdr + 10] << 8) | pg[hdr + 11];
      var ptrArray = hdr + 12;
      for (i = 0; i < nCells; i++) {
        cellOff = (pg[ptrArray + i * 2] << 8) | pg[ptrArray + i * 2 + 1];
        var child = (pg[cellOff] << 24) | (pg[cellOff + 1] << 16) | (pg[cellOff + 2] << 8) | pg[cellOff + 3];
        this.walkBtree(child, rows, depth + 1);
      }
      this.walkBtree(rightmost, rows, depth + 1);
    } else if (type === 13) { // leaf table
      var ptr = hdr + 8;
      for (i = 0; i < nCells; i++) {
        cellOff = (pg[ptr + i * 2] << 8) | pg[ptr + i * 2 + 1];
        try {
          var payloadLen = readVarint(pg, cellOff);
          var rowid = readVarint(pg, payloadLen.next);
          rows.push(this.readPayload(pg, rowid.next, payloadLen.value));
        } catch (e) { /* skip corrupt cell */ }
      }
    }
  };

  // Read a leaf-cell payload, following the overflow chain when spilled.
  Snapshot.prototype.readPayload = function (pg, pos, payloadLen) {
    var U = this.usable;
    var X = U - 35;
    var local;
    if (payloadLen <= X) {
      local = payloadLen;
    } else {
      var M = ((U - 12) * 32 / 255) - 23;
      M = Math.floor(M);
      var K = M + ((payloadLen - M) % (U - 4));
      local = K <= X ? K : M;
    }
    if (pos + local > pg.length) throw new Error('cell out of bounds');
    var payload = pg.slice(pos, pos + local);
    if (local < payloadLen) {
      var overflowNo = (pg[pos + local] << 24) | (pg[pos + local + 1] << 16) | (pg[pos + local + 2] << 8) | pg[pos + local + 3];
      var remaining = payloadLen - local;
      var guard = 0;
      while (remaining > 0 && overflowNo && guard++ < 100000) {
        var opg = this.page(overflowNo);
        if (!opg) break;
        var next = (opg[0] << 24) | (opg[1] << 16) | (opg[2] << 8) | opg[3];
        var chunk = Math.min(remaining, U - 4);
        var part = opg.slice(4, 4 + chunk);
        var merged = new Uint8Array(payload.length + part.length);
        merged.set(payload); merged.set(part, payload.length);
        payload = merged;
        remaining -= chunk;
        overflowNo = next;
      }
    }
    return decodeRecord(payload);
  };

  // ---------- schema ----------

  // Parse column names out of "CREATE TABLE name (col1 TYPE, col2 TYPE, ...)"
  function parseColumns(sql) {
    var open = sql.indexOf('(');
    var close = sql.lastIndexOf(')');
    if (open === -1 || close === -1) return null;
    var inner = sql.slice(open + 1, close);
    // split on top-level commas
    var parts = [], depth = 0, cur = '', inQ = null;
    for (var i = 0; i < inner.length; i++) {
      var ch = inner[i];
      if (inQ) { cur += ch; if (ch === inQ) inQ = null; continue; }
      if (ch === '"' || ch === '`' || ch === '[') { inQ = ch === '[' ? ']' : ch; cur += ch; continue; }
      if (ch === '(') depth++;
      if (ch === ')') depth--;
      if (ch === ',' && depth === 0) { parts.push(cur); cur = ''; continue; }
      cur += ch;
    }
    parts.push(cur);
    var cols = [];
    var skip = /^(PRIMARY|UNIQUE|CHECK|FOREIGN|CONSTRAINT)\b/i;
    for (var j = 0; j < parts.length; j++) {
      var def = parts[j].trim();
      if (!def || skip.test(def)) continue;
      var m = /^"([^"]+)"|^\[([^\]]+)\]|^`([^`]+)`|^([A-Za-z_][A-Za-z0-9_]*)/.exec(def);
      if (m) cols.push(m[1] || m[2] || m[3] || m[4]);
    }
    return cols;
  }

  Snapshot.prototype.tables = function () {
    var master = this.tableRows(1);
    var out = {};
    for (var i = 0; i < master.length; i++) {
      var r = master[i];
      // sqlite_master: type(0), name(1), tbl_name(2), rootpage(3), sql(4)
      if (r[0] === 'table' && typeof r[3] === 'number' && r[3] > 0) {
        out[r[1]] = { rootPage: r[3], sql: r[4] };
      }
    }
    return out;
  };

  // Full scan of a table → array of objects keyed by parsed column names.
  Snapshot.prototype.readTable = function (name) {
    var t = this.tables()[name];
    if (!t) return [];
    var cols = parseColumns(t.sql || '') || [];
    var raw = this.tableRows(t.rootPage);
    var rows = [];
    for (var i = 0; i < raw.length; i++) {
      var vals = raw[i];
      var obj = {};
      for (var c = 0; c < cols.length; c++) {
        obj[cols[c]] = c < vals.length ? vals[c] : null;
      }
      rows.push(obj);
    }
    return rows;
  };

  root.TR_SQLITE = { Snapshot: Snapshot, parseColumns: parseColumns, decodeRecord: decodeRecord };
})(typeof window !== 'undefined' ? window : globalThis);

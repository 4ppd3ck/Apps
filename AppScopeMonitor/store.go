// SQLite event store + in-process event bus with SSE fan-out
// (mirrors monitor/store.py).
package monitor

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite" // pure-Go sqlite driver (no cgo)
)

// Schema is the exact schema from store.py (events, blocks, meta tables).
const Schema = `
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    category TEXT NOT NULL,      -- privacy | file | network | system
    kind TEXT NOT NULL,          -- camera_start, mic_stop, file_open, connection, ...
    app TEXT,
    pid INTEGER,
    user TEXT,
    device TEXT,
    path TEXT,
    remote TEXT,
    local TEXT,
    proto TEXT,
    direction TEXT,
    detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts);
CREATE INDEX IF NOT EXISTS idx_events_cat ON events (category, ts DESC);
CREATE TABLE IF NOT EXISTS traffic_samples (
    ts REAL PRIMARY KEY,
    rx_bytes INTEGER NOT NULL,
    tx_bytes INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_traffic_samples_ts ON traffic_samples (ts);
CREATE TABLE IF NOT EXISTS connection_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identity TEXT NOT NULL,
    started_at REAL NOT NULL,
    last_seen REAL NOT NULL,
    ended_at REAL,
    missed_snapshots INTEGER NOT NULL DEFAULT 0,
    app TEXT,
    pid TEXT,
    proto TEXT,
    local TEXT,
    remote TEXT,
    scope TEXT,
    state TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_connection_history_last_seen
    ON connection_history (last_seen DESC);
CREATE TABLE IF NOT EXISTS destination_traffic (
    app TEXT NOT NULL,
    remote_ip TEXT NOT NULL,
    bytes_in INTEGER NOT NULL DEFAULT 0,
    bytes_out INTEGER NOT NULL DEFAULT 0,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    PRIMARY KEY (app, remote_ip)
);
CREATE INDEX IF NOT EXISTS idx_destination_traffic_last_seen
    ON destination_traffic (last_seen);
CREATE TABLE IF NOT EXISTS app_traffic (
    app TEXT PRIMARY KEY,
    bytes_in INTEGER NOT NULL DEFAULT 0,
    bytes_out INTEGER NOT NULL DEFAULT 0,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS blocks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    type TEXT NOT NULL,          -- ip | connection | app
    value TEXT NOT NULL,         -- ip | ip:port | app name/path
    app_path TEXT,
    detail TEXT,
    status TEXT,                 -- enforced | queued | error | unsupported
    status_detail TEXT
);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
`

// Event is one monitoring event. Nullable fields are `any` so they marshal
// to JSON null / SQL NULL exactly like the Python dicts.
type Event struct {
	ID        int64   `json:"id"`
	Ts        float64 `json:"ts"`
	Category  string  `json:"category"`
	Kind      string  `json:"kind"`
	App       any     `json:"app"`
	Pid       any     `json:"pid"`
	User      any     `json:"user"`
	Device    any     `json:"device"`
	Path      any     `json:"path"`
	Remote    any     `json:"remote"`
	Local     any     `json:"local"`
	Proto     any     `json:"proto"`
	Direction any     `json:"direction"`
	Detail    any     `json:"detail"`
}

// Block is one enforcement rule (blocks table row).
type Block struct {
	ID           int64   `json:"id"`
	Ts           float64 `json:"ts"`
	Type         string  `json:"type"`
	Value        string  `json:"value"`
	AppPath      *string `json:"app_path"`
	Detail       *string `json:"detail"`
	Status       *string `json:"status"`
	StatusDetail *string `json:"status_detail"`
}

// Store wraps the SQLite database.
type Store struct {
	dbPath string
	db     *sql.DB
	mu     sync.Mutex

	stopOnce sync.Once
	stopCh   chan struct{}

	started       bool
	retentionDays int
	retDone       chan struct{}
}

// NewStore opens (and initialises) the database at dbPath.
func NewStore(dbPath string) (*Store, error) {
	s := &Store{
		dbPath:  dbPath,
		stopCh:  make(chan struct{}),
		retDone: make(chan struct{}),
	}
	if dir := filepath.Dir(dbPath); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite", s.dbPath)
	if err != nil {
		return nil, err
	}
	// Single connection mirrors the Python lock + one connection; also
	// avoids SQLITE_BUSY entirely.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	s.db = db
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("pragma journal_mode: %w", err)
	}
	if _, err := db.Exec(Schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("schema: %w", err)
	}
	return s, nil
}

// Start launches the retention loop.
func (s *Store) Start(retentionDays int) {
	s.mu.Lock()
	s.retentionDays = retentionDays
	s.started = true
	s.mu.Unlock()
	go s.retentionLoop()
}

// Stop signals the retention loop to finish (waits if it was started).
func (s *Store) Stop() {
	s.stopOnce.Do(func() { close(s.stopCh) })
	s.mu.Lock()
	started := s.started
	s.mu.Unlock()
	if started {
		<-s.retDone
	}
}

// Close closes the underlying database handle.
func (s *Store) Close() error { return s.db.Close() }

// DBPath returns the database file path.
func (s *Store) DBPath() string { return s.dbPath }

func (s *Store) retentionLoop() {
	defer close(s.retDone)
	for {
		select {
		case <-s.stopCh:
			return
		case <-time.After(1800 * time.Second):
		}
		cutoff := Now() - float64(s.retentionDays)*86400
		if _, err := s.DeleteBefore(cutoff); err != nil {
			fmt.Printf("[store] retention error: %v\n", err)
		}
	}
}

func dbStr(v any) any {
	switch x := v.(type) {
	case nil:
		return nil
	case string:
		return x
	case float64:
		return int64(x)
	case int:
		return int64(x)
	case int64:
		return x
	default:
		return StrOf(x)
	}
}

// Insert persists one event and sets its ID (mirrors Store.insert).
func (s *Store) Insert(ev *Event) error {
	if ev.Ts == 0 {
		ev.Ts = Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(
		`INSERT INTO events (ts, category, kind, app, pid, user, device, path,`+
			` remote, local, proto, direction, detail)`+
			` VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		ev.Ts, ev.Category, ev.Kind, dbStr(ev.App), dbStr(ev.Pid), dbStr(ev.User),
		dbStr(ev.Device), dbStr(ev.Path), dbStr(ev.Remote), dbStr(ev.Local),
		dbStr(ev.Proto), dbStr(ev.Direction), dbStr(ev.Detail))
	if err != nil {
		return err
	}
	id, err := res.LastInsertId()
	if err == nil {
		ev.ID = id
	}
	return nil
}

// Query fetches events, newest first (mirrors Store.query).
func (s *Store) Query(category string, since float64, limit int, kinds []string) ([]*Event, error) {
	sqlStr := `SELECT id, ts, category, kind, app, pid, user, device, path, remote,` +
		` local, proto, direction, detail FROM events WHERE ts > ?`
	args := []any{since}
	if category != "" {
		sqlStr += " AND category = ?"
		args = append(args, category)
	}
	if len(kinds) > 0 {
		sqlStr += " AND kind IN (" + placeholders(len(kinds)) + ")"
		for _, k := range kinds {
			args = append(args, k)
		}
	}
	sqlStr += " ORDER BY ts DESC LIMIT ?"
	args = append(args, limit)

	s.mu.Lock()
	rows, err := s.db.Query(sqlStr, args...)
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*Event
	for rows.Next() {
		ev := &Event{}
		var app, user, device, path, remote, local, proto, direction, detail sql.NullString
		var pid sql.NullInt64
		if err := rows.Scan(&ev.ID, &ev.Ts, &ev.Category, &ev.Kind, &app, &pid,
			&user, &device, &path, &remote, &local, &proto, &direction, &detail); err != nil {
			return nil, err
		}
		ev.App = nullAny(app)
		ev.Pid = nullInt(pid)
		ev.User = nullAny(user)
		ev.Device = nullAny(device)
		ev.Path = nullAny(path)
		ev.Remote = nullAny(remote)
		ev.Local = nullAny(local)
		ev.Proto = nullAny(proto)
		ev.Direction = nullAny(direction)
		ev.Detail = nullAny(detail)
		out = append(out, ev)
	}
	return out, rows.Err()
}

func nullInt(v sql.NullInt64) any {
	if !v.Valid {
		return nil
	}
	return v.Int64
}

func placeholders(n int) string {
	b := make([]byte, 0, n*3)
	for i := 0; i < n; i++ {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, '?')
	}
	return string(b)
}

func nullAny(v sql.NullString) any {
	if !v.Valid {
		return nil
	}
	return v.String
}

// Counts returns {category: {kind: n}} for events newer than since.
func (s *Store) Counts(since float64) (map[string]map[string]int64, error) {
	s.mu.Lock()
	rows, err := s.db.Query(
		`SELECT category, kind, COUNT(*) FROM events WHERE ts > ?`+
			` GROUP BY category, kind`, since)
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]map[string]int64{}
	for rows.Next() {
		var cat, kind string
		var n int64
		if err := rows.Scan(&cat, &kind, &n); err != nil {
			return nil, err
		}
		if out[cat] == nil {
			out[cat] = map[string]int64{}
		}
		out[cat][kind] = n
	}
	return out, rows.Err()
}

// DeleteBefore removes retained events and network-history samples before cutoff.
func (s *Store) DeleteBefore(cutoff float64) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec("DELETE FROM events WHERE ts < ?", cutoff)
	if err != nil {
		return 0, err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	if _, err := s.db.Exec("DELETE FROM traffic_samples WHERE ts < ?", cutoff); err != nil {
		return 0, err
	}
	if _, err := s.db.Exec(
		"DELETE FROM connection_history WHERE COALESCE(ended_at, last_seen) < ?", cutoff); err != nil {
		return 0, err
	}
	if _, err := s.db.Exec("DELETE FROM destination_traffic WHERE last_seen < ?", cutoff); err != nil {
		return 0, err
	}
	if _, err := s.db.Exec("DELETE FROM app_traffic WHERE last_seen < ?", cutoff); err != nil {
		return 0, err
	}
	return affected, nil
}

// ConnectionRecord describes one observed connection lifecycle.
type ConnectionRecord struct {
	StartedAt float64  `json:"started_at"`
	LastSeen  float64  `json:"last_seen"`
	EndedAt   *float64 `json:"ended_at"`
	App       string   `json:"app"`
	PID       string   `json:"pid"`
	Protocol  string   `json:"protocol"`
	Local     string   `json:"local"`
	Remote    string   `json:"remote"`
	Scope     string   `json:"scope"`
	State     string   `json:"state"`

	// geo enrichment (filled from the geo cache when available)
	GeoCC      string `json:"geo_cc,omitempty"`
	GeoCountry string `json:"geo_country,omitempty"`
	GeoCity    string `json:"geo_city,omitempty"`
	GeoReverse string `json:"geo_reverse,omitempty"`
	GeoOrg     string `json:"geo_org,omitempty"`
}

type connectionIdentity struct {
	PID      string `json:"pid"`
	App      string `json:"app"`
	Protocol string `json:"protocol"`
	Local    string `json:"local"`
	Remote   string `json:"remote"`
}

// RecordConnectionSnapshot tracks endpoint lifetimes without retaining every
// polling snapshot. Two consecutive missing snapshots mark an endpoint closed.
func (s *Store) RecordConnectionSnapshot(ts float64, connections []map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	active := make(map[string]int64)
	rows, err := tx.Query("SELECT id, identity FROM connection_history WHERE ended_at IS NULL")
	if err != nil {
		return err
	}
	for rows.Next() {
		var id int64
		var identity string
		if err := rows.Scan(&id, &identity); err != nil {
			rows.Close()
			return err
		}
		active[identity] = id
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}

	seen := make(map[string]bool, len(connections))
	for _, connection := range connections {
		app := nullableText(connection["app"])
		pid := nullableText(connection["pid"])
		protocol := strings.ToUpper(nullableText(connection["proto"]))
		local := formatConnectionEndpoint(connection["local_ip"], connection["local_port"])
		remote := formatConnectionEndpoint(connection["remote_ip"], connection["remote_port"])
		identityBytes, err := json.Marshal(connectionIdentity{
			PID: pid, App: app, Protocol: protocol, Local: local, Remote: remote,
		})
		if err != nil {
			return fmt.Errorf("encode connection identity: %w", err)
		}
		identity := string(identityBytes)
		if seen[identity] {
			continue
		}
		seen[identity] = true
		state := NormalizeConnState(nullableText(connection["state"]))
		if state == "" && protocol == "UDP" {
			state = "BOUND"
		}
		scope := "other"
		switch ClassifyIP(nullableText(connection["remote_ip"])) {
		case "external":
			scope = "external"
		case "lan", "loopback":
			scope = "internal"
		}
		if id, exists := active[identity]; exists {
			_, err = tx.Exec(
				`UPDATE connection_history SET last_seen=?, missed_snapshots=0,
				 app=?, pid=?, proto=?, local=?, remote=?, scope=?, state=? WHERE id=?`,
				ts, app, pid, protocol, local, remote, scope, state, id)
		} else {
			_, err = tx.Exec(
				`INSERT INTO connection_history
				 (identity, started_at, last_seen, app, pid, proto, local, remote, scope, state)
				 VALUES (?,?,?,?,?,?,?,?,?,?)`,
				identity, ts, ts, app, pid, protocol, local, remote, scope, state)
		}
		if err != nil {
			return fmt.Errorf("record connection snapshot: %w", err)
		}
	}

	for identity, id := range active {
		if seen[identity] {
			continue
		}
		if _, err := tx.Exec(
			`UPDATE connection_history SET missed_snapshots=missed_snapshots+1,
			 ended_at=CASE WHEN missed_snapshots+1 >= 2 THEN ? ELSE ended_at END,
			 state=CASE WHEN missed_snapshots+1 >= 2 THEN 'CLOSED' ELSE state END
			 WHERE id=? AND ended_at IS NULL`, ts, id); err != nil {
			return fmt.Errorf("close missing connection: %w", err)
		}
	}
	return tx.Commit()
}

func (s *Store) QueryConnectionHistory(since float64, limit int) ([]*ConnectionRecord, error) {
	if limit <= 0 {
		limit = 500
	}
	if limit > 2000 {
		limit = 2000
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(
		`SELECT started_at, last_seen, ended_at, app, pid, proto, local, remote, scope, state
		 FROM connection_history WHERE last_seen >= ? ORDER BY last_seen DESC LIMIT ?`,
		since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []*ConnectionRecord
	for rows.Next() {
		var record ConnectionRecord
		var ended sql.NullFloat64
		var app, pid, protocol, local, remote, scope sql.NullString
		if err := rows.Scan(
			&record.StartedAt, &record.LastSeen, &ended, &app, &pid,
			&protocol, &local, &remote, &scope, &record.State); err != nil {
			return nil, err
		}
		if ended.Valid {
			record.EndedAt = &ended.Float64
		}
		record.App, record.PID = app.String, pid.String
		record.Protocol, record.Local, record.Remote = protocol.String, local.String, remote.String
		record.Scope = scope.String
		records = append(records, &record)
	}
	return records, rows.Err()
}

// OpenConnectionStarts returns identity -> started_at for every open
// connection-history record, so the live view can render how long each
// endpoint has been connected (first seen -> now).
func (s *Store) OpenConnectionStarts() (map[string]float64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(
		"SELECT identity, started_at FROM connection_history WHERE ended_at IS NULL")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]float64{}
	for rows.Next() {
		var identity string
		var started float64
		if err := rows.Scan(&identity, &started); err != nil {
			return nil, err
		}
		out[identity] = started
	}
	return out, rows.Err()
}

// DestinationDelta is one per-destination byte accumulation produced by the
// connection poll: bytes seen on sockets belonging to (app, remote IP)
// since the previous counter sample.
type DestinationDelta struct {
	App      string
	RemoteIP string
	BytesIn  int64
	BytesOut int64
}

// DestinationTraffic is one persisted per-destination byte total. Bytes are
// cumulative "since first recording" for the (app, IP) pair — per-socket
// counters vanish when a socket closes, so the daemon accumulates deltas
// into this table instead.
type DestinationTraffic struct {
	App       string  `json:"app"`
	RemoteIP  string  `json:"remote_ip"`
	BytesIn   int64   `json:"bytes_in"`
	BytesOut  int64   `json:"bytes_out"`
	FirstSeen float64 `json:"first_seen"`
	LastSeen  float64 `json:"last_seen"`
}

// DestinationSpan aggregates one (app, remote endpoint) group of connection
// lifecycles out of the history: how many connections were observed, for how
// long in total, and how many are still open.
type DestinationSpan struct {
	App         string
	Remote      string
	Connections int64
	Open        int64
	Seconds     float64
	LastSeen    float64
}

// AddDestinationBytes accumulates per-destination byte deltas (UPSERT).
// first_seen is set on insert and never updated, so the row brackets the
// whole recording window for that destination.
func (s *Store) AddDestinationBytes(deltas []DestinationDelta, ts float64) error {
	if len(deltas) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	for _, d := range deltas {
		if d.RemoteIP == "" {
			continue
		}
		app := d.App
		if app == "" {
			app = "Unknown"
		}
		if _, err := tx.Exec(
			`INSERT INTO destination_traffic (app, remote_ip, bytes_in, bytes_out, first_seen, last_seen)
			 VALUES (?, ?, ?, ?, ?, ?)
			 ON CONFLICT(app, remote_ip) DO UPDATE SET
			     bytes_in = bytes_in + excluded.bytes_in,
			     bytes_out = bytes_out + excluded.bytes_out,
			     last_seen = excluded.last_seen`,
			app, d.RemoteIP, d.BytesIn, d.BytesOut, ts, ts); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// DestinationBytes returns per-destination byte totals touched since ts.
func (s *Store) DestinationBytes(since float64) ([]DestinationTraffic, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(
		`SELECT app, remote_ip, bytes_in, bytes_out, first_seen, last_seen
		 FROM destination_traffic WHERE last_seen >= ?`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DestinationTraffic
	for rows.Next() {
		var t DestinationTraffic
		var app, ip sql.NullString
		if err := rows.Scan(&app, &ip, &t.BytesIn, &t.BytesOut, &t.FirstSeen, &t.LastSeen); err != nil {
			return nil, err
		}
		t.App, t.RemoteIP = app.String, ip.String
		out = append(out, t)
	}
	return out, rows.Err()
}

// AddAppTraffic accumulates per-app byte deltas measured at the process
// level (nettop per-process totals, TCP+UDP). Unlike destination_traffic,
// these totals don't depend on per-socket attribution, so they capture
// QUIC/UDP traffic that has no observable remote endpoint.
func (s *Store) AddAppTraffic(deltas []DestinationDelta, ts float64) error {
	if len(deltas) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	for _, d := range deltas {
		if d.App == "" {
			continue
		}
		if _, err := tx.Exec(
			`INSERT INTO app_traffic (app, bytes_in, bytes_out, first_seen, last_seen)
			 VALUES (?, ?, ?, ?, ?)
			 ON CONFLICT(app) DO UPDATE SET
			     bytes_in = bytes_in + excluded.bytes_in,
			     bytes_out = bytes_out + excluded.bytes_out,
			     last_seen = excluded.last_seen`,
			d.App, d.BytesIn, d.BytesOut, ts, ts); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// AppTraffic returns per-app process-level byte totals touched since ts.
func (s *Store) AppTraffic(since float64) ([]DestinationTraffic, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(
		`SELECT app, bytes_in, bytes_out, first_seen, last_seen
		 FROM app_traffic WHERE last_seen >= ?`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DestinationTraffic
	for rows.Next() {
		var t DestinationTraffic
		var app sql.NullString
		if err := rows.Scan(&app, &t.BytesIn, &t.BytesOut, &t.FirstSeen, &t.LastSeen); err != nil {
			return nil, err
		}
		t.App = app.String
		out = append(out, t)
	}
	return out, rows.Err()
}

// DestinationSpans groups external connection lifecycles by (app, remote
// endpoint). Seconds sums each lifecycle's duration (started_at ->
// ended/last seen); Open counts lifecycles not yet closed.
func (s *Store) DestinationSpans(since float64) ([]DestinationSpan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(
		`SELECT app, remote, COUNT(*),
		        SUM(CASE WHEN ended_at IS NULL THEN 1 ELSE 0 END),
		        SUM(COALESCE(ended_at, last_seen) - started_at),
		        MAX(last_seen)
		 FROM connection_history
		 WHERE scope = 'external' AND last_seen >= ?
		 GROUP BY app, remote`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DestinationSpan
	for rows.Next() {
		var span DestinationSpan
		var app, remote sql.NullString
		if err := rows.Scan(&app, &remote, &span.Connections,
			&span.Open, &span.Seconds, &span.LastSeen); err != nil {
			return nil, err
		}
		span.App, span.Remote = app.String, remote.String
		if span.Seconds < 0 {
			span.Seconds = 0
		}
		out = append(out, span)
	}
	return out, rows.Err()
}

func nullableText(value any) string {
	if value == nil {
		return ""
	}
	text := StrOf(value)
	if text == "None" {
		return ""
	}
	return text
}

func formatConnectionEndpoint(address, port any) string {
	host := nullableText(address)
	if host == "" {
		return ""
	}
	portText := nullableText(port)
	if portText == "" {
		return host
	}
	return host + ":" + portText
}

// InsertTrafficSample stores one aggregate interface-counter snapshot.
func (s *Store) InsertTrafficSample(ts float64, rxBytes, txBytes int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(
		"INSERT OR REPLACE INTO traffic_samples (ts, rx_bytes, tx_bytes) VALUES (?,?,?)",
		ts, rxBytes, txBytes)
	return err
}

// TrafficSampleBefore returns the latest counter sample at or before ts.
func (s *Store) TrafficSampleBefore(ts float64) (sample TrafficSample, ok bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row := s.db.QueryRow(
		"SELECT ts, rx_bytes, tx_bytes FROM traffic_samples WHERE ts <= ? ORDER BY ts DESC LIMIT 1",
		ts)
	err = row.Scan(&sample.Ts, &sample.RxBytes, &sample.TxBytes)
	if err == sql.ErrNoRows {
		return TrafficSample{}, false, nil
	}
	if err != nil {
		return TrafficSample{}, false, err
	}
	return sample, true, nil
}

// FirstTrafficSample returns the oldest retained counter sample.
func (s *Store) FirstTrafficSample() (sample TrafficSample, ok bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row := s.db.QueryRow("SELECT ts, rx_bytes, tx_bytes FROM traffic_samples ORDER BY ts LIMIT 1")
	err = row.Scan(&sample.Ts, &sample.RxBytes, &sample.TxBytes)
	if err == sql.ErrNoRows {
		return TrafficSample{}, false, nil
	}
	if err != nil {
		return TrafficSample{}, false, err
	}
	return sample, true, nil
}

// FirstTrafficSampleAfter returns the first sample at or after ts.
func (s *Store) FirstTrafficSampleAfter(ts float64) (sample TrafficSample, ok bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row := s.db.QueryRow(
		"SELECT ts, rx_bytes, tx_bytes FROM traffic_samples WHERE ts >= ? ORDER BY ts LIMIT 1",
		ts)
	err = row.Scan(&sample.Ts, &sample.RxBytes, &sample.TxBytes)
	if err == sql.ErrNoRows {
		return TrafficSample{}, false, nil
	}
	if err != nil {
		return TrafficSample{}, false, err
	}
	return sample, true, nil
}

// ------------------------------------------------------------- blocks ----

// AddBlock inserts a new rule (status "queued"); returns its id.
func (s *Store) AddBlock(rtype, value string, appPath, detail *string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(
		`INSERT INTO blocks (ts, type, value, app_path, detail, status,`+
			` status_detail) VALUES (?,?,?,?,?,?,?)`,
		Now(), rtype, value, appPath, detail, "queued", "not applied yet")
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateBlockStatus updates status fields for a rule.
func (s *Store) UpdateBlockStatus(bid int64, status, detail string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec("UPDATE blocks SET status=?, status_detail=? WHERE id=?",
		status, detail, bid)
	return err
}

const blockCols = `id, ts, type, value, app_path, detail, status, status_detail`

func scanBlock(scan func(...any) error) (*Block, error) {
	b := &Block{}
	var appPath, detail, status, statusDetail sql.NullString
	if err := scan(&b.ID, &b.Ts, &b.Type, &b.Value, &appPath, &detail,
		&status, &statusDetail); err != nil {
		return nil, err
	}
	b.AppPath = nullStr(appPath)
	b.Detail = nullStr(detail)
	b.Status = nullStr(status)
	b.StatusDetail = nullStr(statusDetail)
	return b, nil
}

func nullStr(v sql.NullString) *string {
	if !v.Valid {
		return nil
	}
	s := v.String
	return &s
}

// ListBlocks returns all rules, newest first.
func (s *Store) ListBlocks() ([]*Block, error) {
	s.mu.Lock()
	rows, err := s.db.Query("SELECT " + blockCols + " FROM blocks ORDER BY ts DESC")
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Block
	for rows.Next() {
		b, err := scanBlock(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// GetBlock returns one rule or nil.
func (s *Store) GetBlock(bid int64) (*Block, error) {
	s.mu.Lock()
	row := s.db.QueryRow("SELECT "+blockCols+" FROM blocks WHERE id=?", bid)
	s.mu.Unlock()
	b, err := scanBlock(row.Scan)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return b, err
}

// RemoveBlock deletes a rule.
func (s *Store) RemoveBlock(bid int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec("DELETE FROM blocks WHERE id=?", bid)
	return err
}

// ---------------------------------------------------------- event bus ----

// EventBus collects events: persisted to SQLite + fanned out to SSE clients.
type EventBus struct {
	store *Store
	mu    sync.Mutex
	subs  map[chan string]bool
}

// NewEventBus creates the bus.
func NewEventBus(store *Store) *EventBus {
	return &EventBus{store: store, subs: map[chan string]bool{}}
}

// Subscribe registers a new SSE subscriber queue (capacity 500 payloads).
func (b *EventBus) Subscribe() chan string {
	q := make(chan string, 500)
	b.mu.Lock()
	b.subs[q] = true
	b.mu.Unlock()
	return q
}

// Unsubscribe removes a subscriber.
func (b *EventBus) Unsubscribe(q chan string) {
	b.mu.Lock()
	delete(b.subs, q)
	b.mu.Unlock()
}

// Publish persists the event and fans the JSON payload out to subscribers.
// Full queues drop their oldest entry to keep the stream live.
func (b *EventBus) Publish(ev *Event) *Event {
	if ev.Ts == 0 {
		ev.Ts = Now()
	}
	if err := b.store.Insert(ev); err != nil {
		fmt.Printf("[bus] store error: %v\n", err)
	}
	payload, err := json.Marshal(map[string]any{"type": "event", "data": ev})
	if err != nil {
		return ev
	}
	b.mu.Lock()
	subs := make([]chan string, 0, len(b.subs))
	for q := range b.subs {
		subs = append(subs, q)
	}
	b.mu.Unlock()
	for _, q := range subs {
		select {
		case q <- string(payload):
		default:
			// drop oldest, keep stream live
			select {
			case <-q:
			default:
			}
			select {
			case q <- string(payload):
			default:
			}
		}
	}
	return ev
}

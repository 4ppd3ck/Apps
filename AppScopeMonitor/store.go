// SQLite event store + in-process event bus with SSE fan-out
// (mirrors monitor/store.py).
package monitor

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

// DeleteBefore removes events older than the cutoff epoch; returns row count.
func (s *Store) DeleteBefore(cutoff float64) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec("DELETE FROM events WHERE ts < ?", cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
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

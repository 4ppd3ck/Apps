package main

// Finding / Alert / Check types plus the JSON store (stdlib only — no SQLite
// dependency so the matrix in build.sh covers every GOOS/GOARCH cleanly).

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	SevInfo     = "info"
	SevLow      = "low"
	SevMedium   = "medium"
	SevHigh     = "high"
	SevCritical = "critical"
)

var sevRank = map[string]int{
	SevInfo: 0, SevLow: 1, SevMedium: 2, SevHigh: 3, SevCritical: 4,
}

func SevGE(a, b string) bool { return sevRank[a] >= sevRank[b] }

// Finding is one observation from a check on one scan.
type Finding struct {
	Check    string         `json:"check"`
	Severity string         `json:"severity"`
	Title    string         `json:"title"`
	Detail   string         `json:"detail"`
	Evidence map[string]any `json:"evidence,omitempty"`
	// Fingerprint links repeat observations of the same underlying issue;
	// empty means the finding is scan-transient (not converted to an alert).
	Fingerprint string `json:"fingerprint,omitempty"`
}

// Alert is a persisted, deduplicated Finding.
type Alert struct {
	ID          int64          `json:"id"`
	Ts          float64        `json:"ts"`
	FirstTs     float64        `json:"first_ts"`
	Severity    string         `json:"severity"`
	Check       string         `json:"check"`
	Title       string         `json:"title"`
	Detail      string         `json:"detail"`
	Evidence    map[string]any `json:"evidence,omitempty"`
	Fingerprint string         `json:"fingerprint"`
	Count       int            `json:"count"`
	Acked       bool           `json:"acked"`
	NotifiedTs  float64        `json:"notified_ts"`
}

// FingerprintOf builds a stable dedupe key from the finding's identity.
func FingerprintOf(check, ident string) string {
	h := sha256.Sum256([]byte(check + "|" + ident))
	return hex.EncodeToString(h[:])[:20]
}

// CheckStatus is surfaced per check in the dashboard.
type CheckStatus struct {
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Status      string  `json:"status"` // ok | unavailable | disabled
	Reason      string  `json:"reason,omitempty"`
	LastRun     float64 `json:"last_run"`
	LastMs      int64   `json:"last_ms"`
}

// Check is a scheduled detector. Interval: "fast" or "slow".
type Check struct {
	Name        string
	Description string
	Interval    string
	Run         func() []Finding
}

// Store persists alerts + baseline as JSON files under dataDir.
type Store struct {
	dir string
	mu  sync.Mutex

	alerts   []*Alert
	nextID   int64
	baseline map[string]any
	hub      *Hub
	notifyAt map[string]float64 // fingerprint -> last notified ts
}

func NewStore(dir string, hub *Hub) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, hub: hub, baseline: map[string]any{}, notifyAt: map[string]float64{}}
	s.load()
	return s, nil
}

func (s *Store) load() {
	raw, err := os.ReadFile(filepath.Join(s.dir, "alerts.json"))
	if err == nil {
		_ = json.Unmarshal(raw, &s.alerts)
	}
	for _, a := range s.alerts {
		if a.ID >= s.nextID {
			s.nextID = a.ID + 1
		}
		if a.NotifiedTs > 0 {
			s.notifyAt[a.Fingerprint] = a.NotifiedTs
		}
	}
	if b, err := os.ReadFile(filepath.Join(s.dir, "baseline.json")); err == nil {
		_ = json.Unmarshal(b, &s.baseline)
	}
}

func (s *Store) saveAlertsLocked() {
	raw, err := json.MarshalIndent(s.alerts, "", " ")
	if err != nil {
		return
	}
	tmp := filepath.Join(s.dir, "alerts.json.tmp")
	if os.WriteFile(tmp, raw, 0o644) == nil {
		_ = os.Rename(tmp, filepath.Join(s.dir, "alerts.json"))
	}
}

func (s *Store) saveBaselineLocked() {
	raw, err := json.MarshalIndent(s.baseline, "", " ")
	if err != nil {
		return
	}
	tmp := filepath.Join(s.dir, "baseline.json.tmp")
	if os.WriteFile(tmp, raw, 0o644) == nil {
		_ = os.Rename(tmp, filepath.Join(s.dir, "baseline.json"))
	}
}

// Record converts a finding into (or bumps) an alert. Returns the alert when
// it is new or its notify window elapsed, so the caller can push a desktop
// notification; the returned bool says whether to re-notify.
func (s *Store) Record(f Finding, renotifyAfter time.Duration) (*Alert, bool) {
	if f.Fingerprint == "" {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := float64(time.Now().UnixNano()) / 1e9
	for _, a := range s.alerts {
		if a.Fingerprint == f.Fingerprint {
			a.Count++
			a.Ts = now
			a.Severity = f.Severity
			a.Title = f.Title
			a.Detail = f.Detail
			a.Evidence = f.Evidence
			// Acked means "seen, stop nudging me": the alert row still counts
			// occurrences, but desktop/webhook re-notifications stay off until
			// the row is deleted (a fresh observation then alerts anew).
			reNotify := !a.Acked && now-s.notifyAt[a.Fingerprint] >= renotifyAfter.Seconds()
			if reNotify {
				a.NotifiedTs = now
				s.notifyAt[a.Fingerprint] = now
			}
			s.saveAlertsLocked()
			s.hub.Broadcast(map[string]any{"type": "alert", "alert": a})
			return a, reNotify
		}
	}
	a := &Alert{
		ID:          s.nextID,
		Ts:          now,
		FirstTs:     now,
		Severity:    f.Severity,
		Check:       f.Check,
		Title:       f.Title,
		Detail:      f.Detail,
		Evidence:    f.Evidence,
		Fingerprint: f.Fingerprint,
		Count:       1,
		NotifiedTs:  now,
	}
	s.nextID++
	s.notifyAt[a.Fingerprint] = now
	s.alerts = append([]*Alert{a}, s.alerts...)
	if len(s.alerts) > 2000 {
		// newest-first list: the tail is the oldest — dropped, newest kept
		fmt.Fprintf(os.Stderr, "sentinel: alert store full (%d kept) — oldest alerts trimmed; export or delete acked ones\n", 2000)
		s.alerts = s.alerts[:2000]
	}
	s.saveAlertsLocked()
	s.hub.Broadcast(map[string]any{"type": "alert", "alert": a})
	return a, true
}

// BaselineKey returns a typed value from baseline.json, creating it if absent.
// created=true signals first observation (callers usually skip alerting then).
func (s *Store) BaselineKey(key string, value any) (any, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.baseline[key]
	if !ok {
		s.baseline[key] = value
		s.saveBaselineLocked()
		return value, false
	}
	return cur, true
}

// BaselineUpdate overwrites a baseline key (learned state).
func (s *Store) BaselineUpdate(key string, value any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.baseline[key] = value
	s.saveBaselineLocked()
}

func (s *Store) BaselineReset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.baseline = map[string]any{}
	s.saveBaselineLocked()
}

// BaselineList returns the string-keyed view for the dashboard.
func (s *Store) BaselineList() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]any{}
	for k, v := range s.baseline {
		out[k] = v
	}
	return out
}

func (s *Store) Alerts(since float64, minSev string) []*Alert {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []*Alert{}
	for _, a := range s.alerts {
		if a.Ts < since {
			continue
		}
		if minSev != "" && !SevGE(a.Severity, minSev) {
			continue
		}
		out = append(out, a)
	}
	return out
}

func (s *Store) Ack(id int64, all bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.alerts {
		if all || a.ID == id {
			a.Acked = true
		}
	}
	s.saveAlertsLocked()
	s.hub.Broadcast(map[string]any{"type": "ack"})
}

// AckByFingerprint pre-acks any alert matching fingerprint (used by the
// intel "autoack" mode: known-provider alerts stay in history with counts
// but never notify). Missing matches are fine — Record calls this right
// after creating or bumping the alert.
func (s *Store) AckByFingerprint(fingerprint string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.alerts {
		if a.Fingerprint == fingerprint {
			a.Acked = true
		}
	}
	s.saveAlertsLocked()
}

// AckExcluded pre-acks every unacked alert the given predicate silences —
// called when a watchdog exclusion is set, so "stop showing me this app"
// also quiets what is already on the board (new findings from that app are
// never recorded in the first place). Returns how many rows were acked.
func (s *Store) AckExcluded(excluded func(Finding) bool) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, a := range s.alerts {
		if a.Acked || !excluded(Finding{Check: a.Check, Evidence: a.Evidence}) {
			continue
		}
		a.Acked = true
		n++
	}
	if n > 0 {
		s.saveAlertsLocked()
		s.hub.Broadcast(map[string]any{"type": "ack"})
	}
	return n
}

// Delete removes alerts by id (or every acked alert when allAcked is set).
// Missing ids are ignored so stale UI clicks stay harmless. The next scan
// that still observes the underlying condition re-records the alert fresh
// — deleting expresses "stop showing this", not "never alert again"; use
// ack (or allowlist the source) for recurring noise.
func (s *Store) Delete(id int64, allAcked bool) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.alerts[:0]
	removed := 0
	for _, a := range s.alerts {
		match := (!allAcked && a.ID == id) || (allAcked && a.Acked)
		if match {
			removed++
			continue
		}
		kept = append(kept, a)
	}
	if removed == 0 {
		return 0
	}
	s.alerts = kept
	s.saveAlertsLocked()
	s.hub.Broadcast(map[string]any{"type": "ack"})
	return removed
}

// Endpoints returns the learned endpoint map for beacon tracking.
// Endpoints returns a copy of the learned endpoint map — callers mutate it
// freely; SaveEndpoints writes the result back under the lock.
func (s *Store) Endpoints() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	ep, _ := s.baseline["endpoints"].(map[string]any)
	out := map[string]any{}
	for k, v := range ep {
		out[k] = v
	}
	return out
}

func (s *Store) SaveEndpoints(ep map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.baseline["endpoints"] = ep
	s.saveBaselineLocked()
}

// Summary for /api/status.
func (s *Store) Summary() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	bySev := map[string]int{}
	unacked := 0
	for _, a := range s.alerts {
		bySev[a.Severity]++
		if !a.Acked {
			unacked++
		}
	}
	sort.Slice(s.alerts, func(i, j int) bool { return s.alerts[i].ID > s.alerts[j].ID })
	return map[string]any{
		"total": len(s.alerts), "unacked": unacked, "by_severity": bySev,
	}
}

func FmtAny(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

// MatchBadName applies the process-bad-name rules. Plain tokens match as
// case-insensitive substrings; a token wrapped in slashes ("/\bmsf\b/") is
// treated as a regular expression (case-insensitive) — use it for short or
// ambiguous tokens that would swallow innocent names.
func MatchBadName(name string, bad []string) bool {
	ln := strings.ToLower(name)
	for _, n := range bad {
		n = strings.TrimSpace(n)
		if len(n) < 2 {
			continue
		}
		if strings.HasPrefix(n, "/") && strings.HasSuffix(n, "/") && len(n) > 2 {
			re, err := regexp.Compile("(?i)" + n[1:len(n)-1])
			if err != nil {
				continue
			}
			if re.MatchString(ln) {
				return true
			}
			continue
		}
		if strings.Contains(ln, strings.ToLower(n)) {
			return true
		}
	}
	return false
}

func StrHasAny(s string, needles []string) bool {
	ls := strings.ToLower(s)
	for _, n := range needles {
		if n != "" && strings.Contains(ls, strings.ToLower(n)) {
			return true
		}
	}
	return false
}

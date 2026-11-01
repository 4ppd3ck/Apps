package main

// Per-app exclusions, persisted in exclusions.json beside the other state.
//
// Four independent scopes, matching the dashboard's Exclusions tab:
//   watchdog  — alerts/findings related to the app are never recorded or
//               notified (new_endpoint, beacon, privacy_exfil, file_exfil,
//               sensitive, conn_badport…)
//   auto_ack  — the app's alerts ARE recorded (history + hit counts) but
//               land pre-acked and never notify
//   live      — the app's rows are hidden from the Live Access tab
//   appaccess — the app's entries are hidden from the App Access tab
//
// A row can also carry per-target entries (Targets): the "app holds two
// sensitive files, only one of them is benign" case — the watchdog/live
// scopes then apply to that one app+target pair instead of the whole app.
//
// Matching is bidirectional case-insensitive substring ("zcode" covers
// "ZCode Helper" and "com.zcode.app"); exclusions are the user's explicit
// intent, so err on the side of matching.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type Exclusion struct {
	App       string            `json:"app"`
	Watchdog  bool              `json:"watchdog"`
	AutoAck   bool              `json:"auto_ack"`
	Live      bool              `json:"live"`
	AppAccess bool              `json:"app_access"`
	Targets   []TargetExclusion `json:"targets,omitempty"`
}

// TargetExclusion is one app+target pair (a file path, device or store) with
// its own watchdog/live scopes. App Access is not a target scope — that tab
// shows permission grants, not accesses to specific things.
type TargetExclusion struct {
	Target   string `json:"target"`
	Watchdog bool   `json:"watchdog"`
	Live     bool   `json:"live"`
}

type Exclusions struct {
	mu      sync.Mutex
	dir     string
	list    []Exclusion
	lastMod map[string]any // last-seen stat of exclusions.json
}

func LoadExclusions(dir string) *Exclusions {
	e := &Exclusions{dir: dir, lastMod: map[string]any{}}
	if raw, err := os.ReadFile(filepath.Join(dir, "exclusions.json")); err == nil {
		_ = json.Unmarshal(raw, &e.list)
	}
	e.noteMod()
	return e
}

// statMod returns the file's identity for change detection.
func (e *Exclusions) statMod() map[string]any {
	fi, err := os.Stat(filepath.Join(e.dir, "exclusions.json"))
	if err != nil {
		return nil
	}
	return map[string]any{"size": fi.Size(), "mtime": fi.ModTime().UnixNano()}
}

func (e *Exclusions) noteMod() { e.lastMod = e.statMod() }

// MaybeReload re-reads exclusions.json when it changed on disk. A second
// Sentinel process (an orphaned previous launch) or a manual edit must take
// effect in a long-running instance — otherwise a process that started
// before the exclusion was saved keeps notifying forever.
func (e *Exclusions) MaybeReload() {
	cur := e.statMod()
	if cur == nil {
		return
	}
	e.mu.Lock()
	same := e.lastMod != nil && cur["size"] == e.lastMod["size"] &&
		cur["mtime"] == e.lastMod["mtime"]
	e.mu.Unlock()
	if same {
		return
	}
	var list []Exclusion
	if raw, err := os.ReadFile(filepath.Join(e.dir, "exclusions.json")); err == nil {
		if err := json.Unmarshal(raw, &list); err != nil {
			return // keep the working copy; a torn write must not clear it
		}
		e.mu.Lock()
		e.list = list
		e.mu.Unlock()
	}
	e.mu.Lock()
	e.noteMod()
	e.mu.Unlock()
}

func (e *Exclusions) List() []Exclusion {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Exclusion, len(e.list))
	copy(out, e.list)
	return out
}

// foldRow merges every row whose key overlaps app (same name after case
// folding, or either containing the other — e.g. an old "/Applications/X.app"
// row vs a new "X") into one survivor carrying their scope flags and target
// entries, so a later untick can't be shadowed by a stale differently-keyed
// row. Returns the survivor (App set to app), the non-overlapping remainder
// of the list, and whether any row folded in.
func (e *Exclusions) foldRow(app string) (Exclusion, []Exclusion, bool) {
	la := strings.ToLower(app)
	merged := Exclusion{App: app}
	found := false
	kept := make([]Exclusion, 0, len(e.list))
	for _, x := range e.list {
		lx := strings.ToLower(x.App)
		if lx != la && !strings.Contains(la, lx) && !strings.Contains(lx, la) {
			kept = append(kept, x)
			continue
		}
		merged.Watchdog = merged.Watchdog || x.Watchdog
		merged.AutoAck = merged.AutoAck || x.AutoAck
		merged.Live = merged.Live || x.Live
		merged.AppAccess = merged.AppAccess || x.AppAccess
		merged.Targets = append(merged.Targets, x.Targets...)
		found = true
	}
	return merged, kept, found
}

// Set upserts one app's row and persists.
func (e *Exclusions) Set(app string, field string, value bool) []Exclusion {
	e.mu.Lock()
	app = strings.TrimSpace(app)
	if app != "" {
		merged, kept, _ := e.foldRow(app)
		switch field {
		case "watchdog":
			merged.Watchdog = value
		case "auto_ack":
			merged.AutoAck = value
		case "live":
			merged.Live = value
		case "app_access":
			merged.AppAccess = value
		}
		kept = append(kept, merged)
		e.list = kept
	}
	out := make([]Exclusion, len(e.list))
	copy(out, e.list)
	e.saveLocked()
	e.mu.Unlock()
	return out
}

// SetTarget upserts one app+target entry (e.g. a single sensitive file whose
// popup should stop while the app's other files still alert) and persists.
// Unticking both scopes drops the entry.
func (e *Exclusions) SetTarget(app, target, field string, value bool) []Exclusion {
	e.mu.Lock()
	app, target = strings.TrimSpace(app), strings.TrimSpace(target)
	if app != "" && target != "" {
		merged, kept, _ := e.foldRow(app)
		lt := strings.ToLower(target)
		trow := TargetExclusion{Target: target}
		targets := make([]TargetExclusion, 0, len(merged.Targets)+1)
		for _, t := range merged.Targets {
			if strings.ToLower(t.Target) == lt {
				trow = t
				continue
			}
			targets = append(targets, t)
		}
		switch field {
		case "watchdog":
			trow.Watchdog = value
		case "live":
			trow.Live = value
		}
		if trow.Watchdog || trow.Live {
			targets = append(targets, trow)
		}
		merged.Targets = targets
		kept = append(kept, merged)
		e.list = kept
	}
	out := make([]Exclusion, len(e.list))
	copy(out, e.list)
	e.saveLocked()
	e.mu.Unlock()
	return out
}

// Remove drops an app's exclusion row entirely (per-target entries included)
// and persists. For apps already uninstalled, whose rows would otherwise sit
// in the list forever. Reports whether anything was dropped.
func (e *Exclusions) Remove(app string) bool {
	e.mu.Lock()
	app = strings.TrimSpace(app)
	la := strings.ToLower(app)
	if app == "" {
		e.mu.Unlock()
		return false
	}
	kept := make([]Exclusion, 0, len(e.list))
	dropped := false
	for _, x := range e.list {
		lx := strings.ToLower(x.App)
		if lx == la || strings.Contains(la, lx) || strings.Contains(lx, la) {
			dropped = true
			continue
		}
		kept = append(kept, x)
	}
	if dropped {
		e.list = kept
		e.saveLocked()
	}
	e.mu.Unlock()
	return dropped
}

// RemoveTarget drops one per-target entry, and with it the app row when it
// ends up empty (no scope set, no other target). Reports whether anything
// was dropped.
func (e *Exclusions) RemoveTarget(app, target string) bool {
	e.mu.Lock()
	app, target = strings.TrimSpace(app), strings.TrimSpace(target)
	lt := strings.ToLower(target)
	la := strings.ToLower(app)
	dropped := false
	if app != "" && target != "" {
		out := make([]Exclusion, 0, len(e.list))
		for _, x := range e.list {
			lx := strings.ToLower(x.App)
			if lx != la && !strings.Contains(la, lx) && !strings.Contains(lx, la) {
				out = append(out, x)
				continue
			}
			targets := make([]TargetExclusion, 0, len(x.Targets))
			for _, t := range x.Targets {
				if strings.ToLower(t.Target) == lt {
					dropped = true
					continue
				}
				targets = append(targets, t)
			}
			x.Targets = targets
			if x.Watchdog || x.AutoAck || x.Live || x.AppAccess || len(x.Targets) > 0 {
				out = append(out, x)
			} else {
				dropped = true
			}
		}
		if dropped {
			e.list = out
			e.saveLocked()
		}
	}
	e.mu.Unlock()
	return dropped
}

func (e *Exclusions) saveLocked() {
	raw, err := json.MarshalIndent(e.list, "", " ")
	if err != nil {
		return
	}
	tmp := filepath.Join(e.dir, "exclusions.json.tmp")
	if os.WriteFile(tmp, raw, 0o644) == nil {
		_ = os.Rename(tmp, filepath.Join(e.dir, "exclusions.json"))
	}
}

// Excludes reports whether app matches any exclusion with the scope set.
// The app name must contain the exclusion term (not the other way round —
// a "zcode" exclusion must not silence an unrelated "zcod" process).
func (e *Exclusions) Excludes(scope, app string) bool {
	if e == nil || app == "" {
		return false
	}
	la := strings.ToLower(app)
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, x := range e.list {
		if !scopeEnabled(x, scope) {
			continue
		}
		if lx := strings.ToLower(x.App); lx != "" && strings.Contains(la, lx) {
			return true
		}
	}
	return false
}

func scopeEnabled(x Exclusion, scope string) bool {
	switch scope {
	case "watchdog":
		return x.Watchdog
	case "auto_ack":
		return x.AutoAck
	case "live":
		return x.Live
	case "app_access":
		return x.AppAccess
	}
	return false
}

// ExcludesTarget reports whether app+target carries a per-target exclusion
// for the scope — the "one of several sensitive files" case. The app matches
// with the same containment rule as Excludes; the target matches on the full
// string (case-insensitive), with SQLite sidecars collapsing into their store
// so one entry covers the -wal/-shm variants of the same database.
func (e *Exclusions) ExcludesTarget(scope, app, target string) bool {
	if e == nil || app == "" || target == "" {
		return false
	}
	la := strings.ToLower(app)
	lt := strings.ToLower(target)
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, x := range e.list {
		lx := strings.ToLower(x.App)
		if lx == "" || !strings.Contains(la, lx) {
			continue
		}
		for _, t := range x.Targets {
			if !scopeTargetEnabled(t, scope) {
				continue
			}
			ltt := strings.ToLower(t.Target)
			if ltt == lt || storeIdentity(ltt) == storeIdentity(lt) {
				return true
			}
		}
	}
	return false
}

func scopeTargetEnabled(t TargetExclusion, scope string) bool {
	switch scope {
	case "watchdog":
		return t.Watchdog
	case "live":
		return t.Live
	}
	return false
}

// findingApp extracts the app an alert is "about" — evidence["app"] first,
// then process-name evidence. Findings without an app are never excluded.
func findingApp(f Finding) string {
	if f.Evidence == nil {
		return ""
	}
	if app := FmtAny(f.Evidence["app"]); app != "" {
		return app
	}
	return FmtAny(f.Evidence["name"])
}

// findingTarget extracts the sensitive thing (device, store or file path) an
// alert is about — evidence["target"] first, then evidence["path"] (the
// exfil.go monitor-event variant of the same alert uses "path").
func findingTarget(f Finding) string {
	if f.Evidence == nil {
		return ""
	}
	if t := FmtAny(f.Evidence["target"]); t != "" {
		return t
	}
	return FmtAny(f.Evidence["path"])
}

// ExcludedByWatchdog reports whether a finding is silenced: by an app-level
// watchdog exclusion, or by the tighter per-target one (a single file of an
// otherwise un-excluded app).
func (e *Exclusions) ExcludedByWatchdog(f Finding) bool {
	if e == nil {
		return false
	}
	app := findingApp(f)
	if e.Excludes("watchdog", app) {
		return true
	}
	if t := findingTarget(f); t != "" {
		return e.ExcludesTarget("watchdog", app, t)
	}
	return false
}

// ExcludedByAutoAck reports whether a finding's app carries the auto_ack
// exclusion: its alerts stay recorded (history + hit counts) but land
// pre-acked and never notify — same treatment as the intel "autoack" mode,
// driven by the user's per-app choice.
func (e *Exclusions) ExcludedByAutoAck(f Finding) bool {
	if e == nil {
		return false
	}
	return e.Excludes("auto_ack", findingApp(f))
}

// filterWatchdogExcluded drops findings whose app carries the watchdog
// exclusion (from both the scan snapshot and alert dispatch), including the
// per-target variant for findings that name a target.
func (e *Exclusions) filterWatchdogExcluded(findings []Finding) []Finding {
	if e == nil {
		return findings
	}
	out := findings[:0]
	for _, f := range findings {
		if e.ExcludedByWatchdog(f) {
			continue
		}
		out = append(out, f)
	}
	return out
}

// filterPermissionInventory removes app_access-excluded apps from a copy.
func (e *Exclusions) filterPermissionInventory(inv PermissionInventory) PermissionInventory {
	if e == nil {
		return inv
	}
	apps := inv.Apps[:0]
	for _, app := range inv.Apps {
		if e.Excludes("app_access", app.Name) || e.Excludes("app_access", app.Identifier) {
			continue
		}
		apps = append(apps, app)
	}
	inv.Apps = apps
	return inv
}

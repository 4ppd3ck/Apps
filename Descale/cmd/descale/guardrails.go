package main

/* Deletion guardrails: a hard floor under every scanner and delete path.
 *
 * The leftovers and traces scanners derive candidate paths by joining an
 * app's identity into well-known roots. A missing or mis-derived identity
 * must degrade to "propose nothing", never to "propose the root itself" —
 * deleting ~/Library/Application Support would wipe every application's
 * data at once. criticalReason is the shared last line of defense, and it
 * runs twice on purpose:
 *
 *   - at scan time (leftoversFrom, addDirOrphans, collect): protected
 *     locations are dropped before the UI can ever show them;
 *   - at delete time (traces delete, leftovers delete, uninstall): the
 *     endpoints refuse protected paths even when a fresh scan proposed
 *     them, because scan code and delete code can drift independently.
 *
 * The protection table can be switched off from the dashboard (expert
 * mode) for an operator who knows exactly what they are deleting. The
 * structural floor — nothing at or above the home directory, no relative
 * paths, no drive roots — holds in every mode.
 */

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

var (
	guardMu     sync.Mutex
	guardLoaded bool
	guardOn     bool
)

type descaleSettings struct {
	Guardrails *bool `json:"guardrails"`
	// Onboarded records that the welcome banner was dismissed. The flag
	// lives server-side because embedded webviews (AppDeck) may not keep
	// localStorage between launches, which made the banner reappear.
	Onboarded *bool `json:"onboarded,omitempty"`
}

func settingsPath() string {
	return filepath.Join(homeDir(), ".descale", "settings.json")
}

// guardrailsEnabled reports whether the protection table is active. It
// defaults to true: a fresh install (or a missing/corrupt settings file)
// always starts protected; only an explicit toggle lifts the table.
func guardrailsEnabled() bool {
	guardMu.Lock()
	defer guardMu.Unlock()
	if !guardLoaded {
		guardOn = true
		if raw, err := os.ReadFile(settingsPath()); err == nil {
			var s descaleSettings
			if json.Unmarshal(raw, &s) == nil && s.Guardrails != nil {
				guardOn = *s.Guardrails
			}
		}
		guardLoaded = true
	}
	return guardOn
}

// readSettings loads settings.json; a missing or corrupt file yields the
// zero value (guardrails on, onboarding pending).
func readSettings() descaleSettings {
	var s descaleSettings
	if raw, err := os.ReadFile(settingsPath()); err == nil {
		_ = json.Unmarshal(raw, &s)
	}
	return s
}

// saveSettings updates settings.json, merging into whatever is already
// stored so one toggle never erases the other's flag.
func saveSettings(mut func(*descaleSettings)) {
	s := readSettings()
	mut(&s)
	if data, err := json.MarshalIndent(s, "", " "); err == nil {
		p := settingsPath()
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		tmp := p + ".tmp"
		if os.WriteFile(tmp, data, 0o600) == nil {
			_ = os.Rename(tmp, p)
		}
	}
}

// setGuardrailsEnabled flips the toggle immediately and persists it, so
// the choice survives a restart.
func setGuardrailsEnabled(on bool) {
	guardMu.Lock()
	guardOn = on
	guardLoaded = true
	guardMu.Unlock()
	saveSettings(func(s *descaleSettings) { s.Guardrails = &on })
}

var (
	onboardMu     sync.Mutex
	onboardLoaded bool
	onboardDone   bool
)

// onboardingDone reports whether the welcome banner was dismissed before.
// It defaults to false: a fresh install always sees the banner once.
func onboardingDone() bool {
	onboardMu.Lock()
	defer onboardMu.Unlock()
	if !onboardLoaded {
		onboardDone = readSettings().Onboarded != nil && *readSettings().Onboarded
		onboardLoaded = true
	}
	return onboardDone
}

// setOnboardingDone marks the banner dismissed and persists it.
func setOnboardingDone() {
	onboardMu.Lock()
	onboardDone = true
	onboardLoaded = true
	onboardMu.Unlock()
	saveSettings(func(s *descaleSettings) { s.Onboarded = &onboardDone })
}

// criticalReason reports why path must never be trashed or deleted; the
// empty string means the path is fair game. Comparison is case-insensitive
// on every OS: on the case-insensitive macOS/Windows volumes that is exact,
// and on Linux it can only over-protect, never under-protect.
func criticalReason(path string) string {
	p := filepath.Clean(path)
	if !filepath.IsAbs(p) {
		return "not an absolute path: " + path
	}
	if vol := filepath.VolumeName(p); vol != "" && strings.TrimSuffix(p, string(os.PathSeparator)) == vol {
		return "drive root: " + p
	}
	// The home directory itself and every ancestor of it (/Users, /, the
	// drive root): nothing at or above home is a leftover, whatever a scan
	// or rule claims — and this floor holds in expert mode too.
	if rel, err := filepath.Rel(strings.ToLower(p), strings.ToLower(homeDir())); err == nil && !strings.HasPrefix(rel, "..") {
		return "at or above the home directory: " + p
	}
	if guardrailsEnabled() && criticalTable()[strings.ToLower(p)] {
		return "protected system location: " + p
	}
	// Browser profile/data folders are never deletable through Descale,
	// whatever a scanner claims: a scan glitch (browser mid-update, portable
	// install, momentarily missing bundle) must never be able to destroy
	// passwords, history, bookmarks and extensions. Scoped to the data roots
	// the scanners walk, so a user folder that merely contains such a name
	// stays untouched by this rule.
	if reason := browserDataReason(p); reason != "" {
		return reason
	}
	return ""
}

var (
	critMu    sync.Mutex
	critCache map[string]bool
	critHome  string
)

// criticalTable returns the protected locations, cached per home directory
// (DESCALE_HOME lets the fixture tests run against a synthetic tree).
func criticalTable() map[string]bool {
	home := homeDir()
	critMu.Lock()
	defer critMu.Unlock()
	if critCache != nil && critHome == home {
		return critCache
	}
	critCache = buildCriticalTable(home)
	critHome = home
	return critCache
}

// buildCriticalTable lists the protected locations: the leftover scan roots
// themselves, the OS's system directories, the standard user folders, and
// Descale's own state. Keys are lowercased exact directory paths — children
// of these are NOT protected by the table (a per-app folder under
// Application Support is exactly what the scanners should find).
func buildCriticalTable(home string) map[string]bool {
	lib := filepath.Join(home, "Library")
	var dirs []string
	switch runtime.GOOS {
	case "windows":
		local := os.Getenv("LOCALAPPDATA")
		roaming := os.Getenv("APPDATA")
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		windir := os.Getenv("SystemRoot")
		if windir == "" {
			windir = `C:\Windows`
		}
		dirs = []string{
			windir, `C:\Program Files`, `C:\Program Files (x86)`,
			`C:\Users`, `C:\`,
			pd, filepath.Join(pd, "Microsoft"),
			local, roaming, filepath.Join(local, "Programs"),
			filepath.Join(local, "Microsoft"), filepath.Join(roaming, "Microsoft"),
		}
	case "darwin":
		dirs = []string{
			"/System", "/Library", "/Applications", "/Users", "/Volumes",
			"/private", "/private/var", "/private/etc", "/var", "/etc", "/usr",
			"/bin", "/sbin", "/tmp", "/opt", "/Developer",
			lib,
			filepath.Join(lib, "Application Support"),
			filepath.Join(lib, "Application Scripts"),
			filepath.Join(lib, "Accounts"),
			filepath.Join(lib, "Autosave Information"),
			filepath.Join(lib, "Caches"),
			filepath.Join(lib, "Containers"),
			filepath.Join(lib, "Cookies"),
			filepath.Join(lib, "Group Containers"),
			filepath.Join(lib, "HTTPStorages"),
			filepath.Join(lib, "Keychains"),
			filepath.Join(lib, "WebKit"),
			filepath.Join(lib, "LaunchAgents"),
			filepath.Join(lib, "Logs"),
			filepath.Join(lib, "Mail"),
			filepath.Join(lib, "Mail Downloads"),
			filepath.Join(lib, "Messages"),
			filepath.Join(lib, "Metadata"),
			filepath.Join(lib, "Mobile Documents"),
			filepath.Join(lib, "Preferences"),
			filepath.Join(lib, "Saved Application State"),
			filepath.Join(home, "Applications"),
		}
	default: // linux and the other unixes
		dirs = []string{
			"/etc", "/usr", "/var", "/opt", "/boot", "/bin", "/sbin", "/lib",
			"/lib64", "/dev", "/proc", "/sys", "/run", "/srv", "/tmp", "/mnt",
			"/media", "/root", "/lost+found",
			filepath.Join(home, ".config"),
			filepath.Join(home, ".cache"),
			filepath.Join(home, ".local"),
			filepath.Join(home, ".local", "share"),
			filepath.Join(home, ".local", "state"),
			filepath.Join(home, ".var"),
			filepath.Join(home, "snap"),
		}
	}
	// Standard user folders on every OS: no scanner proposes them today,
	// but a future one must not be able to either.
	for _, name := range []string{"Desktop", "Documents", "Downloads", "Music", "Pictures", "Movies", "Videos", "Public"} {
		dirs = append(dirs, filepath.Join(home, name))
	}
	// Descale's own journal/trash and the OS trash: the restore path reads
	// both, so they must survive any clean.
	trash := trashDirPath()
	dirs = append(dirs, trash, filepath.Dir(trash))
	out := make(map[string]bool, len(dirs))
	for _, d := range dirs {
		out[strings.ToLower(filepath.Clean(d))] = true
	}
	return out
}

/* ---------- API ---------- */

func (s *server) handleGuardrailsGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"guardrails": guardrailsEnabled()})
}

// handleGuardrailsSet toggles the protection table. The choice is the
// operator's and is persisted; the structural floor (home and its
// ancestors) is not affected by it.
func (s *server) handleGuardrailsSet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil || req.Enabled == nil {
		fail(w, http.StatusBadRequest, "expected {\"enabled\": true|false}")
		return
	}
	setGuardrailsEnabled(*req.Enabled)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "guardrails": *req.Enabled})
}

// browserDataReason reports why p is a browser data folder that must never
// be deleted, scoped to the Library/AppData locations the scanners walk.
func browserDataReason(p string) string {
	s := strings.ToLower(filepath.ToSlash(p))
	inRoot := false
	for _, root := range []string{
		"/library/application support/", "/library/caches/",
		"/library/preferences/", "/library/httpstorages/",
		"/appdata/local/", "/appdata/roaming/",
	} {
		if strings.Contains(s, root) {
			inRoot = true
			break
		}
	}
	if !inRoot {
		return ""
	}
	for _, seg := range strings.Split(s, "/") {
		if browserDataDirs[seg] {
			return "browser profile/data folder (never a leftover): " + p
		}
	}
	return ""
}

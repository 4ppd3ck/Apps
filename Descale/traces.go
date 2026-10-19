package main

/* Traces tab: folders and files left behind by applications that are no
 * longer installed -- the "I removed MiniMax Agent months ago and its
 * Application Support folder is still here" case, on every OS.
 *
 * The scan walks the well-known leftover locations (macOS ~/Library
 * subfolders, Windows %LOCALAPPDATA%/%APPDATA%/%ProgramData%, the Linux
 * XDG dirs) and proposes an entry only when its identity -- bundle id,
 * display name, or reverse-DNS prefix -- matches NO installed application.
 * Vendor-shared folders survive: "Application Support/Google" stays while
 * Chrome is installed because a first-level subdirectory ("Chrome") is an
 * installed identity.
 *
 * Apple/system identities (com.apple.*, fontconfig, ...) are never
 * proposed. Nothing is deleted by a scan; deletion trashes selected paths
 * (journalled, restorable) and re-validates every path against a fresh
 * scan, so the endpoint can only ever remove what the scan itself
 * proposed.
 */

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// neverOrphans are identities that belong to this tool family or to
// system infrastructure the scanners should stay away from even when no
// installed app claims them.
var neverOrphans = map[string]bool{
	"descale": true, "appdeck": true, "appscope": true, "monitor": true,
	"fontconfig": true, "dbus": true, "systemd": true, "dconf": true,
	"mesa_shader_cache": true, "pulse": true,
}

// Trace is one orphaned leftover the scan proposes.
type Trace struct {
	Path      string `json:"path"`
	Kind      string `json:"kind"`
	SizeBytes int64  `json:"sizeBytes"`
}

// installedIdentities collects the names/ids of every installed app: on
// macOS bundle ids + display names + executables, on Linux desktop ids +
// names + exec basenames, on Windows registry DisplayNames. All lowercase.
func installedIdentities() map[string]bool {
	ids := map[string]bool{}
	add := func(vs ...string) {
		for _, v := range vs {
			if v != "" {
				ids[strings.ToLower(v)] = true
			}
		}
	}
	switch runtime.GOOS {
	case "windows":
		for _, a := range listInstalledWindows() {
			add(a.Name, strings.ToLower(a.Name))
		}
	case "linux":
		for _, a := range listAppsLinux() {
			add(a.ID, a.Name, strings.ToLower(a.Name), a.Exe)
		}
	default:
		for _, a := range listAppsMac() {
			add(a.ID, a.Name, strings.ToLower(a.Name), a.Exe)
		}
	}
	for n := range neverOrphans {
		ids[n] = true
	}
	return ids
}

// idInUse reports whether a bundle-id-shaped key (a folder name, a plist
// base, a launch-agent label) belongs to an installed app: exact match, or
// the installed id is a dot/hyphen prefix of it (helper extensions like
// com.foo.app.helper).
func idInUse(key string, ids map[string]bool) bool {
	k := strings.ToLower(key)
	if ids[k] {
		return true
	}
	for id := range ids {
		if id != "" && (strings.HasPrefix(k, id+".") || strings.HasPrefix(k, id+"-")) {
			return true
		}
	}
	return false
}

// vendorInUse covers vendor-shared folders: "Google" holds "Chrome". A
// top-level folder is in use when any installed identity names one of its
// first-level children.
func vendorInUse(dir string, ids map[string]bool) bool {
	name := strings.ToLower(filepath.Base(filepath.Clean(dir)))
	for id := range ids {
		if id == name {
			return true
		}
		if strings.HasPrefix(id, name) && len(id) > len(name) &&
			strings.ContainsRune(" .-_", rune(id[len(name)])) {
			return true
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if ids[strings.ToLower(e.Name())] {
			return true
		}
	}
	return false
}

// looksLikeBundleID: reverse-DNS-ish ("com.vendor.product"), not a plain
// sentence — the shape Preferences plists and saved states use.
func looksLikeBundleID(s string) bool {
	if s == "" || strings.Contains(s, " ") {
		return false
	}
	parts := strings.Split(strings.ToLower(s), ".")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
	}
	return true
}

// appleID stays away from anything Apple ships or manages.
func appleID(key string) bool {
	return strings.HasPrefix(strings.ToLower(key), "com.apple.") ||
		strings.HasPrefix(strings.ToLower(key), "apple")
}

func scanTraces() []Trace {
	ids := installedIdentities()
	var out []Trace
	switch runtime.GOOS {
	case "windows":
		out = traceLocationsWindows(ids)
	case "linux":
		out = traceLocationsLinux(ids)
	default:
		out = traceLocationsMac(ids)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SizeBytes > out[j].SizeBytes })
	return out
}

// addDirOrphans proposes first-level directories of root whose name matches
// no installed identity (with the vendor-subdir rescue for folder roots).
func addDirOrphans(out []Trace, root, kind string, ids map[string]bool) []Trace {
	entries, err := os.ReadDir(root)
	if err != nil {
		return out
	}
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() || strings.HasPrefix(name, ".") || neverOrphans[strings.ToLower(name)] {
			continue
		}
		if strings.HasPrefix(strings.ToLower(name), "com.apple.") {
			continue
		}
		p := filepath.Join(root, name)
		if looksLikeBundleID(name) {
			if idInUse(name, ids) || appleID(name) {
				continue
			}
		} else {
			if ids[strings.ToLower(name)] || vendorInUse(p, ids) {
				continue
			}
		}
		fi, err := os.Lstat(p)
		if err != nil {
			continue
		}
		out = append(out, Trace{Path: p, Kind: kind, SizeBytes: dirSize(p, fi)})
	}
	return out
}

func traceLocationsMac(ids map[string]bool) []Trace {
	lib := filepath.Join(homeDir(), "Library")
	var out []Trace
	for _, loc := range []struct{ root, kind string }{
		{filepath.Join(lib, "Application Support"), "data"},
		{filepath.Join(lib, "Caches"), "caches"},
		{filepath.Join(lib, "Logs"), "logs"},
		{filepath.Join(lib, "Containers"), "container"},
		{filepath.Join(lib, "HTTPStorages"), "storage"},
		{filepath.Join(lib, "WebKit"), "storage"},
		{filepath.Join(lib, "Application Scripts"), "scripts"},
	} {
		out = addDirOrphans(out, loc.root, loc.kind, ids)
	}

	// Preferences: id-keyed plists (com.vendor.product.plist) and the
	// rarer display-name ones; .lockfile siblings are skipped
	prefs := filepath.Join(lib, "Preferences")
	entries, _ := os.ReadDir(prefs)
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".plist") ||
			strings.HasSuffix(name, ".lockfile") || strings.HasPrefix(name, ".") {
			continue
		}
		base := strings.TrimSuffix(name, ".plist")
		if appleID(base) || neverOrphans[strings.ToLower(base)] {
			continue
		}
		if looksLikeBundleID(base) {
			if idInUse(base, ids) {
				continue
			}
		} else if ids[strings.ToLower(base)] {
			continue
		}
		p := filepath.Join(prefs, name)
		if fi, err := os.Lstat(p); err == nil {
			out = append(out, Trace{Path: p, Kind: "preferences", SizeBytes: fi.Size()})
		}
	}

	// Saved Application State: <id>.savedState bundles
	sas := filepath.Join(lib, "Saved Application State")
	entries, _ = os.ReadDir(sas)
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".savedState") {
			continue
		}
		base := strings.TrimSuffix(name, ".savedState")
		if appleID(base) || idInUse(base, ids) {
			continue
		}
		p := filepath.Join(sas, name)
		if fi, err := os.Lstat(p); err == nil {
			out = append(out, Trace{Path: p, Kind: "state", SizeBytes: dirSize(p, fi)})
		}
	}

	// Launch Agents whose Label points at no installed app (own labels and
	// Apple's excluded) -- the user-level ones only, per Startup tab policy
	agents, _ := filepath.Glob(filepath.Join(lib, "LaunchAgents", "*.plist"))
	for _, a := range agents {
		d, err := readPlist(a)
		if err != nil {
			continue
		}
		label, _ := d["Label"].(string)
		if label == "" || appleID(label) ||
			strings.Contains(strings.ToLower(label), "descale") {
			continue
		}
		if idInUse(label, ids) {
			continue
		}
		if fi, err := os.Lstat(a); err == nil {
			out = append(out, Trace{Path: a, Kind: "launch agent", SizeBytes: fi.Size()})
		}
	}
	return out
}

func traceLocationsWindows(ids map[string]bool) []Trace {
	local := os.Getenv("LOCALAPPDATA")
	roaming := os.Getenv("APPDATA")
	if local == "" || roaming == "" {
		return nil
	}
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	var out []Trace
	for _, loc := range []struct{ root, kind string }{
		{local, "data"}, {roaming, "data"}, {pd, "data"},
		{filepath.Join(local, "Programs"), "programs"},
	} {
		out = addDirOrphans(out, loc.root, loc.kind, ids)
	}
	// Start Menu folders of removed apps, user and all-users scope
	for _, root := range []string{roaming, pd} {
		out = addDirOrphans(out, filepath.Join(root, "Microsoft", "Windows",
			"Start Menu", "Programs"), "shortcuts", ids)
	}
	return out
}

func traceLocationsLinux(ids map[string]bool) []Trace {
	home := homeDir()
	var out []Trace
	for _, loc := range []struct{ root, kind string }{
		{filepath.Join(home, ".config"), "data"},
		{filepath.Join(home, ".cache"), "caches"},
		{filepath.Join(home, ".local", "share"), "data"},
		{filepath.Join(home, ".local", "state"), "state"},
	} {
		out = addDirOrphans(out, loc.root, loc.kind, ids)
	}
	return out
}

func (s *server) handleTraces(w http.ResponseWriter, r *http.Request) {
	traces := scanTraces()
	var total int64
	for _, t := range traces {
		total += t.SizeBytes
	}
	note := "Folders and files whose owning application is not installed. " +
		"Review before deleting — an entry you actually still use means its " +
		"app carries a different name than its data folder; leave those."
	if runtime.GOOS == "linux" {
		note += " Package-managed system dirs are deliberately not scanned."
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"traces": traces, "bytes": total, "note": note,
	})
}

// handleTracesDelete trashes checked traces. Every requested path is
// re-validated against a fresh scan: only locations the scan itself
// proposes can move, so a stale dashboard cannot trash something that just
// became an installed app's data.
func (s *server) handleTracesDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Paths []string `json:"paths"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, "bad request body")
		return
	}
	allowed := map[string]int64{}
	for _, t := range scanTraces() {
		allowed[t.Path] = t.SizeBytes
	}
	trashDir := trashDirPath()
	if err := os.MkdirAll(trashDir, 0o755); err != nil {
		fail(w, http.StatusInternalServerError, fmt.Sprintf("cannot create trash directory: %v", err))
		return
	}
	entry := JournalEntry{
		ID:     fmt.Sprintf("e%d", time.Now().UnixNano()),
		At:     time.Now().UTC().Format(time.RFC3339),
		Action: "traces",
		Name:   "leftover traces",
	}
	var failures, skipped []map[string]string
	removed := 0
	var bytes int64
	for _, p := range req.Paths {
		size, ok := allowed[p]
		if !ok {
			skipped = append(skipped, map[string]string{"path": p,
				"reason": "not in the current trace scan"})
			continue
		}
		dst, err := trashTo(trashDir, p)
		if err != nil {
			failures = append(failures, map[string]string{"path": p, "error": err.Error()})
			continue
		}
		entry.Items = append(entry.Items, JournalItem{Path: p, Trash: filepath.Base(dst)})
		entry.Bytes += size
		entry.Files++
		removed++
		bytes += size
	}
	if entry.Files > 0 {
		s.saveJournal(entry)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "removed": removed, "bytes": bytes, "files": entry.Files,
		"failed": failures, "skipped": skipped,
	})
}

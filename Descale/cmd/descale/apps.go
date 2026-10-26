package main

/* Uninstall tab + Startup tab backend.
 *
 * Uninstall: list installed .app bundles (/Applications, ~/Applications,
 * and the AppDeck-managed apps under ~/Library/Application Support/AppDeck/),
 * hunt the files an app scatters under ~/Library keyed by its bundle id,
 * and remove the whole set by moving it to the Trash (journalled).
 *
 * Startup: enumerate LaunchAgents/Daemons plists; user agents can be
 * activated/deactivated (bootout + rename to *.plist.disabled), system
 * ones are listed read-only because touching them needs an administrator.
 */

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

/* ---------- plist reading (plutil -> XML -> small token walk) ---------- */

// readPlist converts any plist (XML or binary) via macOS's plutil and walks
// the XML: top-level string/number/bool values and arrays of strings land in
// the map, nested dictionaries are skipped (Info.plist and LaunchAgent needs
// are flat).
func readPlist(path string) (map[string]any, error) {
	out, err := exec.Command("plutil", "-convert", "xml1", "-o", "-", path).Output()
	if err != nil {
		return nil, err
	}
	res := map[string]any{}
	dec := xml.NewDecoder(strings.NewReader(string(out)))
	pendingKey := ""
	collecting := false
	var arr []string
	for {
		tok, err := dec.Token()
		if err != nil {
			return res, nil
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "key":
				pendingKey = readText(dec)
			case "string":
				v := readText(dec)
				if collecting {
					arr = append(arr, v)
				} else if pendingKey != "" {
					res[pendingKey] = v
					pendingKey = ""
				}
			case "integer", "real", "date":
				v := readText(dec)
				if pendingKey != "" {
					res[pendingKey] = v
					pendingKey = ""
				}
			case "true":
				if pendingKey != "" {
					res[pendingKey] = true
					pendingKey = ""
				}
			case "false":
				if pendingKey != "" {
					res[pendingKey] = false
					pendingKey = ""
				}
			case "array":
				if pendingKey != "" {
					collecting = true
					arr = nil
				}
			case "dict":
				if pendingKey != "" || collecting {
					skipDict(dec)
					pendingKey = ""
					collecting = false
				}
			}
		case xml.EndElement:
			if t.Name.Local == "array" && collecting {
				if pendingKey != "" {
					res[pendingKey] = arr
				}
				pendingKey = ""
				collecting = false
			}
		}
	}
}

func readText(dec *xml.Decoder) string {
	var sb strings.Builder
	for {
		tok, err := dec.Token()
		if err != nil {
			return sb.String()
		}
		switch t := tok.(type) {
		case xml.CharData:
			sb.Write(t)
		case xml.StartElement:
			sb.WriteString(readText(dec))
		case xml.EndElement:
			return sb.String()
		}
	}
}

func skipDict(dec *xml.Decoder) {
	depth := 1
	for depth > 0 {
		tok, err := dec.Token()
		if err != nil {
			return
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == "dict" {
				depth++
			}
		case xml.EndElement:
			if t.Name.Local == "dict" {
				depth--
			}
		}
	}
}

/* ---------- Uninstall tab ---------- */

type AppInfo struct {
	Path            string `json:"path"`
	Name            string `json:"name"`
	ID              string `json:"id"`
	Version         string `json:"version"`
	Kind            string `json:"kind,omitempty"`            // app | winapp | appdeck
	Scope           string `json:"scope,omitempty"`           // system | appdeck (macOS)
	Source          string `json:"source,omitempty"`          // AppDeck: registry | manifest | discovered
	UninstallString string `json:"uninstallString,omitempty"` // Windows: registered uninstaller
	Exe             string `json:"-"`
	Running         bool   `json:"running"`
}

type Leftover struct {
	Path      string `json:"path"`
	Kind      string `json:"kind"`
	SizeBytes int64  `json:"sizeBytes"`
}

// appDeckAppsDir: AppDeck installs its apps as <name>/<name>.app under this
// folder — a real install location for the Uninstall tab even though it is
// not /Applications.
func appDeckAppsDir() string {
	// Per-OS AppDeck data layouts: the Windows launcher unpacks and imports
	// into %LOCALAPPDATA%\AppDeck\Apps (LAUNCHER_DATA_DIR overrides it),
	// macOS uses ~/Library/Application Support/AppDeck/Apps. The Windows
	// branch previously returned the macOS spelling, so every AppDeck
	// entry carried a nonexistent path and the fallback uninstaller had
	// nothing to remove.
	if v := os.Getenv("LAUNCHER_DATA_DIR"); v != "" {
		return filepath.Join(v, "Apps")
	}
	if runtime.GOOS == "windows" {
		if la := os.Getenv("LOCALAPPDATA"); la != "" {
			return filepath.Join(la, "AppDeck", "Apps")
		}
	}
	return filepath.Join(homeDir(), "Library", "Application Support", "AppDeck", "Apps")
}

// appDeckDataDir: per-app data AppDeck keeps for its apps
// (<DataDir>/appdata/<id>) — the "app data" its own uninstall offers to
// remove alongside the app folder.
func appDeckDataDir() string {
	return filepath.Join(filepath.Dir(appDeckAppsDir()), "appdata")
}

// appDeckAppFolder maps an AppDeck-scope bundle path to the folder AppDeck
// itself manages: Apps/<name>/<name>.app → Apps/<name>. AppDeck discovers
// apps by scanning those folders for an app.json manifest, so trashing the
// bundle alone would leave the launcher still listing (and able to rebuild)
// the app — the folder is the install.
func appDeckAppFolder(bundlePath string) (string, bool) {
	p := filepath.Clean(bundlePath)
	folder := filepath.Dir(p)
	if strings.EqualFold(filepath.Dir(folder), appDeckAppsDir()) {
		return folder, true
	}
	return "", false
}

// appDeckDataDirs lists the AppDeck app-data folders an AppDeck-scope app
// may own, keyed by the manifest id (the Apps/<name> folder name) and the
// bundle id; leftoversFrom drops the ones that do not exist.
func appDeckDataDirs(app AppInfo) []leftoverCand {
	if app.Scope != "appdeck" {
		return nil
	}
	var cands []leftoverCand
	if folder, ok := appDeckAppFolder(app.Path); ok {
		cands = append(cands, leftoverCand{
			path: filepath.Join(appDeckDataDir(), strings.ToLower(filepath.Base(folder))),
			kind: "appdeck data",
		})
	}
	if app.ID != "" {
		cands = append(cands, leftoverCand{
			path: filepath.Join(appDeckDataDir(), strings.ToLower(app.ID)),
			kind: "appdeck data",
		})
	}
	return cands
}

// appScopes lists the macOS install locations Descale scans itself. The
// AppDeck apps are NOT here: their inventory comes from AppDeck (live
// /api/apps query, manifest fallback) so a new app added in AppDeck shows
// up without a Descale change — see appdeck.go.
func appScopes() []struct {
	glob  string
	scope string
} {
	return []struct {
		glob  string
		scope string
	}{
		{filepath.Join("/Applications", "*.app"), "system"},
		{filepath.Join(homeDir(), "Applications", "*.app"), "system"},
	}
}

// listApps enumerates installed applications per OS: .app bundles on macOS,
// .desktop entries (system + user scope, user wins) on Linux. Windows apps
// come from the registry instead (appsList -> listInstalledWindows). Every
// platform appends the AppDeck sub-list — the Uninstall tab's AppDeck
// section queries the live launcher (or falls back to the manifest scan),
// and Windows/Linux decks carry apps just the same.
func listApps() []AppInfo {
	switch runtime.GOOS {
	case "windows":
		return append(listInstalledWindows(), listAppDeckApps()...)
	case "linux":
		return append(listAppsLinux(), listAppDeckApps()...)
	default:
		return listAppsMac()
	}
}

func listAppsMac() []AppInfo {
	var bundles []string
	for _, sc := range appScopes() {
		matches, _ := filepath.Glob(sc.glob)
		bundles = append(bundles, matches...)
	}
	sort.Strings(bundles)
	sys := make([]AppInfo, len(bundles))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i, b := range bundles {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, b string) {
			defer wg.Done()
			<-sem
			info := appInfoFor(b)
			info.Scope = "system"
			sys[i] = info
		}(i, b)
	}
	wg.Wait()
	return append(sys, listAppDeckApps()...)
}

// listAppsLinux reads .desktop entries as the app inventory. A desktop file
// is the launcher identity: its id drives leftover hunting, its Exec names
// the running process. Package-managed binaries are not the desktop file's
// to remove — uninstalling here trashes the entry + leftovers.
func listAppsLinux() []AppInfo {
	home := homeDir()
	scopes := []struct {
		dir, scope string
	}{
		{filepath.Join(home, ".local", "share", "applications"), "user"},
		{"/usr/share/applications", "system"},
		{"/usr/local/share/applications", "system"},
	}
	byID := map[string]AppInfo{}
	var order []string
	for _, sc := range scopes {
		matches, _ := filepath.Glob(filepath.Join(sc.dir, "*.desktop"))
		sort.Strings(matches)
		for _, p := range matches {
			id := strings.TrimSuffix(filepath.Base(p), ".desktop")
			if _, dup := byID[id]; dup && sc.scope != "user" {
				continue // user entry wins over the system one
			}
			info := desktopAppInfo(p, id)
			if info.Name == "" {
				continue // not a displayable entry (e.g. action-only file)
			}
			if _, dup := byID[id]; !dup {
				order = append(order, id)
			}
			byID[id] = info
		}
	}
	out := make([]AppInfo, 0, len(order))
	for _, id := range order {
		out = append(out, byID[id])
	}
	return out
}

// desktopAppInfo parses the small subset of a .desktop file Descale needs.
func desktopAppInfo(path, id string) AppInfo {
	info := AppInfo{Path: path, ID: id, Kind: "app"}
	noDisplay := false
	f, err := os.Open(path)
	if err != nil {
		return info
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == "[Desktop Action" { // an actions-only section
			break
		}
		if !strings.HasPrefix(line, "[") && strings.Contains(line, "=") {
			key, val, _ := strings.Cut(line, "=")
			val = strings.TrimSpace(val)
			switch strings.TrimSpace(key) {
			case "Name":
				if info.Name == "" {
					info.Name = val // localized Name[xx]= keys never match here
				}
			case "NoDisplay":
				noDisplay = val == "true"
			case "Version":
				info.Version = val
			case "Exec":
				if info.Exe == "" {
					// first token, field codes (%f %u …) stripped
					if fields := strings.Fields(val); len(fields) > 0 {
						exe := fields[0]
						if i := strings.LastIndexByte(exe, '/'); i >= 0 {
							exe = exe[i+1:]
						}
						info.Exe = exe
					}
				}
			}
		}
	}
	if noDisplay || info.Name == "" {
		return AppInfo{Path: path, ID: id, Kind: "app"} // hidden entry
	}
	if info.Exe != "" && len(runningApps([]string{info.Exe})) > 0 {
		info.Running = true
	}
	return info
}

func appInfoFor(bundle string) AppInfo {
	info := AppInfo{Path: bundle, Name: strings.TrimSuffix(filepath.Base(bundle), ".app"), Kind: "app"}
	if d, err := readPlist(filepath.Join(bundle, "Contents", "Info.plist")); err == nil {
		if v, ok := d["CFBundleIdentifier"].(string); ok {
			info.ID = v
		}
		if v, ok := d["CFBundleName"].(string); ok && v != "" {
			info.Name = v
		}
		if v, ok := d["CFBundleShortVersionString"].(string); ok {
			info.Version = v
		}
		if v, ok := d["CFBundleExecutable"].(string); ok {
			info.Exe = v
		}
	}
	exe := info.Exe
	if exe == "" {
		exe = strings.TrimSuffix(filepath.Base(bundle), ".app")
	}
	if len(runningApps([]string{exe})) > 0 {
		info.Running = true
	}
	return out(info)
}

func out(a AppInfo) AppInfo { return a }

func dirSize(p string, fi os.FileInfo) int64 {
	if !fi.IsDir() {
		return fi.Size()
	}
	var n int64
	_ = filepath.WalkDir(p, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() {
			if info, e := d.Info(); e == nil {
				n += info.Size()
			}
		}
		return nil
	})
	return n
}

// appSearchNames returns the exact folder names an app's leftovers may use:
// its bundle/desktop id when known, the display name, and the lowercased
// display name (Linux and Windows apps conventionally use lowercase dirs).
func appSearchNames(app AppInfo) []string {
	var names []string
	seen := map[string]bool{}
	for _, n := range []string{app.ID, app.Name, strings.ToLower(app.Name)} {
		if n != "" && !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	return names
}

// appLeftovers hunts the files an app scatters outside its install, keyed by
// its id (and, secondarily, the display name). Only exact-name matches are
// proposed — no fuzzy "looks related" guessing. Same contract on every OS;
// the candidate locations differ.
func appLeftovers(app AppInfo) []Leftover {
	switch runtime.GOOS {
	case "windows":
		return leftoversFrom(appLeftoverCandidatesWindows(app))
	case "linux":
		return leftoversFrom(appLeftoverCandidatesLinux(app))
	default:
		return leftoversFrom(appLeftoverCandidatesMac(app))
	}
}

type leftoverCand struct {
	path, kind string
}

// leftoversFrom materializes candidates: existing paths only, sized, deduped,
// biggest first. Dedup is identity-based, not just string-based: on a
// case-insensitive volume the id-derived path ("app") and the name-derived
// one ("App") are the same directory, and os.SameFile sees that.
func leftoversFrom(cands []leftoverCand) []Leftover {
	home := homeDir()
	seen := map[string]bool{}
	caseSeen := map[string]string{} // lower(path) -> first path with it
	out := []Leftover{}             // never nil: this slice is returned as JSON and null breaks the client
	for _, c := range cands {
		if c.path == "" || seen[c.path] || c.path == home {
			continue
		}
		if reason := criticalReason(c.path); reason != "" {
			continue // a shared root is never a leftover, however it was derived
		}
		fi, err := os.Lstat(c.path)
		if err != nil {
			continue
		}
		if first, dup := caseSeen[strings.ToLower(c.path)]; dup {
			if fi2, err2 := os.Lstat(first); err2 == nil && os.SameFile(fi, fi2) {
				continue // same file, different spelling
			}
		}
		seen[c.path] = true
		caseSeen[strings.ToLower(c.path)] = c.path
		out = append(out, Leftover{Path: c.path, Kind: c.kind, SizeBytes: dirSize(c.path, fi)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SizeBytes > out[j].SizeBytes })
	return out
}

func appLeftoverCandidatesMac(app AppInfo) []leftoverCand {
	home := homeDir()
	var cands []leftoverCand
	// AppDeck keeps per-app data under its own data dir; the bundle-id and
	// name hunts below never look there. Wrapped .app bundles inside an
	// AppDeck folder carry their own bundle id — hunt by it too.
	names := appSearchNames(app)
	bundleID := ""
	if app.Scope == "appdeck" {
		cands = append(cands, appDeckDataDirs(app)...)
		bundleID = appDeckBundleID(app.Path)
		if bundleID != "" {
			names = append(names, bundleID)
		}
	}
	// filepath.Join drops empty elements, so a missing bundle id would turn
	// ".../Caches/<id>" into ".../Caches" — the shared root itself, every
	// application's data. appSearchNames yields only non-empty names, so a
	// no-bundle-id app proposes name-keyed locations or nothing at all.
	for _, key := range names {
		cands = append(cands,
			leftoverCand{filepath.Join(home, "Library", "Caches", key), "caches"},
			leftoverCand{filepath.Join(home, "Library", "Application Support", key), "data"},
			leftoverCand{filepath.Join(home, "Library", "Containers", key), "container"},
			leftoverCand{filepath.Join(home, "Library", "HTTPStorages", key), "storage"},
			leftoverCand{filepath.Join(home, "Library", "WebKit", key), "storage"},
			leftoverCand{filepath.Join(home, "Library", "Application Scripts", key), "scripts"},
			leftoverCand{filepath.Join(home, "Library", "Logs", key), "logs"},
		)
	}
	// id-keyed locations: the app's own id and, for wrapped AppDeck apps,
	// the inner bundle id (Preferences plists, saved states, agents).
	ids := make([]string, 0, 2)
	for _, id := range []string{app.ID, bundleID} {
		if id != "" {
			ids = append(ids, id)
		}
	}
	for _, id := range ids {
		cands = append(cands,
			leftoverCand{filepath.Join(home, "Library", "Preferences", id+".plist"), "preferences"},
			leftoverCand{filepath.Join(home, "Library", "Saved Application State", id+".savedState"), "state"},
		)
		agents, _ := filepath.Glob(filepath.Join(home, "Library", "LaunchAgents", "*.plist"))
		for _, a := range agents {
			if d, err := readPlist(a); err == nil {
				blob := fmt.Sprint(d["Label"], "|", d["Program"], "|", d["ProgramArguments"])
				if strings.Contains(blob, id) {
					cands = append(cands, leftoverCand{a, "launch agent"})
				}
			}
		}
	}
	return cands
}

func appLeftoverCandidatesWindows(app AppInfo) []leftoverCand {
	local := os.Getenv("LOCALAPPDATA")
	roaming := os.Getenv("APPDATA")
	programData := os.Getenv("ProgramData")
	if local == "" || roaming == "" {
		return nil // env shape unexpected; propose nothing rather than guess
	}
	if programData == "" {
		programData = `C:\ProgramData`
	}
	var cands []leftoverCand
	for _, n := range appSearchNames(app) {
		cands = append(cands,
			leftoverCand{filepath.Join(local, n), "data"},
			leftoverCand{filepath.Join(roaming, n), "data"},
			leftoverCand{filepath.Join(programData, n), "data"},
			leftoverCand{filepath.Join(local, "Programs", n), "programs"},
		)
		// vendor-nested layout: "Google Chrome" -> ...\Google\Chrome (the
		// dominant Windows convention; still derived from the exact name)
		if vendor, rest, cut := strings.Cut(n, " "); cut && vendor != "" && rest != "" {
			cands = append(cands,
				leftoverCand{filepath.Join(local, vendor, rest), "data"},
				leftoverCand{filepath.Join(roaming, vendor, rest), "data"},
			)
		}
		// Start Menu folders and .lnk shortcuts, user and all-users scope
		for _, root := range []string{roaming, programData} {
			matches, _ := filepath.Glob(filepath.Join(root, "Microsoft",
				"Windows", "Start Menu", "Programs", n+"*"))
			for _, m := range matches {
				cands = append(cands, leftoverCand{m, "shortcuts"})
			}
		}
	}
	return cands
}

func appLeftoverCandidatesLinux(app AppInfo) []leftoverCand {
	home := homeDir()
	var cands []leftoverCand
	for _, n := range appSearchNames(app) {
		cands = append(cands,
			leftoverCand{filepath.Join(home, ".config", n), "data"},
			leftoverCand{filepath.Join(home, ".cache", n), "caches"},
			leftoverCand{filepath.Join(home, ".local", "share", n), "data"},
			leftoverCand{filepath.Join(home, ".local", "state", n), "state"},
			leftoverCand{filepath.Join(home, "."+n), "data"},
			leftoverCand{filepath.Join(home, "snap", n), "snap"},
		)
	}
	if app.ID != "" {
		// flatpak per-app data lives under the desktop id, not the name
		cands = append(cands,
			leftoverCand{filepath.Join(home, ".var", "app", app.ID), "flatpak"})
	}
	return cands
}

type appsListResult struct {
	Apps []AppInfo `json:"apps"`
	Note string    `json:"note,omitempty"`
}

// appsList is the shared source for /api/apps and `descale apps`.
func (s *server) appsList() appsListResult {
	apps := listApps()
	if runtime.GOOS == "windows" {
		return appsListResult{
			Apps: apps,
			Note: "Uninstall runs each application's own uninstaller (interactive). After it finishes, open the app again and delete the leftovers it left behind.",
		}
	}
	if runtime.GOOS == "linux" {
		return appsListResult{
			Apps: apps,
			Note: "Applications are the .desktop launcher entries; deleting leftovers removes their config/cache/data folders. Package-managed binaries stay — use your package manager to remove those.",
		}
	}
	return appsListResult{Apps: apps}
}

func (s *server) handleApps(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.appsList())
}

// findApp looks the path up in the same list the dashboard showed — the
// per-OS inventory, not just macOS bundles, so Windows registry entries and
// Linux desktop entries validate too.
func (s *server) findApp(path string) *AppInfo {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	apps := s.appsList().Apps
	for i := range apps {
		if apps[i].Path == path {
			return &apps[i]
		}
	}
	return nil
}

// uninstallBundlePath: what "uninstall the application" removes. For an
// AppDeck-scope app that is the whole Apps/<name> folder AppDeck manages —
// the .app bundle lives inside it, and the launcher keys its app list off
// the folder.
func uninstallBundlePath(app AppInfo) string {
	if app.Scope == "appdeck" {
		if folder, ok := appDeckAppFolder(app.Path); ok {
			return folder
		}
	}
	return app.Path
}

func (s *server) handleAppLeftovers(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, "bad request body")
		return
	}
	app := s.findApp(req.Path)
	if app == nil {
		fail(w, http.StatusBadRequest, "application is not in the scanned install list")
		return
	}
	bundlePath := uninstallBundlePath(*app)
	bundleSize := int64(0)
	if fi, err := os.Lstat(bundlePath); err == nil {
		bundleSize = dirSize(bundlePath, fi)
	}
	left := appLeftovers(*app)
	var total int64
	for _, l := range left {
		total += l.SizeBytes
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"app": app, "bundlePath": bundlePath, "leftovers": left, "bundleBytes": bundleSize,
		"leftoverBytes": total, "totalBytes": total + bundleSize,
	})
}

func (s *server) handleAppUninstall(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path    string `json:"path"`
		Confirm bool   `json:"confirm"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, "bad request body")
		return
	}
	if runtime.GOOS == "windows" {
		// Registry entries run their vendor uninstaller (below). AppDeck
		// entries are not registry installs — they share the cross-platform
		// flow below, which delegates to the launcher (or trashes the folder
		// itself) exactly like the macOS path.
		if app := s.findApp(req.Path); app == nil || app.Kind != "appdeck" {
			s.uninstallWindows(w, req.Path, req.Confirm)
			return
		}
	}
	var log stepLogger
	log.addf("uninstall requested for %q", req.Path)
	app := s.findApp(req.Path)
	if app == nil {
		log.addf("FAILED: %q is not in the scanned install list", req.Path)
		failWithLog(w, http.StatusBadRequest, "application is not in the scanned install list", log.steps)
		return
	}
	log.addf("resolved: %s (kind %s, scope %s, id %s)", app.Name, app.Kind, app.Scope, app.ID)
	appdeck := app.Kind == "appdeck"
	if app.Running && !appdeck {
		log.addf("REFUSED: %s is running — quit it first", app.Name)
		failWithLog(w, http.StatusConflict, app.Name+" is running — quit it first", log.steps)
		return
	}
	bundlePath, bundleSize, left := planUninstall(app)
	log.addf("bundle: %s (%s)", bundlePath, fmtBytes(bundleSize))
	log.addf("leftover locations: %d", len(left))

	if !req.Confirm {
		var total int64
		for _, l := range left {
			total += l.SizeBytes
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"confirmRequired": true, "app": app, "bundlePath": bundlePath, "leftovers": left,
			"bundleBytes": bundleSize, "leftoverBytes": total,
			"totalBytes": total + bundleSize, "log": log.steps,
		})
		return
	}

	out, appErr := s.uninstallAppCore(app, &log)
	if appErr != nil {
		failWithLog(w, appErr.code, appErr.msg, log.steps)
		return
	}
	summary := fmt.Sprintf("%d item(s) · %s → Trash · %d failed",
		out.entry.Files, fmtBytes(out.entry.Bytes), len(out.failures))
	logPath := s.saveOpLog("uninstall", log.steps, summary)
	if logPath != "" {
		log.addf("log saved: %s", logPath)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "app": app.Name, "bytes": out.entry.Bytes, "files": out.entry.Files,
		"failed": out.failures, "note": out.note, "log": log.steps, "logPath": logPath,
	})
}

// planUninstall resolves what one uninstall will touch: the bundle path,
// its size, and every leftover location. Shared by the single-app flow and
// the batch endpoint.
func planUninstall(app *AppInfo) (string, int64, []Leftover) {
	bundlePath := uninstallBundlePath(*app)
	bundleSize := int64(0)
	if fi, err := os.Lstat(bundlePath); err == nil {
		bundleSize = dirSize(bundlePath, fi)
	}
	return bundlePath, bundleSize, appLeftovers(*app)
}

// appUninstallOutcome is what trashing one application produced.
type appUninstallOutcome struct {
	entry   JournalEntry
	note    string
	failures []map[string]string
}

// uninstallAppCore performs the trash/delegate work for ONE application:
// moves the bundle plus every leftover to the Trash (or delegates an
// AppDeck app to the launcher), writes one journal entry, and returns the
// outcome with its step trail appended to log. Callers validate first —
// running/winapp/appdeck-scope classification stays with them. Refusals
// from the AppDeck delegation come back as *appError.
func (s *server) uninstallAppCore(app *AppInfo, log *stepLogger) (*appUninstallOutcome, *appError) {
	appdeck := app.Kind == "appdeck"
	bundlePath, bundleSize, left := planUninstall(app)
	log.addf("bundle: %s (%s)", bundlePath, fmtBytes(bundleSize))
	log.addf("leftover locations: %d", len(left))

	trashDir := trashDirPath()
	_ = os.MkdirAll(trashDir, 0o755)
	out := &appUninstallOutcome{
		entry: JournalEntry{
			ID:     fmt.Sprintf("e%d", time.Now().UnixNano()),
			At:     time.Now().UTC().Format(time.RFC3339),
			Action: "uninstall",
			Name:   app.Name,
		},
	}
	move := func(p string, size int64) {
		log.addf("moving %s (%s) → Trash…", p, fmtBytes(size))
		if reason := criticalReason(p); reason != "" {
			log.addf("REFUSED: %s", reason)
			out.failures = append(out.failures, map[string]string{"rule": "uninstall", "path": p, "error": "refused: " + reason})
			return
		}
		dst, err := trashTo(trashDirPath(), p)
		if err != nil {
			log.addf("FAILED: %s — %v", p, err)
			out.failures = append(out.failures, map[string]string{"rule": "uninstall", "path": p, "error": err.Error()})
			return
		}
		log.addf("ok → Trash/%s", filepath.Base(dst))
		out.entry.Items = append(out.entry.Items, JournalItem{Path: p, Trash: filepath.Base(dst)})
		out.entry.Bytes += size
		out.entry.Files++
	}

	if appdeck {
		// Same semantics as AppDeck's own uninstall: the launcher stops the
		// app, removes its folder and records the removal. Refusals (e.g.
		// apps registered in apps.json) come back verbatim with nothing
		// touched here. With the launcher down, Descale trashes the folder
		// itself and records the id so an embedded launcher will not
		// resurrect the app.
		log.addf("AppDeck app — delegating to the AppDeck launcher…")
		note, err := appDeckUninstall(app.ID)
		switch {
		case err == nil:
			log.addf("ok — launcher removed the app folder")
			out.note = "app folder removed by AppDeck (permanent, as in AppDeck's own uninstall)"
			if note != "" {
				out.note = "app folder removed by AppDeck — " + note
			}
		case errors.Is(err, errAppDeckDown):
			log.addf("launcher unreachable — trashing the folder directly…")
			move(bundlePath, bundleSize)
			recordAppDeckUninstalled(app.ID)
			out.note = "AppDeck is not running — app folder moved to the Trash (restorable)"
		default:
			log.addf("REFUSED by AppDeck: %v", err)
			return nil, &appError{http.StatusConflict, "AppDeck refused: " + err.Error()}
		}
	} else {
		move(bundlePath, bundleSize)
	}
	for _, l := range left {
		move(l.Path, l.SizeBytes)
	}
	if out.entry.Files > 0 || len(out.entry.Commands) > 0 {
		s.saveJournal(out.entry)
		log.addf("journal saved (%d item(s), %s) — restorable", out.entry.Files, fmtBytes(out.entry.Bytes))
	} else {
		log.addf("nothing moved — journal skipped")
	}
	if runtime.GOOS == "linux" {
		out.note += "menu entry and leftovers trashed; package-managed binaries " +
			"remain — remove them with your package manager"
	}
	log.addf("done: %d item(s) moved, %d failed", out.entry.Files, len(out.failures))
	return out, nil
}

// handleAppsUninstallBatch uninstalls SEVERAL applications in one confirmed
// operation. Every path is resolved against a single fresh scan (the
// single-app flow re-scans per call — a batch must not). Apps that cannot
// take part are skipped with a reason rather than failing the batch:
// running apps, Windows registry entries (their vendor uninstaller is
// interactive), and AppDeck apps (removed permanently by the launcher —
// mixing a permanent delete into a Trash-restorable batch would break the
// safety story; uninstall those from the launcher). Each eligible app gets
// its own journal entry, so every uninstall stays individually restorable.
func (s *server) handleAppsUninstallBatch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Paths []string `json:"paths"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, "bad request body")
		return
	}
	if len(req.Paths) == 0 {
		fail(w, http.StatusBadRequest, "select at least one application")
		return
	}
	if len(req.Paths) > 24 {
		fail(w, http.StatusBadRequest, "uninstall at most 24 applications at once")
		return
	}

	var log stepLogger
	log.addf("batch uninstall requested for %d application(s)", len(req.Paths))
	list := s.appsList()
	byPath := make(map[string]*AppInfo, len(list.Apps))
	for i := range list.Apps {
		byPath[list.Apps[i].Path] = &list.Apps[i]
	}

	type batchResult struct {
		Path   string `json:"path"`
		Name   string `json:"name,omitempty"`
		OK     bool   `json:"ok"`
		Bytes  int64  `json:"bytes,omitempty"`
		Files  int    `json:"files,omitempty"`
		Error  string `json:"error,omitempty"`
	}
	var results []batchResult
	var skipped []map[string]string
	trashed, totalBytes := 0, int64(0)
	for _, p := range req.Paths {
		app := byPath[p]
		switch {
		case app == nil:
			log.addf("SKIP %q — not in the scanned install list", p)
			skipped = append(skipped, map[string]string{"path": p, "reason": "not in the scanned install list"})
			results = append(results, batchResult{Path: p, Error: "not in the scanned install list"})
			continue
		case app.Kind == "winapp":
			log.addf("SKIP %s — its vendor uninstaller is interactive; uninstall it on its own", app.Name)
			skipped = append(skipped, map[string]string{"path": p, "reason": app.Name + " needs its vendor's interactive uninstaller — uninstall it on its own"})
			results = append(results, batchResult{Path: p, Name: app.Name, Error: "needs its vendor's interactive uninstaller"})
			continue
		case app.Scope == "appdeck" && app.Kind == "appdeck":
			log.addf("SKIP %s — AppDeck apps are removed permanently; uninstall from the launcher", app.Name)
			skipped = append(skipped, map[string]string{"path": p, "reason": app.Name + " is an AppDeck app — uninstall it from the launcher (permanent there)"})
			results = append(results, batchResult{Path: p, Name: app.Name, Error: "AppDeck app — uninstall from the launcher"})
			continue
		case app.Running:
			log.addf("SKIP %s — running; quit it first", app.Name)
			skipped = append(skipped, map[string]string{"path": p, "reason": app.Name + " is running — quit it first"})
			results = append(results, batchResult{Path: p, Name: app.Name, Error: app.Name + " is running"})
			continue
		}
		appLog := stepLogger{}
		appLog.addf("uninstalling %s…", app.Name)
		out, appErr := s.uninstallAppCore(app, &appLog)
		if appErr != nil {
			log.addf("FAILED %s: %s", app.Name, appErr.msg)
			results = append(results, batchResult{Path: p, Name: app.Name, Error: appErr.msg})
			continue
		}
		log.steps = append(log.steps, appLog.steps...)
		log.addf("OK %s — %d item(s), %s", app.Name, out.entry.Files, fmtBytes(out.entry.Bytes))
		results = append(results, batchResult{Path: p, Name: app.Name, OK: true,
			Bytes: out.entry.Bytes, Files: out.entry.Files})
		trashed++
		totalBytes += out.entry.Bytes
	}

	log.addf("batch done: %d uninstalled, %d skipped, %d failed — %s total",
		trashed, len(skipped), len(results)-trashed-len(skipped), fmtBytes(totalBytes))
	summary := fmt.Sprintf("%d app(s) · %s → Trash", trashed, fmtBytes(totalBytes))
	logPath := s.saveOpLog("batch-uninstall", log.steps, summary)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "uninstalled": trashed, "bytes": totalBytes,
		"results": results, "skipped": skipped, "log": log.steps, "logPath": logPath,
	})
}

// handleAppLeftoversDelete trashes checked leftover locations WITHOUT
// uninstalling the app — the "app is gone but its folders are still here"
// case on every OS (Windows after an uninstaller ran, Linux after a package
// removal, macOS after a manual drag-to-Trash). Requested paths are
// validated against a fresh scan of the app's leftovers: only locations the
// scan itself proposes can be trashed, so the endpoint cannot be talked
// into moving arbitrary directories.
func (s *server) handleAppLeftoversDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path  string   `json:"path"`
		Paths []string `json:"paths"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, "bad request body")
		return
	}
	app := s.findApp(req.Path)
	if app == nil {
		fail(w, http.StatusBadRequest, "application is not in the scanned install list")
		return
	}
	if app.Running {
		fail(w, http.StatusConflict, app.Name+" is running — quit it first (its folders may be in use)")
		return
	}
	var log stepLogger
	log.addf("leftover deletion requested for %s", app.Name)
	allowed := map[string]int64{}
	for _, l := range appLeftovers(*app) {
		allowed[l.Path] = l.SizeBytes
	}
	log.addf("scan proposes %d leftover location(s)", len(allowed))
	trashDir := trashDirPath()
	_ = os.MkdirAll(trashDir, 0o755)
	entry := JournalEntry{
		ID:     fmt.Sprintf("e%d", time.Now().UnixNano()),
		At:     time.Now().UTC().Format(time.RFC3339),
		Action: "leftovers",
		Name:   app.Name,
	}
	var failures, skipped []map[string]string
	removed := 0
	var bytes int64
	for _, p := range req.Paths {
		if reason := criticalReason(p); reason != "" {
			log.addf("SKIPPED %s: %s", p, reason)
			skipped = append(skipped, map[string]string{"path": p, "reason": reason})
			continue
		}
		size, ok := allowed[p]
		if !ok {
			log.addf("SKIPPED %s: not in the app's leftover scan", p)
			skipped = append(skipped, map[string]string{"path": p,
				"reason": "not in the app's leftover scan"})
			continue
		}
		log.addf("moving %s (%s) → Trash…", p, fmtBytes(size))
		dst, err := trashTo(trashDir, p)
		if err != nil {
			log.addf("FAILED: %s — %v", p, err)
			failures = append(failures, map[string]string{"path": p, "error": err.Error()})
			continue
		}
		log.addf("ok → Trash/%s", filepath.Base(dst))
		entry.Items = append(entry.Items, JournalItem{Path: p, Trash: filepath.Base(dst)})
		entry.Bytes += size
		entry.Files++
		removed++
		bytes += size
	}
	if entry.Files > 0 {
		s.saveJournal(entry)
		log.addf("journal saved (%d item(s), %s) — restorable", entry.Files, fmtBytes(entry.Bytes))
	} else {
		log.addf("nothing moved — journal skipped")
	}
	log.addf("done: %d moved, %d skipped, %d failed", removed, len(skipped), len(failures))
	summary := fmt.Sprintf("%d moved · %s → Trash · %d skipped · %d failed",
		removed, fmtBytes(bytes), len(skipped), len(failures))
	logPath := s.saveOpLog("leftovers", log.steps, summary)
	if logPath != "" {
		log.addf("log saved: %s", logPath)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "app": app.Name, "removed": removed, "bytes": bytes,
		"files": entry.Files, "failed": failures, "skipped": skipped, "log": log.steps,
		"logPath": logPath,
	})
}

/* ---------- Startup tab ---------- */

type StartupItem struct {
	Path      string `json:"path"`
	Name      string `json:"name"`
	Label     string `json:"label"`
	Program   string `json:"program"`
	RunAtLoad bool   `json:"runAtLoad"`
	KeepAlive bool   `json:"keepAlive"`
	Active    bool   `json:"active"`
	Scope     string `json:"scope"`          // user | system
	Kind      string `json:"kind,omitempty"` // launchagent | runkey | startupfolder
}

// listStartup dispatches per OS: LaunchAgents on macOS/Linux, Run keys and
// the Startup folder on Windows.
func listStartup() []StartupItem {
	if runtime.GOOS == "windows" {
		return listStartupWindows()
	}
	return listStartupAgents()
}

func listStartupAgents() []StartupItem {
	home := homeDir()
	scopes := []struct{ dir, scope string }{
		{filepath.Join(home, "Library", "LaunchAgents"), "user"},
		{"/Library/LaunchAgents", "system"},
		{"/Library/LaunchDaemons", "system"},
	}
	var out []StartupItem
	for _, sc := range scopes {
		paths, _ := filepath.Glob(filepath.Join(sc.dir, "*.plist"))
		disabled, _ := filepath.Glob(filepath.Join(sc.dir, "*.plist.disabled"))
		paths = append(paths, disabled...)
		sort.Strings(paths)
		for _, p := range paths {
			it := StartupItem{
				Path:   p,
				Scope:  sc.scope,
				Active: !strings.HasSuffix(p, ".disabled"),
				Name:   filepath.Base(p),
			}
			if d, err := readPlist(p); err == nil {
				if v, ok := d["Label"].(string); ok {
					it.Label = v
				}
				if pa, ok := d["ProgramArguments"].([]string); ok && len(pa) > 0 {
					it.Program = pa[0]
				}
				if v, ok := d["Program"].(string); ok && it.Program == "" {
					it.Program = v
				}
				if b, ok := d["RunAtLoad"].(bool); ok {
					it.RunAtLoad = b
				}
				if b, ok := d["KeepAlive"].(bool); ok {
					it.KeepAlive = b
				}
				if b, ok := d["Disabled"].(bool); ok && b {
					it.Active = false
				}
			}
			if it.Label == "" {
				it.Label = strings.TrimSuffix(strings.TrimSuffix(filepath.Base(p), ".disabled"), ".plist")
			}
			out = append(out, it)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Scope != out[j].Scope {
			return out[i].Scope == "user"
		}
		return out[i].Label < out[j].Label
	})
	return out
}

func (s *server) handleStartup(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": listStartup()})
}

func (s *server) handleStartupToggle(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path     string `json:"path"`
		Activate bool   `json:"activate"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, "bad request body")
		return
	}
	if runtime.GOOS == "windows" {
		s.startupToggleWindows(w, req.Path, req.Activate)
		return
	}
	s.startupToggleAgents(w, req.Path, req.Activate)
}

func (s *server) startupToggleAgents(w http.ResponseWriter, path string, activate bool) {
	var it *StartupItem
	for _, item := range listStartupAgents() {
		if item.Path == path {
			it = &item
			break
		}
	}
	if it == nil {
		fail(w, http.StatusBadRequest, "startup item is not in the scanned list")
		return
	}
	if it.Scope != "user" {
		fail(w, http.StatusForbidden, "system-wide agents/daemons need an administrator — Descale manages only your own Launch Agents (~/Library/LaunchAgents)")
		return
	}
	uid := os.Getuid()
	var outputs []string
	from, to := it.Path, it.Path
	if activate {
		if !strings.HasSuffix(it.Path, ".disabled") {
			fail(w, http.StatusBadRequest, "item is already active")
			return
		}
		to = strings.TrimSuffix(it.Path, ".disabled")
		if err := os.Rename(it.Path, to); err != nil {
			fail(w, http.StatusInternalServerError, err.Error())
			return
		}
		out, err := exec.Command("launchctl", "bootstrap", fmt.Sprintf("gui/%d", uid), to).CombinedOutput()
		outputs = append(outputs, "bootstrap: "+strings.TrimSpace(string(out))+errString(err))
	} else {
		if !strings.HasSuffix(it.Path, ".plist") {
			fail(w, http.StatusBadRequest, "item is already deactivated")
			return
		}
		label := it.Label
		if label == "" {
			label = strings.TrimSuffix(filepath.Base(it.Path), ".plist")
		}
		out, _ := exec.Command("launchctl", "bootout", fmt.Sprintf("gui/%d/%s", uid, label)).CombinedOutput()
		outputs = append(outputs, "bootout: "+strings.TrimSpace(string(out)))
		to = it.Path + ".disabled"
		if err := os.Rename(it.Path, to); err != nil {
			fail(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	entry := JournalEntry{
		ID:       fmt.Sprintf("e%d", time.Now().UnixNano()),
		At:       time.Now().UTC().Format(time.RFC3339),
		Action:   "startup",
		Name:     it.Label,
		Commands: outputs,
		Rules:    []string{"launch-agent"},
	}
	entry.Items = []JournalItem{{Path: from, Trash: filepath.Base(to)}}
	s.saveJournal(entry)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "active": activate, "output": strings.Join(outputs, " | ")})
}

func errString(err error) string {
	if err != nil {
		return " (" + err.Error() + ")"
	}
	return ""
}

/* ---------- app icons (Uninstall tab visuals) ---------- */

var (
	iconMu    sync.Mutex
	iconCache = map[string][]byte{}
)

// handleAppIcon serves an app's icon as PNG, extracted from the bundle's
// .icns via macOS sips. Cached per app path; 404 when nothing can be
// extracted (the UI falls back to a glyph). No icon bytes leave the
// machine — this is a localhost-only endpoint.
func (s *server) handleAppIcon(w http.ResponseWriter, r *http.Request) {
	if runtime.GOOS != "darwin" {
		http.NotFound(w, r)
		return
	}
	app := s.findApp(r.URL.Query().Get("path"))
	if app == nil {
		http.NotFound(w, r)
		return
	}
	// AppDeck apps have no bundle: their icon is the manifest folder's
	// icon.png (what AppDeck's dashboard shows).
	if app.Kind == "appdeck" {
		png, err := os.ReadFile(filepath.Join(app.Path, "icon.png"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(png)
		return
	}
	iconMu.Lock()
	png, ok := iconCache[app.Path]
	iconMu.Unlock()
	if ok {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(png)
		return
	}
	d, err := readPlist(filepath.Join(app.Path, "Contents", "Info.plist"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	resDir := filepath.Join(app.Path, "Contents", "Resources")
	var icns string
	if name, ok := d["CFBundleIconFile"].(string); ok && name != "" {
		cand := filepath.Join(resDir, strings.TrimSuffix(name, ".icns")+".icns")
		if _, err := os.Stat(cand); err == nil {
			icns = cand
		}
	}
	if icns == "" {
		if name, ok := d["CFBundleIconName"].(string); ok && name != "" {
			cand := filepath.Join(resDir, name+".icns")
			if _, err := os.Stat(cand); err == nil {
				icns = cand
			}
		}
	}
	if icns == "" {
		matches, _ := filepath.Glob(filepath.Join(resDir, "*.icns"))
		if len(matches) > 0 {
			sort.Strings(matches)
			icns = matches[0]
		}
	}
	if icns == "" {
		http.NotFound(w, r)
		return
	}
	tmp, err := os.CreateTemp("", "descale-icon-*.png")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	tmpPath := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpPath)
	if out, err := exec.Command("sips", "-s", "format", "png", "--resampleHeightWidthMax", "128", icns, "--out", tmpPath).CombinedOutput(); err != nil {
		_ = out
		http.NotFound(w, r)
		return
	}
	png, err = os.ReadFile(tmpPath)
	if err != nil || len(png) < 8 {
		http.NotFound(w, r)
		return
	}
	iconMu.Lock()
	iconCache[app.Path] = png
	iconMu.Unlock()
	w.Header().Set("Content-Type", "image/png")
	_, _ = w.Write(png)
}

/* ---------- Windows startup (HKCU Run keys + Startup folder) ---------- */

const (
	winRunKeyUser   = `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
	winRunKeySystem = `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
)

type winRegValue struct {
	Type string
	Data string
}

type deactivatedRun struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Data string `json:"data"`
}

// winStorePath persists deactivated Run-key values so Activate can put them
// back without a journal dig.
func winStorePath() string {
	return filepath.Join(homeDir(), ".descale", "win-startup.json")
}

func winReadDeactivated() []deactivatedRun {
	raw, err := os.ReadFile(winStorePath())
	if err != nil {
		return nil
	}
	var list []deactivatedRun
	if json.Unmarshal(raw, &list) != nil {
		return nil
	}
	return list
}

func winWriteDeactivated(list []deactivatedRun) {
	data, err := json.MarshalIndent(list, "", " ")
	if err != nil {
		return
	}
	p := winStorePath()
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	tmp := p + ".tmp"
	if os.WriteFile(tmp, data, 0o600) == nil {
		_ = os.Rename(tmp, p)
	}
}

var winRegValueRe = regexp.MustCompile(`^\s*(\S+)\s+REG_([A-Z_]+)\s+(.*)$`)

// winRegQuery parses `reg query` output: one value per line of the form
// "    Name    REG_SZ    data". The key header line doesn't match.
func winRegQuery(key string) (map[string]winRegValue, error) {
	out, err := exec.Command("reg", "query", key).Output()
	if err != nil {
		return nil, err
	}
	values := map[string]winRegValue{}
	for _, line := range strings.Split(string(out), "\r\n") {
		if m := winRegValueRe.FindStringSubmatch(strings.TrimRight(line, "\r\n")); m != nil {
			values[m[1]] = winRegValue{Type: "REG_" + m[2], Data: strings.TrimSpace(m[3])}
		}
	}
	return values, nil
}

func listStartupWindows() []StartupItem {
	var out []StartupItem
	if vals, err := winRegQuery(winRunKeyUser); err == nil {
		names := make([]string, 0, len(vals))
		for n := range vals {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			out = append(out, StartupItem{
				Path: "reg://HKCU/Run/" + n, Name: n, Label: n,
				Program: vals[n].Data, Active: true, Scope: "user", Kind: "runkey",
			})
		}
	}
	for _, d := range winReadDeactivated() {
		out = append(out, StartupItem{
			Path: "reg://HKCU/Run/" + d.Name, Name: d.Name, Label: d.Name,
			Program: d.Data, Active: false, Scope: "user", Kind: "runkey",
		})
	}
	if vals, err := winRegQuery(winRunKeySystem); err == nil {
		names := make([]string, 0, len(vals))
		for n := range vals {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			out = append(out, StartupItem{
				Path: "reg://HKLM/Run/" + n, Name: n, Label: n,
				Program: vals[n].Data, Active: true, Scope: "system", Kind: "runkey",
			})
		}
	}
	dir := filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
	lnks, _ := filepath.Glob(filepath.Join(dir, "*.lnk"))
	disabled, _ := filepath.Glob(filepath.Join(dir, "*.lnk.disabled"))
	paths := append(lnks, disabled...)
	sort.Strings(paths)
	for _, p := range paths {
		out = append(out, StartupItem{
			Path:   p,
			Name:   filepath.Base(p),
			Label:  strings.TrimSuffix(strings.TrimSuffix(filepath.Base(p), ".disabled"), ".lnk"),
			Active: !strings.HasSuffix(p, ".disabled"),
			Scope:  "user",
			Kind:   "startupfolder",
		})
	}
	return out
}

func (s *server) startupToggleWindows(w http.ResponseWriter, path string, activate bool) {
	switch {
	case strings.HasPrefix(path, "reg://HKCU/Run/"):
		name := strings.TrimPrefix(path, "reg://HKCU/Run/")
		if activate {
			var found *deactivatedRun
			rest := []deactivatedRun{}
			for _, d := range winReadDeactivated() {
				if d.Name == name {
					found = &d
				} else {
					rest = append(rest, d)
				}
			}
			if found == nil {
				fail(w, http.StatusBadRequest, "no stored value for "+name)
				return
			}
			out, err := exec.Command("reg", "add", winRunKeyUser, "/v", name, "/t", found.Type, "/d", found.Data, "/f").CombinedOutput()
			if err != nil {
				fail(w, http.StatusInternalServerError, strings.TrimSpace(string(out))+errString(err))
				return
			}
			winWriteDeactivated(rest)
			s.journalStartup(name, "reg delete "+winRunKeyUser+" /v "+name, nil)
		} else {
			vals, err := winRegQuery(winRunKeyUser)
			if err != nil {
				fail(w, http.StatusInternalServerError, err.Error())
				return
			}
			v, ok := vals[name]
			if !ok {
				fail(w, http.StatusBadRequest, "value not found in "+winRunKeyUser)
				return
			}
			if out, err := exec.Command("reg", "delete", winRunKeyUser, "/v", name, "/f").CombinedOutput(); err != nil {
				fail(w, http.StatusInternalServerError, strings.TrimSpace(string(out))+errString(err))
				return
			}
			list := winReadDeactivated()
			list = append(list, deactivatedRun{Name: name, Type: v.Type, Data: v.Data})
			winWriteDeactivated(list)
			s.journalStartup(name, "reg add "+winRunKeyUser+" /v "+name, nil)
		}
	case strings.HasSuffix(path, ".lnk") || strings.HasSuffix(path, ".lnk.disabled"):
		var from, to string
		if activate {
			if !strings.HasSuffix(path, ".disabled") {
				fail(w, http.StatusBadRequest, "item is already active")
				return
			}
			from, to = path, strings.TrimSuffix(path, ".disabled")
		} else {
			if strings.HasSuffix(path, ".disabled") {
				fail(w, http.StatusBadRequest, "item is already deactivated")
				return
			}
			from, to = path, path+".disabled"
		}
		if err := os.Rename(from, to); err != nil {
			fail(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.journalStartup(filepath.Base(path), "rename "+filepath.Base(from)+" -> "+filepath.Base(to), nil)
	default:
		fail(w, http.StatusBadRequest, "unknown startup item: "+path)
	}
}

func (s *server) journalStartup(name, command string, items []JournalItem) {
	entry := JournalEntry{
		ID:       fmt.Sprintf("e%d", time.Now().UnixNano()),
		At:       time.Now().UTC().Format(time.RFC3339),
		Action:   "startup",
		Name:     name,
		Commands: []string{command},
		Rules:    []string{"windows-startup"},
	}
	if items != nil {
		entry.Items = items
	}
	if entry.Files > 0 || len(entry.Commands) > 0 {
		s.saveJournal(entry)
	}
}

/* ---------- Windows: installed programs (registry Uninstall keys) ---------- */

func listInstalledWindows() []AppInfo {
	var out []AppInfo
	for _, root := range []string{
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
		`HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall`,
	} {
		out = append(out, winUninstallEnum(root)...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// winHiveFull maps the hive abbreviations reg.exe accepts as input to the
// full names it echoes in key header lines: `reg query HKLM\... /s` prints
// HKEY_LOCAL_MACHINE\... headers, so header matching must compare against
// the expanded form (and, defensively, the abbreviated one too).
var winHiveFull = map[string]string{
	"HKLM": "HKEY_LOCAL_MACHINE",
	"HKCU": "HKEY_CURRENT_USER",
	"HKCR": "HKEY_CLASSES_ROOT",
	"HKU":  "HKEY_USERS",
	"HKCC": "HKEY_CURRENT_CONFIG",
}

// winFullKeyPath expands a leading hive abbreviation to reg.exe's full
// hive name; unknown forms pass through unchanged.
func winFullKeyPath(root string) string {
	hive, rest, cut := strings.Cut(root, `\`)
	if full, ok := winHiveFull[strings.ToUpper(hive)]; ok {
		if cut {
			return full + `\` + rest
		}
		return full
	}
	return root
}

// winUninstallEnum walks an Uninstall key with `reg query /s`; every
// subkey with a DisplayName and an UninstallString becomes an entry.
// SystemComponent=1 entries are hidden (that is what the flag means).
func winUninstallEnum(root string) []AppInfo {
	out, err := exec.Command("reg", "query", root, "/s").Output()
	if err != nil && len(out) == 0 {
		return nil
	}
	return parseWinUninstallQuery(root, string(out))
}

// winRegKeyRe recognizes a `reg query /s` key header line after trimming:
// any full or abbreviated hive name followed by a backslash. Headers bound
// registry blocks — a foreign header (or a blank line) must flush the
// candidate collected so far, or the next block's values bleed into it.
var winRegKeyRe = regexp.MustCompile(`(?i)^(?:HKEY_|HKLM\\|HKCU\\|HKCR\\|HKU\\|HKCC\\)`)

// parseWinUninstallQuery parses `reg query <root> /s` output: key header
// lines start a candidate app, value lines fill it in, and only candidates
// with both a DisplayName and an UninstallString survive. Split from the
// exec so captured reg.exe output can be parsed and tested on any OS.
// Header lines carry the full hive name (HKEY_LOCAL_MACHINE\...) even when
// the key was queried with its abbreviated form (HKLM\...), so both spellings
// are accepted; key paths are case-insensitive.
func parseWinUninstallQuery(root, queryOut string) []AppInfo {
	fullRoot := strings.ToLower(winFullKeyPath(root))
	abbrRoot := strings.ToLower(root)
	var apps []AppInfo
	var cur *AppInfo
	flush := func() {
		if cur != nil && cur.Name != "" && cur.UninstallString != "" {
			apps = append(apps, *cur)
		}
		cur = nil
	}
	for _, line := range strings.Split(queryOut, "\r\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		switch {
		case lower == "":
			flush() // blank line ends a registry block
		case winRegKeyRe.MatchString(lower):
			matched := strings.HasPrefix(lower, fullRoot) || strings.HasPrefix(lower, abbrRoot)
			flush()
			if matched {
				cur = &AppInfo{Path: trimmed, Kind: "winapp"}
			}
		case cur != nil:
			if m := winRegValueRe.FindStringSubmatch(line); m != nil {
				name, data := m[1], strings.TrimSpace(m[3])
				switch name {
				case "DisplayName":
					cur.Name = data
				case "DisplayVersion":
					cur.Version = data
				case "UninstallString":
					cur.UninstallString = data
				case "SystemComponent":
					if strings.EqualFold(data, "0x1") {
						cur.Name = "" // hidden system component — drop it
					}
				}
			}
		}
	}
	flush()
	return apps
}

// uninstallWindows runs the application's own registered uninstaller,
// detached — interactive uninstallers outlive the HTTP request — and
// journals the command. Leftover cleanup afterwards is the user's rescan.
func (s *server) uninstallWindows(w http.ResponseWriter, path string, confirm bool) {
	var log stepLogger
	log.addf("uninstall requested for %q (Windows registry entry)", path)
	var target *AppInfo
	for _, a := range listInstalledWindows() {
		if a.Path == path {
			target = &a
			break
		}
	}
	if target == nil {
		log.addf("FAILED: %q is not in the scanned install list", path)
		failWithLog(w, http.StatusBadRequest, "application is not in the scanned install list", log.steps)
		return
	}
	log.addf("resolved: %s (registry uninstaller: %s)", target.Name, target.UninstallString)
	if !confirm {
		writeJSON(w, http.StatusOK, map[string]any{
			"confirmRequired": true, "app": target, "log": log.steps,
			"note": "Runs this application's own uninstaller (interactive): " + target.UninstallString,
		})
		return
	}
	if strings.TrimSpace(target.UninstallString) == "" {
		log.addf("FAILED: no UninstallString registered for this application")
		failWithLog(w, http.StatusBadRequest, "no UninstallString registered for this application", log.steps)
		return
	}
	log.addf("launching the app's own uninstaller…")
	cmd := exec.Command("cmd", "/c", target.UninstallString)
	if err := cmd.Start(); err != nil {
		log.addf("FAILED: %v", err)
		failWithLog(w, http.StatusInternalServerError, err.Error(), log.steps)
		return
	}
	log.addf("uninstaller running (interactive window) — after it finishes, rescan this app's vendor folders for leftovers")
	go func() { _ = cmd.Wait() }()
	entry := JournalEntry{
		ID:       fmt.Sprintf("e%d", time.Now().UnixNano()),
		At:       time.Now().UTC().Format(time.RFC3339),
		Action:   "uninstall",
		Name:     target.Name,
		Commands: []string{target.UninstallString},
	}
	if entry.Files > 0 || len(entry.Commands) > 0 {
		s.saveJournal(entry)
		log.addf("journal saved (uninstaller command recorded)")
	}
	log.addf("done: uninstaller launched")
	summary := "uninstaller launched (interactive)"
	logPath := s.saveOpLog("uninstall", log.steps, summary)
	if logPath != "" {
		log.addf("log saved: %s", logPath)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "app": target.Name, "ran": target.UninstallString, "log": log.steps,
		"logPath": logPath,
		"note":    "Uninstaller launched — after it finishes, rescan this app's vendor folders for leftovers.",
	})
}

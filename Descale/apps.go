package main

/* Uninstall tab + Startup tab backend.
 *
 * Uninstall: list installed .app bundles (/Applications, ~/Applications),
 * hunt the files an app scatters under ~/Library keyed by its bundle id,
 * and remove the whole set by moving it to the Trash (journalled).
 *
 * Startup: enumerate LaunchAgents/Daemons plists; user agents can be
 * activated/deactivated (bootout + rename to *.plist.disabled), system
 * ones are listed read-only because touching them needs an administrator.
 */

import (
	"encoding/json"
	"encoding/xml"
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
	Kind            string `json:"kind,omitempty"`            // app | winapp
	UninstallString string `json:"uninstallString,omitempty"` // Windows: registered uninstaller
	Exe             string `json:"-"`
	Running         bool   `json:"running"`
}

type Leftover struct {
	Path      string `json:"path"`
	Kind      string `json:"kind"`
	SizeBytes int64  `json:"sizeBytes"`
}

func appRoots() []string {
	return []string{"/Applications", filepath.Join(homeDir(), "Applications")}
}

func listApps() []AppInfo {
	var bundles []string
	for _, root := range appRoots() {
		matches, _ := filepath.Glob(filepath.Join(root, "*.app"))
		bundles = append(bundles, matches...)
	}
	sort.Strings(bundles)
	out := make([]AppInfo, len(bundles))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i, b := range bundles {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, b string) {
			defer wg.Done()
			<-sem
			out[i] = appInfoFor(b)
		}(i, b)
	}
	wg.Wait()
	return out
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

// appLeftovers hunts the files an app scatters outside its bundle, keyed by
// bundle id (and, secondarily, the display name). Only exact-name matches
// are proposed — no fuzzy "looks related" guessing.
func appLeftovers(app AppInfo) []Leftover {
	home := homeDir()
	id, name := app.ID, app.Name
	type cand struct {
		p, kind string
	}
	cands := []cand{
		{filepath.Join(home, "Library", "Caches", id), "caches"},
		{filepath.Join(home, "Library", "Caches", name), "caches"},
		{filepath.Join(home, "Library", "Application Support", id), "data"},
		{filepath.Join(home, "Library", "Application Support", name), "data"},
		{filepath.Join(home, "Library", "Preferences", id+".plist"), "preferences"},
		{filepath.Join(home, "Library", "Saved Application State", id+".savedState"), "state"},
		{filepath.Join(home, "Library", "Containers", id), "container"},
		{filepath.Join(home, "Library", "HTTPStorages", id), "storage"},
		{filepath.Join(home, "Library", "WebKit", id), "storage"},
		{filepath.Join(home, "Library", "Logs", id), "logs"},
		{filepath.Join(home, "Library", "Logs", name), "logs"},
		{filepath.Join(home, "Library", "Application Scripts", id), "scripts"},
	}
	seen := map[string]bool{}
	var out []Leftover
	add := func(p, kind string) {
		if p == "" || seen[p] || p == home {
			return
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return
		}
		seen[p] = true
		out = append(out, Leftover{Path: p, Kind: kind, SizeBytes: dirSize(p, fi)})
	}
	for _, c := range cands {
		add(c.p, c.kind)
	}
	if id != "" {
		agents, _ := filepath.Glob(filepath.Join(home, "Library", "LaunchAgents", "*.plist"))
		for _, a := range agents {
			if d, err := readPlist(a); err == nil {
				blob := fmt.Sprint(d["Label"], "|", d["Program"], "|", d["ProgramArguments"])
				if strings.Contains(blob, id) {
					add(a, "launch agent")
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SizeBytes > out[j].SizeBytes })
	return out
}

type appsListResult struct {
	Apps []AppInfo `json:"apps"`
	Note string    `json:"note,omitempty"`
}

// appsList is the shared source for /api/apps and `descale apps`.
func (s *server) appsList() appsListResult {
	if runtime.GOOS == "windows" {
		return appsListResult{
			Apps: listInstalledWindows(),
			Note: "Uninstall runs each application's own uninstaller (interactive). After it finishes, rescan for leftovers.",
		}
	}
	return appsListResult{Apps: listApps()}
}

func (s *server) handleApps(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.appsList())
}

func (s *server) findApp(path string) *AppInfo {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	apps := listApps()
	for i := range apps {
		if apps[i].Path == path {
			return &apps[i]
		}
	}
	return nil
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
	bundleSize := int64(0)
	if fi, err := os.Lstat(app.Path); err == nil {
		bundleSize = dirSize(app.Path, fi)
	}
	left := appLeftovers(*app)
	var total int64
	for _, l := range left {
		total += l.SizeBytes
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"app": app, "leftovers": left, "bundleBytes": bundleSize,
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
		s.uninstallWindows(w, req.Path, req.Confirm)
		return
	}
	app := s.findApp(req.Path)
	if app == nil {
		fail(w, http.StatusBadRequest, "application is not in the scanned install list")
		return
	}
	if app.Running {
		fail(w, http.StatusConflict, app.Name+" is running — quit it first")
		return
	}
	bundleSize := int64(0)
	if fi, err := os.Lstat(app.Path); err == nil {
		bundleSize = dirSize(app.Path, fi)
	}
	left := appLeftovers(*app)

	if !req.Confirm {
		var total int64
		for _, l := range left {
			total += l.SizeBytes
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"confirmRequired": true, "app": app, "leftovers": left,
			"bundleBytes": bundleSize, "leftoverBytes": total,
			"totalBytes": total + bundleSize,
		})
		return
	}

	trashDir := trashDirPath()
	_ = os.MkdirAll(trashDir, 0o755)
	entry := JournalEntry{
		ID:     fmt.Sprintf("e%d", time.Now().UnixNano()),
		At:     time.Now().UTC().Format(time.RFC3339),
		Action: "uninstall",
		Name:   app.Name,
	}
	var failures []map[string]string
	move := func(p string, size int64) {
		dst, err := trashTo(trashDir, p)
		if err != nil {
			failures = append(failures, map[string]string{"rule": "uninstall", "path": p, "error": err.Error()})
			return
		}
		entry.Items = append(entry.Items, JournalItem{Path: p, Trash: filepath.Base(dst)})
		entry.Bytes += size
		entry.Files++
	}
	for _, l := range left {
		move(l.Path, l.SizeBytes)
	}
	move(app.Path, bundleSize)
	if entry.Files > 0 || len(entry.Commands) > 0 {
		s.saveJournal(entry)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "app": app.Name, "bytes": entry.Bytes, "files": entry.Files, "failed": failures,
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
	var target *AppInfo
	for _, a := range listInstalledWindows() {
		if a.Path == path {
			target = &a
			break
		}
	}
	if target == nil {
		fail(w, http.StatusBadRequest, "application is not in the scanned install list")
		return
	}
	if !confirm {
		writeJSON(w, http.StatusOK, map[string]any{
			"confirmRequired": true, "app": target,
			"note": "Runs this application's own uninstaller (interactive): " + target.UninstallString,
		})
		return
	}
	if strings.TrimSpace(target.UninstallString) == "" {
		fail(w, http.StatusBadRequest, "no UninstallString registered for this application")
		return
	}
	cmd := exec.Command("cmd", "/c", target.UninstallString)
	if err := cmd.Start(); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
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
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "app": target.Name, "ran": target.UninstallString,
		"note": "Uninstaller launched — after it finishes, rescan this app's vendor folders for leftovers.",
	})
}

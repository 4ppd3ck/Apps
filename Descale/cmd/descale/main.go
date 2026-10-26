// Command descale is a stdlib-only local server for the Descale desktop
// utility: an OS/arch-aware buildup (junk) analyzer with Trash-based
// cleaning, driven by a rules database (rules/descale-rules.json) that can
// be edited without rebuilding. It serves the static GUI plus a small JSON
// API.
//
// The server binds to 127.0.0.1 only. Unlike a plain content server this
// process can move files to the Trash, so it must never be reachable from
// the network.
//
// Safety model (see README):
//   - the API never accepts paths from the client — only rule IDs; every
//     path is derived fresh from the rules DB and re-validated;
//   - cleaning moves files to ~/.Trash (recoverable), never deletes in
//     place, except rules whose action is explicitly "delete";
//   - every clean session is journalled and restorable via /api/restore.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultPort = 8212
	appVersion  = "0.5.1"
)

/* ---------- rules database ---------- */

type Var struct {
	Name     string            `json:"name"`
	Exec     string            `json:"exec,omitempty"`
	Env      string            `json:"env,omitempty"`
	Fallback map[string]string `json:"fallback,omitempty"`
}

type Require struct {
	Binary string   `json:"binary,omitempty"`
	Dirs   []string `json:"dirs,omitempty"`
}

type Rule struct {
	ID            string   `json:"id"`
	Title         string   `json:"title"`
	Description   string   `json:"description"`
	Category      string   `json:"category"`
	OS            []string `json:"os"`
	Arch          []string `json:"arch"`
	Safety        string   `json:"safety"`
	Paths         []string `json:"paths"`
	Exclude       []string `json:"exclude"`
	Requires      *Require `json:"requires,omitempty"`
	RunningApps   []string `json:"runningApps,omitempty"`
	MinAgeDays    int      `json:"minAgeDays,omitempty"`
	RequiresAdmin bool     `json:"requiresAdmin,omitempty"`
	Permanent     bool     `json:"permanent,omitempty"` // command rules that are irreversible (e.g. Recycle Bin)
	Action        string   `json:"action,omitempty"`
	Command       string   `json:"command,omitempty"`
	Enabled       *bool    `json:"enabled,omitempty"`
}

type RulesDB struct {
	Version int    `json:"version"`
	Vars    []Var  `json:"vars"`
	Rules   []Rule `json:"rules"`
}

func (r *Rule) enabled() bool { return r.Enabled == nil || *r.Enabled }

/* ---------- scan / report types ---------- */

type Sample struct {
	Name      string `json:"name"`
	SizeBytes int64  `json:"sizeBytes"`
}

type RuleResult struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Category    string   `json:"category"`
	Safety      string   `json:"safety"`
	Action      string   `json:"action"`
	Permanent   bool     `json:"permanent,omitempty"`
	Status      string   `json:"status"` // ok | skipped | unavailable | disabled | command
	Reason      string   `json:"reason,omitempty"`
	SizeBytes   int64    `json:"sizeBytes"`
	FileCount   int      `json:"fileCount"`
	DurationMs  int64    `json:"durationMs"`
	Samples     []Sample `json:"samples,omitempty"`
}

type Report struct {
	GeneratedAt string       `json:"generatedAt"`
	Version     string       `json:"version"`
	OS          string       `json:"os"`
	Arch        string       `json:"arch"`
	ArchLabel   string       `json:"archLabel"`
	OSVersion   string       `json:"osVersion"`
	Home        string       `json:"home"`
	Rules       []RuleResult `json:"rules"`
	RulesSigned bool         `json:"rulesSigned"`
	TotalBytes  int64        `json:"totalBytes"`
	TotalFiles  int          `json:"totalFiles"`
	SafeBytes   int64        `json:"safeBytes"`
	ReviewBytes int64        `json:"reviewBytes"`
	DurationMs  int64        `json:"durationMs"`
}

type JournalItem struct {
	Path  string `json:"path"`
	Trash string `json:"trash"`
}

type JournalEntry struct {
	ID       string        `json:"id"`
	At       string        `json:"at"`
	Action   string        `json:"action"`
	Name     string        `json:"name,omitempty"` // app / item name for uninstall & startup entries
	Rules    []string      `json:"rules"`
	Bytes    int64         `json:"bytes"`
	Files    int           `json:"files"`
	Items    []JournalItem `json:"items,omitempty"`
	Commands []string      `json:"commands,omitempty"`
	Restored bool          `json:"restored"`
}

/* ---------- server ---------- */

type server struct {
	root        string // app dir: index.html, css/, js/, rules/
	journalMu   sync.Mutex
	osVersion   string
	osVersionMu sync.Mutex

	// background scan job (the UI polls /api/scan/poll for progress)
	scanMu      sync.Mutex
	scanRunning bool
	scanDone    int
	scanTotal   int
	scanSigned  bool
	scanResults []RuleResult
	scanEnded   time.Time
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "descale: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "serve":
			return serve(args[1:])
		case "scan", "clean", "apps", "startup", "nudge", "rules", "version", "help":
			return cliRun(args)
		}
		if _, err := strconv.Atoi(strings.TrimSpace(args[0])); err == nil {
			return serve(args) // AppDeck passes a bare port number
		}
		cliUsage()
		return fmt.Errorf("unknown command: %s", args[0])
	}
	return serve(nil)
}

func serve(args []string) error {
	port, err := resolvePort(args)
	if err != nil {
		return err
	}
	root := resolveRoot()
	if !hasIndexHTML(root) {
		fmt.Fprintf(os.Stderr, "warning: no index.html in %q; set DESCALE_ROOT to the app directory\n", root)
	}
	seedMimeTypes()

	srv := &server{root: root}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/info", srv.handleInfo)
	mux.HandleFunc("POST /api/scan", srv.handleScan)
	mux.HandleFunc("GET /api/scan/poll", srv.handleScanPoll)
	mux.HandleFunc("POST /api/clean", srv.handleClean)
	mux.HandleFunc("GET /api/journal", srv.handleJournal)
	mux.HandleFunc("POST /api/restore", srv.handleRestore)
	mux.HandleFunc("GET /api/apps", srv.handleApps)
	mux.HandleFunc("GET /api/app/icon", srv.handleAppIcon)
	mux.HandleFunc("POST /api/app/leftovers", srv.handleAppLeftovers)
	mux.HandleFunc("POST /api/app/leftovers/delete", srv.handleAppLeftoversDelete)
	mux.HandleFunc("POST /api/app/uninstall", srv.handleAppUninstall)
	mux.HandleFunc("POST /api/apps/uninstall", srv.handleAppsUninstallBatch)
	mux.HandleFunc("GET /api/startup", srv.handleStartup)
	mux.HandleFunc("POST /api/startup/toggle", srv.handleStartupToggle)
	mux.HandleFunc("GET /api/traces", srv.handleTraces)
	mux.HandleFunc("POST /api/traces/delete", srv.handleTracesDelete)
	mux.HandleFunc("POST /api/reveal", srv.handleReveal)
	mux.HandleFunc("GET /api/traces/exclusions", srv.handleTracesExclusionsGet)
	mux.HandleFunc("POST /api/traces/exclusions/add", srv.handleTracesExclusionsAdd)
	mux.HandleFunc("POST /api/traces/exclusions/remove", srv.handleTracesExclusionsRemove)
	mux.HandleFunc("GET /api/guardrails", srv.handleGuardrailsGet)
	mux.HandleFunc("POST /api/guardrails", srv.handleGuardrailsSet)
	mux.HandleFunc("POST /api/onboarded", srv.handleOnboarded)
	mux.HandleFunc("GET /api/nudge", srv.handleNudgeStatus)
	mux.HandleFunc("POST /api/nudge", srv.handleNudgeToggle)
	mux.Handle("/", logging(noCache(http.FileServer(http.Dir(root)))))

	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("cannot bind %s: %w", addr, err)
	}
	fmt.Printf("💧 Descale v%s at http://127.0.0.1:%d  (read-only until you confirm a clean)\n", appVersion, port)
	httpSrv := &http.Server{Handler: hostGuard("127.0.0.1", mux)}
	return httpSrv.Serve(ln)
}

/* ---------- http plumbing (mirrors the Itihasas server) ---------- */

func resolvePort(args []string) (int, error) {
	if len(args) > 0 {
		return parsePort(args[0])
	}
	if env, ok := os.LookupEnv("PORT"); ok && env != "" {
		return parsePort(env)
	}
	return defaultPort, nil
}

func parsePort(s string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("invalid port %q: must be an integer like 8212", s)
	}
	return port, nil
}

func resolveRoot() string {
	if r := strings.TrimSpace(os.Getenv("DESCALE_ROOT")); r != "" {
		return absPath(r)
	}
	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		exeDir := filepath.Dir(exe)
		if hasIndexHTML(exeDir) {
			return absPath(exeDir)
		}
	}
	if cwd, err := os.Getwd(); err == nil {
		return absPath(cwd)
	}
	return "."
}

func hasIndexHTML(dir string) bool {
	fi, err := os.Stat(filepath.Join(dir, "index.html"))
	return err == nil && !fi.IsDir()
}

func absPath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}

func seedMimeTypes() {
	for ext, typ := range map[string]string{
		".css":  "text/css; charset=utf-8",
		".html": "text/html; charset=utf-8",
		".js":   "text/javascript; charset=utf-8",
		".json": "application/json; charset=utf-8",
		".png":  "image/png",
		".svg":  "image/svg+xml",
		".md":   "text/markdown; charset=utf-8",
	} {
		_ = mime.AddExtensionType(ext, typ)
	}
}

func noCache(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		next.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  int64
}

func (w *statusWriter) WriteHeader(code int) {
	w.Header().Set("Cache-Control", "no-cache")
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.wrote += int64(n)
	return n, err
}

func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		if strings.HasPrefix(r.URL.Path, "/api/") {
			fmt.Printf("%s %s -> %d (%d bytes)\n", r.Method, r.URL.Path, sw.status, sw.wrote)
		}
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

/* ---------- environment ---------- */

// homeDir returns the effective home directory. DESCALE_HOME overrides it,
// which is how the fixture tests run the whole engine against a synthetic
// tree instead of the operator's real home.
func homeDir() string {
	if h := strings.TrimSpace(os.Getenv("DESCALE_HOME")); h != "" {
		return absPath(h)
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return h
}

func (s *server) osVersionString() string {
	s.osVersionMu.Lock()
	defer s.osVersionMu.Unlock()
	if s.osVersion != "" {
		return s.osVersion
	}
	switch runtime.GOOS {
	case "darwin":
		if out, err := exec.Command("sw_vers", "-productVersion").Output(); err == nil {
			s.osVersion = strings.TrimSpace(string(out))
		}
	case "windows":
		s.osVersion = ""
	}
	return s.osVersion
}

func resolveVars(db *RulesDB) map[string]string {
	vars := map[string]string{}
	for _, v := range db.Vars {
		if v.Env != "" {
			if val := strings.TrimSpace(os.Getenv(v.Env)); val != "" {
				vars[v.Name] = val
				continue
			}
		}
		if v.Exec != "" {
			var cmd *exec.Cmd
			if runtime.GOOS == "windows" {
				cmd = exec.Command("cmd", "/c", v.Exec)
			} else {
				cmd = exec.Command("sh", "-c", v.Exec)
			}
			cmd.Env = append(os.Environ(), "LC_ALL=C")
			if out, err := cmd.Output(); err == nil {
				if val := strings.TrimSpace(string(out)); val != "" && !strings.Contains(val, "\n") {
					vars[v.Name] = val
					continue
				}
			}
		}
		if val, ok := v.Fallback[runtime.GOOS+"/"+runtime.GOARCH]; ok {
			vars[v.Name] = val
		} else if val, ok := v.Fallback["*"]; ok {
			vars[v.Name] = val
		}
	}
	return vars
}

func expand(p string, vars map[string]string, home string) string {
	for k, v := range vars {
		p = strings.ReplaceAll(p, "{"+k+"}", v)
	}
	switch {
	case p == "~":
		return home
	case strings.HasPrefix(p, "~/"):
		return filepath.Join(home, p[2:])
	}
	return absPath(p)
}

func ruleApplies(r *Rule) bool {
	return listHas(r.OS, runtime.GOOS) && listHas(r.Arch, runtime.GOARCH)
}

func listHas(list []string, v string) bool {
	return len(list) == 0 || contains(list, v)
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

var (
	adminMu     sync.Mutex
	adminCached *bool
)

// isAdmin answers "is this process elevated?" — on Windows via `net session`
// (succeeds only for administrators), elsewhere via euid. Cached per run.
func isAdmin() bool {
	adminMu.Lock()
	defer adminMu.Unlock()
	if adminCached != nil {
		return *adminCached
	}
	elevated := false
	switch runtime.GOOS {
	case "windows":
		elevated = exec.Command("net", "session").Run() == nil
	default:
		elevated = os.Geteuid() == 0
	}
	adminCached = &elevated
	return elevated
}

// binaryKnownAt checks the well-known install locations in addition to
// $PATH: GUI-launched processes (AppDeck) get a minimal PATH that misses
// /opt/homebrew/bin, which would mark installed tools as unavailable.
func binaryKnownAt(name string) bool {
	if runtime.GOOS == "windows" {
		return false // PATH-only on Windows
	}
	for _, dir := range []string{
		"/opt/homebrew/bin", "/opt/homebrew/sbin",
		"/usr/local/bin", "/usr/local/sbin",
		"/usr/bin", "/bin", "/snap/bin",
	} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			return true
		}
	}
	return false
}

// trashDirPath is where cleaned files become recoverable. macOS and Linux
// have a per-user Trash; Windows' Recycle Bin needs a shell API, so Descale
// keeps its own restorable trash folder instead.
func trashDirPath() string {
	home := homeDir()
	if runtime.GOOS == "windows" {
		return filepath.Join(home, ".descale", "trash")
	}
	return filepath.Join(home, ".Trash")
}

// runningApps detects named processes (macOS/Linux via pgrep). On Windows
// detection is not implemented in v0.1 and simply reports nothing running.
func runningApps(names []string) []string {
	if runtime.GOOS == "windows" {
		return nil
	}
	var running []string
	for _, name := range names {
		if err := exec.Command("pgrep", "-x", name).Run(); err == nil {
			running = append(running, name)
		}
	}
	return running
}

/* ---------- scanning ---------- */

// rulesPubKey is the ed25519 public key that signs the rules database.
// Empty string = unsigned local mode (any local edits are accepted).
// Generate a keypair with `descale rules genkeys`; anyone holding the
// private key can sign rule updates, so keep it off shared machines.
const rulesPubKey = "dc7f0e9cbea1a4d061a2868d5c955c6becc18a6e66dfc17b5dd5251ef41ab376"

func (s *server) loadRules() (*RulesDB, bool, error) {
	path := filepath.Join(s.root, "rules", "descale-rules.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}
	signed := false
	if sig, err := os.ReadFile(path + ".sig"); err == nil {
		if rulesPubKey == "" {
			return nil, false, errors.New("rules file carries a signature but no public key is embedded in this build")
		}
		if err := verifyRulesSignature(raw, sig); err != nil {
			return nil, false, fmt.Errorf("rules signature INVALID: %w", err)
		}
		signed = true
	}
	var db RulesDB
	if err := json.Unmarshal(raw, &db); err != nil {
		return nil, signed, fmt.Errorf("rules file: %w", err)
	}
	return &db, signed, nil
}

type collected struct {
	roots   []string
	files   []string
	bytes   int64
	count   int
	samples map[string]int64
	notes   []string
	// blocked counts paths the scanner could not read at all (macOS TCC,
	// unix permissions, Windows ACLs). A rule with blocked > 0 and no
	// readable files must never report a clean "0 B · 0 files" — that
	// zero is "couldn't look", not "nothing there".
	blocked int
}

// unreadableNote renders a directory the scanner could not read, with the
// OS-specific way to fix it. Consistent across darwin/linux/windows.
func unreadableNote(dir string) string {
	switch runtime.GOOS {
	case "darwin":
		return filepath.Base(dir) + ": unreadable (macOS privacy protection — grant the app launching Descale Full Disk Access in System Settings › Privacy & Security)"
	case "windows":
		return filepath.Base(dir) + ": unreadable (check folder permissions / run Descale elevated)"
	default:
		return filepath.Base(dir) + ": unreadable (check ownership and permissions)"
	}
}

// accessHint is the short remediation shown for a fully blocked rule.
func accessHint() string {
	switch runtime.GOOS {
	case "darwin":
		return "grant the app that launches Descale Full Disk Access (System Settings › Privacy & Security)"
	case "windows":
		return "check folder permissions or run Descale elevated"
	default:
		return "check ownership and permissions of the listed folders"
	}
}

// dirReadable reports whether dir can actually be listed. A plain Lstat is
// not enough: macOS TCC allows stat on ~/.Trash but fails open/readdir with
// EPERM, so the probe must attempt a real directory read. Works uniformly
// across unix and windows (ACL failures surface as error from Open).
func dirReadable(dir string) bool {
	f, err := os.Open(dir)
	if err != nil {
		return false
	}
	_, err = f.Readdirnames(1)
	f.Close()
	return err == nil || errors.Is(err, io.EOF)
}

// checkBlockedPatterns guards the "zero matches" case: Go's filepath.Glob
// swallows read errors, so a privacy-protected directory looks exactly like
// an empty one. When a pattern with a wildcard produced nothing, stat the
// literal prefix and probe it; existing-but-unreadable is recorded as
// blocked. Patterns without a wildcard are skipped: Glob returning nothing
// there genuinely means "no such path".
func checkBlockedPatterns(c *collected, rawPattern, pat string, matchCount int) {
	if matchCount > 0 || !strings.ContainsAny(pat, "*?[") {
		return
	}
	prefix := pat
	if i := strings.LastIndexAny(pat, `/\`); i >= 0 {
		prefix = pat[:i+1]
	} else {
		prefix = ""
	}
	if prefix == "" || strings.ContainsAny(prefix, "*?[") {
		return
	}
	prefix = strings.TrimSuffix(prefix, string(os.PathSeparator))
	if fi, err := os.Lstat(prefix); err != nil || !fi.IsDir() {
		return
	}
	if !dirReadable(prefix) {
		c.blocked++
		c.notes = append(c.notes, unreadableNote(prefix))
	}
}

// excluded reports whether path is covered by an exclude entry. Two
// semantics, chosen by the entry's own shape://   - an entry ending in "." (e.g. ".../Caches/com.apple.") is a raw string
//
//	  prefix — it covers every bundle-id that starts with it, and children;
//	- any other entry matches exactly or as a containing directory.
//
// Broad globs are not supported in excludes, on purpose: wide globs are how
// cleaning tools eat user data.
func excluded(path string, ex []string) bool {
	sep := string(os.PathSeparator)
	for _, e := range ex {
		if path == e {
			return true
		}
		if strings.HasSuffix(e, ".") {
			if strings.HasPrefix(path, e) {
				return true
			}
			continue
		}
		if strings.HasPrefix(path, e+sep) {
			return true
		}
	}
	return false
}

// collect walks every rule path (after var/~ expansion and globbing) and
// returns the matching files, sizes and per-root top-level samples. It is
// the single source of truth for both /api/scan (sizes) and /api/clean
// (file list), so what the report showed is exactly what cleaning touches.
func collect(r *Rule, vars map[string]string, home string) (*collected, error) {
	c := &collected{samples: map[string]int64{}}
	var cutoff time.Time
	if r.MinAgeDays > 0 {
		cutoff = time.Now().AddDate(0, 0, -r.MinAgeDays)
	}
	ex := make([]string, 0, len(r.Exclude))
	for _, e := range r.Exclude {
		ex = append(ex, expand(e, vars, home))
	}

	for _, pattern := range r.Paths {
		pat := expand(pattern, vars, home)
		if strings.Contains(pat, "{") {
			// A {var} could not be resolved on this machine — skip the
			// pattern rather than guessing at a literal "{...}" path.
			c.notes = append(c.notes, "unresolved variable in "+pattern)
			continue
		}
		matches, err := filepath.Glob(pat)
		if err != nil {
			c.notes = append(c.notes, "bad pattern "+pattern)
			continue
		}
		checkBlockedPatterns(c, pattern, pat, len(matches))
		sort.Strings(matches)
		for _, match := range matches {
			if excluded(match, ex) {
				continue
			}
			if reason := criticalReason(match); reason != "" {
				c.notes = append(c.notes, "skipped "+reason)
				continue
			}
			fi, err := os.Lstat(match)
			if err != nil {
				continue
			}
			if !fi.IsDir() {
				// A pattern that names a file directly (e.g. Downloads/*.pkg).
				if !cutoff.IsZero() && fi.ModTime().After(cutoff) {
					continue
				}
				c.roots = append(c.roots, match)
				c.files = append(c.files, match)
				c.bytes += fi.Size()
				c.count++
				c.samples[filepath.Base(match)] += fi.Size()
				continue
			}
			// Refuse to treat the home directory itself (or anything above
			// it) as a cleanable root — a typo'd rule must fail safe.
			if match == home || match == string(os.PathSeparator) {
				c.notes = append(c.notes, "skipped unsafe root "+pattern)
				continue
			}
			c.roots = append(c.roots, match)
			_ = filepath.WalkDir(match, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					c.notes = append(c.notes, filepath.Base(path)+": unreadable")
					if path == match {
						// The root itself is unreadable (TCC/ACL) — count it
						// so the rule reports blocked, not a fake zero.
						c.blocked++
					}
					if d != nil && d.IsDir() {
						return fs.SkipDir
					}
					return nil
				}
				if excluded(path, ex) {
					if d.IsDir() {
						return fs.SkipDir
					}
					return nil
				}
				if d.IsDir() {
					return nil
				}
				info, err := d.Info()
				if err != nil {
					return nil
				}
				if !cutoff.IsZero() && info.ModTime().After(cutoff) {
					return nil
				}
				c.files = append(c.files, path)
				c.bytes += info.Size()
				c.count++
				if rel, err := filepath.Rel(match, path); err == nil {
					first := rel
					if i := strings.Index(rel, string(os.PathSeparator)); i > 0 {
						first = rel[:i]
					}
					c.samples[first] += info.Size()
				}
				return nil
			})
		}
	}
	return c, nil
}

func topSamples(m map[string]int64, n int) []Sample {
	type kv struct {
		k string
		v int64
	}
	list := make([]kv, 0, len(m))
	for k, v := range m {
		list = append(list, kv{k, v})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].v > list[j].v })
	out := make([]Sample, 0, n)
	for i, e := range list {
		if i == n {
			break
		}
		out = append(out, Sample{Name: e.k, SizeBytes: e.v})
	}
	return out
}

// scanRule evaluates one rule against this machine. It is used by both the
// scan report and the clean plan, so the UI always shows what cleaning
// would touch right now — never a stale number.
func scanRule(r *Rule, vars map[string]string, home string) RuleResult {
	res := RuleResult{
		ID: r.ID, Title: r.Title, Description: r.Description,
		Category: r.Category, Safety: r.Safety,
		Action: r.Action, Permanent: r.Permanent,
	}
	if res.Action == "" {
		res.Action = "trash"
	}
	start := time.Now()
	defer func() { res.DurationMs = time.Since(start).Milliseconds() }()

	if !r.enabled() {
		res.Status = "disabled"
		res.Reason = "disabled in rules file"
		return res
	}
	if !ruleApplies(r) {
		res.Status = "unavailable"
		res.Reason = "rule targets a different OS/arch"
		return res
	}
	if r.RequiresAdmin && !isAdmin() {
		res.Status = "unavailable"
		res.Reason = "requires an administrator (run Descale elevated)"
		return res
	}
	if r.Requires != nil {
		if r.Requires.Binary != "" {
			if _, err := exec.LookPath(r.Requires.Binary); err != nil && !binaryKnownAt(r.Requires.Binary) {
				res.Status = "unavailable"
				res.Reason = r.Requires.Binary + " not installed"
				return res
			}
		}
		for _, d := range r.Requires.Dirs {
			if _, err := os.Stat(expand(d, vars, home)); err != nil {
				res.Status = "unavailable"
				res.Reason = filepath.Base(expand(d, vars, home)) + " not present"
				return res
			}
		}
	}
	if len(r.RunningApps) > 0 {
		if running := runningApps(r.RunningApps); len(running) > 0 {
			res.Status = "skipped"
			res.Reason = "app running: " + strings.Join(running, ", ")
			return res
		}
	}
	if r.Action == "command" {
		res.Status = "command"
		res.Reason = "runs: " + r.Command
		return res
	}

	c, err := collect(r, vars, home)
	if err != nil {
		res.Status = "unavailable"
		res.Reason = err.Error()
		return res
	}
	if c.blocked > 0 && c.count == 0 {
		// Everything the rule points at exists but is unreadable. Reporting
		// "ok, 0 B · 0 files" here would pass an invisible-but-full Trash
		// off as empty — for a permanent-delete rule that is dangerous.
		// The notes already carry the OS-specific fix hint.
		res.Status = "blocked"
		res.SizeBytes = 0
		res.FileCount = 0
		res.Reason = strings.Join(dedupe(c.notes), "; ")
		return res
	}
	res.Status = "ok"
	res.SizeBytes = c.bytes
	res.FileCount = c.count
	res.Samples = topSamples(c.samples, 4)
	if len(c.notes) > 0 {
		res.Reason = strings.Join(dedupe(c.notes), "; ")
	}
	return res
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func (s *server) handleScan(w http.ResponseWriter, r *http.Request) {
	s.scanMu.Lock()
	if s.scanRunning {
		total := s.scanTotal
		s.scanMu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"started": true, "alreadyRunning": true, "total": total})
		return
	}
	db, signed, err := s.loadRules()
	if err != nil {
		s.scanMu.Unlock()
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	home := homeDir()
	vars := resolveVars(db)
	s.scanRunning = true
	s.scanDone = 0
	s.scanSigned = signed
	s.scanTotal = len(db.Rules)
	s.scanResults = make([]RuleResult, len(db.Rules))
	s.scanEnded = time.Time{}
	total := s.scanTotal
	s.scanMu.Unlock()

	go func() {
		var wg sync.WaitGroup
		sem := make(chan struct{}, 6)
		for i := range db.Rules {
			wg.Add(1)
			sem <- struct{}{}
			go func(i int) {
				defer wg.Done()
				<-sem
				res := scanRule(&db.Rules[i], vars, home)
				s.scanMu.Lock()
				s.scanResults[i] = res
				s.scanDone++
				s.scanMu.Unlock()
			}(i)
		}
		wg.Wait()
		s.scanMu.Lock()
		s.scanRunning = false
		s.scanEnded = time.Now()
		s.scanMu.Unlock()
	}()
	writeJSON(w, http.StatusOK, map[string]any{"started": true, "total": total})
}

// handleScanPoll reports job progress; once the job is finished it returns
// the fully assembled report (exactly the shape the old synchronous
// endpoint produced, so the UI renders the same way).
func (s *server) handleScanPoll(w http.ResponseWriter, r *http.Request) {
	s.scanMu.Lock()
	defer s.scanMu.Unlock()
	if s.scanRunning {
		completed := make([]RuleResult, 0, s.scanDone)
		for _, res := range s.scanResults {
			if res.ID != "" {
				completed = append(completed, res)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"running": true, "done": s.scanDone, "total": s.scanTotal, "completed": completed,
		})
		return
	}
	if s.scanResults == nil || s.scanEnded.IsZero() {
		writeJSON(w, http.StatusOK, map[string]any{"running": false})
		return
	}
	rep := s.buildReport(s.scanResults, s.scanEnded, time.Since(s.scanEnded).Milliseconds()+1)
	rep.RulesSigned = s.scanSigned
	writeJSON(w, http.StatusOK, map[string]any{"running": false, "report": rep})
}

// buildReport assembles the wire report from per-rule results; shared by
// the poll endpoint and the CLI.
func (s *server) buildReport(results []RuleResult, at time.Time, durationMs int64) Report {
	rep := Report{
		GeneratedAt: at.UTC().Format(time.RFC3339),
		Version:     appVersion,
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
		ArchLabel:   archLabel(),
		OSVersion:   s.osVersionString(),
		Home:        homeDir(),
		Rules:       results,
		DurationMs:  durationMs,
	}
	for _, res := range results {
		if res.Status != "ok" {
			continue
		}
		rep.TotalBytes += res.SizeBytes
		rep.TotalFiles += res.FileCount
		if res.Safety == "safe" {
			rep.SafeBytes += res.SizeBytes
		} else {
			rep.ReviewBytes += res.SizeBytes
		}
	}
	return rep
}

func archLabel() string {
	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" {
		return "Apple Silicon"
	}
	return runtime.GOARCH
}

/* ---------- cleaning ---------- */

type cleanRequest struct {
	Rules   []string `json:"rules"`
	Confirm bool     `json:"confirm"`
}

func (s *server) handleClean(w http.ResponseWriter, r *http.Request) {
	var req cleanRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, "bad request body")
		return
	}
	result, err := s.cleanRules(req.Rules, req.Confirm)
	if err != nil {
		if ae, ok := err.(*appError); ok {
			fail(w, ae.code, ae.msg)
			return
		}
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// appError carries an HTTP status through the shared engine so both the
// dashboard and the CLI get the same refusals with the same messages.
type appError struct {
	code int
	msg  string
}

func (e *appError) Error() string { return e.msg }

// cleanRules is the single engine behind /api/clean and `descale clean`:
// rule IDs in, verified plan or journalled execution out. Paths never come
// from the caller.
func (s *server) cleanRules(ids []string, confirm bool) (map[string]any, error) {
	var log stepLogger
	log.addf("clean requested: %d rule(s) [%s]", len(ids), strings.Join(ids, ", "))
	if len(ids) == 0 {
		return nil, &appError{http.StatusBadRequest, "no rules selected"}
	}
	db, _, err := s.loadRules()
	if err != nil {
		return nil, err
	}
	home := homeDir()
	vars := resolveVars(db)
	byID := map[string]*Rule{}
	for i := range db.Rules {
		byID[db.Rules[i].ID] = &db.Rules[i]
	}
	var selected []*Rule
	for _, id := range ids {
		rule := byID[id]
		if rule == nil {
			return nil, &appError{http.StatusBadRequest, "unknown rule: " + id}
		}
		if !rule.enabled() {
			return nil, &appError{http.StatusBadRequest, "rule is disabled: " + id}
		}
		selected = append(selected, rule)
	}
	// A permanent rule (action "delete", or a command rule explicitly marked
	// permanent like Empty-the-Recycle-Bin) is irreversible — it must never
	// share a session with trash-action rules, or it would destroy the very
	// files this session just made restorable.
	if len(selected) > 1 {
		for _, rule := range selected {
			if rule.Action == "delete" || rule.Permanent {
				return nil, &appError{http.StatusBadRequest,
					"\"" + rule.Title + "\" is permanent and must be run alone, not bundled with other rules"}
			}
		}
	}

	if !confirm {
		// Plan-only: exactly what the confirm step shows the user.
		plan := make([]RuleResult, 0, len(selected))
		var total int64
		var files int
		for _, rule := range selected {
			res := scanRule(rule, vars, home)
			if res.Status == "blocked" {
				return nil, &appError{http.StatusForbidden,
					"\"" + rule.Title + "\" could not be scanned: " + res.Reason + ". Fix access, rescan, then retry — never clean blind."}
			}
			plan = append(plan, res)
			total += res.SizeBytes
			files += res.FileCount
		}
		return map[string]any{
			"confirmRequired": true, "plan": plan, "totalBytes": total, "files": files,
		}, nil
	}

	trashDir := trashDirPath()
	_ = os.MkdirAll(trashDir, 0o755)
	entry := JournalEntry{
		ID:     fmt.Sprintf("e%d", time.Now().UnixNano()),
		At:     time.Now().UTC().Format(time.RFC3339),
		Action: "clean",
	}
	var failures []map[string]string
	husksRemoved := 0

	for _, rule := range selected {
		log.addf("rule %q (%s, action %s): starting", rule.Title, rule.ID, rule.Action)
		ruleFailures := 0
		switch rule.Action {
		case "command":
			log.addf("running command: %s", rule.Command)
			out, err := runCommand(rule.Command)
			line := rule.Command
			if err != nil {
				log.addf("FAILED command: %v — output: %s", err, truncateStr(out, 200))
				line += " (failed: " + err.Error() + ")"
				ruleFailures++
			} else {
				log.addf("ok — output: %s", truncateStr(out, 200))
			}
			entry.Commands = append(entry.Commands, line+": "+out)
		default:
			// Enforce the running-app guard here too, not just in the
			// report: a rule the UI shows as skipped must never be
			// cleanable, even via a direct API call.
			if len(rule.RunningApps) > 0 {
				if running := runningApps(rule.RunningApps); len(running) > 0 {
					log.addf("REFUSED: app running (%s) — rule skipped", strings.Join(running, ", "))
					failures = append(failures, map[string]string{"rule": rule.ID, "path": "-", "error": "app running: " + strings.Join(running, ", ")})
					ruleFailures++
					continue
				}
			}
			c, err := collect(rule, vars, home)
			if err != nil {
				log.addf("FAILED collect: %v", err)
				failures = append(failures, map[string]string{"rule": rule.ID, "path": "-", "error": err.Error()})
				ruleFailures++
				continue
			}
			if c.blocked > 0 && c.count == 0 {
				// Scan-blind clean: every target unreadable. Refuse rather
				// than report a hollow success over an unknown pile.
				log.addf("REFUSED: targets unreadable (%s) — fix access, rescan and retry", strings.Join(dedupe(c.notes), "; "))
				failures = append(failures, map[string]string{"rule": rule.ID, "path": "-",
					"error": "targets unreadable (" + strings.Join(dedupe(c.notes), "; ") + ") — fix access, rescan and retry"})
				ruleFailures++
				continue
			}
			var movedBytes int64
			var moved int
			for _, f := range c.files {
				info, err := os.Lstat(f)
				if err != nil {
					log.addf("FAILED stat %s — %v", f, err)
					failures = append(failures, map[string]string{"rule": rule.ID, "path": f, "error": err.Error()})
					ruleFailures++
					continue
				}
				if rule.Action == "delete" {
					if err := os.Remove(f); err != nil {
						log.addf("FAILED delete %s — %v", f, err)
						failures = append(failures, map[string]string{"rule": rule.ID, "path": f, "error": err.Error()})
						ruleFailures++
						continue
					}
				} else {
					dst, err := trashTo(trashDir, f)
					if err != nil {
						log.addf("FAILED trash %s — %v", f, err)
						failures = append(failures, map[string]string{"rule": rule.ID, "path": f, "error": err.Error()})
						ruleFailures++
						continue
					}
					entry.Items = append(entry.Items, JournalItem{Path: f, Trash: filepath.Base(dst)})
				}
				movedBytes += info.Size()
				moved++
				entry.Bytes += info.Size()
				entry.Files++
			}
			// Husk cleanup: emptying a directory leaves the directory
			// itself behind, so Empty-the-Trash piled up hollow shells
			// (an .app with an empty Contents/, the .d-collision copies)
			// that the next scan still finds at 0 B with nothing left to
			// clean. Drop each matched root whose tree is now nothing but
			// empty directories — never one that still holds a file
			// anywhere, and never a protected location. Not journalled:
			// empty directories hold nothing restorable.
			for _, root := range c.roots {
				if criticalReason(root) == "" && removeTreeIfEmpty(root) {
					husksRemoved++
				}
			}
			entry.Rules = append(entry.Rules, rule.ID)
			_ = movedBytes
			_ = moved
			log.addf("rule %q: moved %d file(s) (%s), %d husk(s) removed, %d failed",
				rule.Title, moved, fmtBytes(movedBytes), husksRemoved, ruleFailures)
		}
	}
	if entry.Files > 0 || len(entry.Commands) > 0 {
		s.saveJournal(entry)
		log.addf("journal %s saved (%d item(s), %s) — restorable", entry.ID, entry.Files, fmtBytes(entry.Bytes))
	} else {
		log.addf("nothing moved — journal skipped")
	}

	summary := fmt.Sprintf("cleaned %d file(s) · %s → Trash · %d husk(s) · %d failed",
		entry.Files, fmtBytes(entry.Bytes), husksRemoved, len(failures))
	logPath := s.saveOpLog("clean", log.steps, summary)
	if logPath != "" {
		log.addf("log saved: %s", logPath)
	}
	return map[string]any{
		"ok":        true,
		"journalId": entry.ID,
		"bytes":     entry.Bytes,
		"files":     entry.Files,
		"husks":     husksRemoved,
		"failed":    failures,
		"commands":  entry.Commands,
		"log":       log.steps,
		"logPath":   logPath,
	}, nil
}

// trashTo moves src into trashDir (the Trash) and returns the destination
// path. A plain rename is tried first — atomic and instant on the same
// volume. When the OS refuses the rename, fallbacks run in order:
//   - macOS: hand the deletion to Finder, which holds the App Management
//     permission modern macOS requires to modify /Applications and knows
//     how to trash running-but-idle apps;
//   - every OS: copy into the Trash, verify the copy, then remove the
//     original — this is what makes cross-volume moves work at all
//     (EXDEV: the app lives on a second disk/external volume), plus any
//     permission case where rename is barred but read+delete are not.
//
// A failed fallback never leaves a half-state silently: if the copy landed
// but the original could not be removed, that exact situation is returned
// as the error (the Trash copy exists; the app is still installed).
func trashTo(trashDir, src string) (string, error) {
	dst := filepath.Join(trashDir, filepath.Base(src))
	if _, err := os.Lstat(dst); err == nil {
		dst = filepath.Join(trashDir, fmt.Sprintf("%s.d%d", filepath.Base(src), time.Now().UnixNano()))
	}
	err := os.Rename(src, dst)
	if err == nil {
		return dst, nil
	}
	renameErr := err
	if runtime.GOOS == "darwin" {
		if ferr := finderTrash(src); ferr == nil {
			return dst, nil
		}
	}
	if cerr := copyTree(src, dst); cerr != nil {
		return "", fmt.Errorf("%v (copy-to-Trash fallback also failed: %v)", renameErr, cerr)
	}
	if rmErr := os.RemoveAll(src); rmErr != nil {
		return "", fmt.Errorf("a copy is in the Trash, but the original could not be removed: %v", rmErr)
	}
	return dst, nil
}

// finderTrash asks Finder to delete src (macOS only). It needs the usual
// one-time "wants to control Finder" automation approval; Finder itself
// carries the App Management right, so this succeeds where a bare rename
// into /Applications content gets EPERM.
func finderTrash(src string) error {
	script := fmt.Sprintf(`tell application "Finder" to delete (POSIX file %q as alias)`, src)
	cmd := exec.Command("osascript", "-e", script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Finder hand-off: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// copyTree recursively copies src to dst (dirs, files, symlinks; modes
// preserved on files). Used by trashTo's cross-volume fallback.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			return os.MkdirAll(target, info.Mode().Perm())
		case info.Mode()&os.ModeSymlink != 0:
			link, err := os.Readlink(p)
			if err != nil {
				return err
			}
			return os.Symlink(link, target)
		default:
			in, err := os.Open(p)
			if err != nil {
				return err
			}
			defer in.Close()
			out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode().Perm())
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, in); err != nil {
				out.Close()
				return err
			}
			return out.Close()
		}
	})
}

// StepLog is one timestamped line of a detailed operation log. Uninstall
// and deletion endpoints return their full step list so the dashboard can
// show exactly what happened — a "1 failed" must never be a dead end.
type StepLog struct {
	At  string `json:"at"`
	Msg string `json:"msg"`
}

type stepLogger struct{ steps []StepLog }

func (l *stepLogger) addf(format string, args ...any) {
	l.steps = append(l.steps, StepLog{
		At:  time.Now().Format("15:04:05"),
		Msg: fmt.Sprintf(format, args...),
	})
}

// failWithLog answers an error that carries the operation's step log, so
// even a refused request shows its trail in the dashboard.
func failWithLog(w http.ResponseWriter, code int, msg string, steps []StepLog) {
	writeJSON(w, code, map[string]any{"error": msg, "log": steps})
}

// fmtBytes renders a byte count the way the dashboard does (0 B, 42 KB, …).
func fmtBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

// truncateStr caps a command-output line for the step log.
func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// saveOpLog persists an operation's step trail as a text file inside the
// APP FOLDER (<app root>/logs/<kind>-<timestamp>.log), pruned to the newest
// keepOpLogs. Returns the app-relative path ("" on failure — logging must
// never break the operation it describes). The dashboard shows the trail
// live; the file is the durable record for "what did that clean do".
const keepOpLogs = 50

func (s *server) saveOpLog(kind string, steps []StepLog, summary string) string {
	dir := filepath.Join(s.root, "logs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return ""
	}
	name := fmt.Sprintf("%s-%s.log", kind, time.Now().Format("20060102-150405"))
	var b strings.Builder
	for _, st := range steps {
		fmt.Fprintf(&b, "%s  %s\n", st.At, st.Msg)
	}
	if summary != "" {
		fmt.Fprintf(&b, "SUMMARY  %s\n", summary)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(b.String()), 0o644); err != nil {
		return ""
	}
	// prune oldest beyond keepOpLogs (names sort chronologically by prefix)
	entries, _ := os.ReadDir(dir)
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for len(names) > keepOpLogs {
		if os.Remove(filepath.Join(dir, names[0])) != nil {
			break
		}
		names = names[1:]
	}
	return filepath.Join("logs", name)
}

// removeTreeIfEmpty deletes root and its directory tree bottom-up, but
// only while every level is empty: the first file found anywhere stops
// that branch, so a clean can only ever clear husks it has emptied (or
// that were already empty) and never a directory that still holds data.
// Reports whether root itself was removed.
func removeTreeIfEmpty(root string) bool {
	entries, err := os.ReadDir(root)
	if err != nil {
		return false // gone, unreadable, or not a directory — nothing to do
	}
	for _, e := range entries {
		if !e.IsDir() {
			return false // a live file anchors the tree
		}
		if !removeTreeIfEmpty(filepath.Join(root, e.Name())) {
			return false
		}
	}
	return os.Remove(root) == nil
}

func runCommand(command string) (string, error) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", command)
	} else {
		cmd = exec.Command("sh", "-c", command)
	}
	out, err := combinedOutputTimeout(cmd, 5*time.Minute)
	return strings.TrimSpace(string(out)), err
}

func combinedOutputTimeout(cmd *exec.Cmd, timeout time.Duration) ([]byte, error) {
	done := make(chan error, 1)
	var buf syncBuffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	go func() { done <- cmd.Wait() }()
	select {
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		return buf.b, errors.New("timed out")
	case err := <-done:
		return buf.b, err
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  []byte
}

func (w *syncBuffer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.b = append(w.b, p...)
	return len(p), nil
}

/* ---------- journal ---------- */

func (s *server) journalPath() string {
	return filepath.Join(homeDir(), ".descale", "journal.json")
}

func (s *server) saveJournal(entry JournalEntry) {
	s.journalMu.Lock()
	defer s.journalMu.Unlock()
	entries := s.readJournal()
	entries = append(entries, entry)
	data, err := json.MarshalIndent(entries, "", " ")
	if err != nil {
		return
	}
	path := s.journalPath()
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}

func (s *server) readJournal() []JournalEntry {
	raw, err := os.ReadFile(s.journalPath())
	if err != nil {
		return nil
	}
	var entries []JournalEntry
	if json.Unmarshal(raw, &entries) != nil {
		return nil
	}
	return entries
}

func (s *server) handleJournal(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"entries": s.readJournal()})
}

func (s *server) handleRestore(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil || req.ID == "" {
		fail(w, http.StatusBadRequest, "expected {\"id\": \"...\"}")
		return
	}
	s.journalMu.Lock()
	defer s.journalMu.Unlock()
	entries := s.readJournal()
	trashDir := trashDirPath()
	for i := range entries {
		if entries[i].ID != req.ID {
			continue
		}
		if entries[i].Restored {
			fail(w, http.StatusConflict, "entry already restored")
			return
		}
		var restored, skipped, failed int
		for _, item := range entries[i].Items {
			if _, err := os.Lstat(item.Path); err == nil {
				// the spot is occupied — usually a fresh husk the app or the
				// OS recreated after the deletion. Keep it aside (restorable
				// under ~/.descale/husks) and put the trashed original back
				// in its place, so a restore never loses either copy.
				husk := filepath.Join(homeDir(), ".descale", "husks",
					fmt.Sprintf("%s-%s", time.Now().Format("20060102-150405"), filepath.Base(item.Path)))
				if err := os.MkdirAll(filepath.Dir(husk), 0o755); err != nil {
					skipped++
					continue
				}
				if err := os.Rename(item.Path, husk); err != nil {
					skipped++
					continue
				}
			}
			_ = os.MkdirAll(filepath.Dir(item.Path), 0o755)
			if err := os.Rename(filepath.Join(trashDir, item.Trash), item.Path); err != nil {
				failed++
				continue
			}
			restored++
		}
		entries[i].Restored = true
		if data, err := json.MarshalIndent(entries, "", " "); err == nil {
			path := s.journalPath()
			tmp := path + ".tmp"
			if os.WriteFile(tmp, data, 0o600) == nil {
				_ = os.Rename(tmp, path)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "restored": restored, "skipped": skipped, "failed": failed})
		return
	}
	fail(w, http.StatusNotFound, "no such journal entry: "+req.ID)
}

/* ---------- info ---------- */

func (s *server) handleInfo(w http.ResponseWriter, r *http.Request) {
	db, signed, err := s.loadRules()
	if err != nil {
		// A rules file that fails verification must be loud, not silently
		// treated as empty — this is the endpoint the UI greets you with.
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	ruleCount := 0
	if db != nil {
		for i := range db.Rules {
			if db.Rules[i].enabled() && ruleApplies(&db.Rules[i]) {
				ruleCount++
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name":          "Descale",
		"version":       appVersion,
		"os":            runtime.GOOS,
		"arch":          runtime.GOARCH,
		"archLabel":     archLabel(),
		"osVersion":     s.osVersionString(),
		"home":          homeDir(),
		"rulesActive":   ruleCount,
		"rulesSigned":   signed,
		"guardrails":    guardrailsEnabled(),
		"onboarded":     onboardingDone(),
		"diskFreeBytes": diskFree(homeDir()),
	})
}

// handleOnboarded records that the welcome banner was dismissed. The flag
// is persisted server-side because the embedded webview may not keep
// localStorage between launches.
func (s *server) handleOnboarded(w http.ResponseWriter, r *http.Request) {
	setOnboardingDone()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "onboarded": true})
}

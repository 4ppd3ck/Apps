package main

// server.go — HTTP API + static UI. Loopback only (AppDeck hands us
// APPDECK_HOST); hostguard.go adds the DNS-rebinding/cross-site layer.
// Static assets come from the app folder (index.html at root is the
// launcher contract), resolved from the binary's working directory, the
// executable's own folder, or SPACELENS_ROOT; if none is found the UI
// embedded by the root ui package answers, so a lone binary still works.
import (
	"encoding/json"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	ui "spacelens"
)

const Version = "1.2"

type server struct {
	root    string // app dir: index.html, css/, js/
	scanner *Scanner
}

func (s *server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("POST /api/scan", s.handleScan)
	mux.HandleFunc("GET /api/scan/poll", s.handlePoll)
	mux.HandleFunc("POST /api/scan/cancel", s.handleCancel)
	mux.HandleFunc("GET /api/roots", s.handleRoots)
	mux.HandleFunc("POST /api/pick", s.handlePick)
	mux.HandleFunc("POST /api/reveal", s.handleReveal)
	mux.HandleFunc("POST /api/delete", s.handleDelete)
	mux.HandleFunc("GET /api/status", s.handleStatus)
	mux.HandleFunc("GET /api/peer", s.handlePeer)
	return mux
}

func (s *server) handleRoot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	p := r.URL.Path
	switch {
	case p == "/" || p == "/index.html":
		s.serveFile(w, r, "index.html", "text/html; charset=utf-8")
	case strings.HasPrefix(p, "/css/"), strings.HasPrefix(p, "/js/"):
		name := strings.TrimPrefix(p, "/")
		switch {
		case strings.HasSuffix(name, ".css"):
			s.serveFile(w, r, name, "text/css; charset=utf-8")
		case strings.HasSuffix(name, ".js"):
			s.serveFile(w, r, name, "text/javascript; charset=utf-8")
		default:
			http.NotFound(w, r)
		}
	default:
		http.NotFound(w, r)
	}
}

// safeAssetPath reports whether name is a plain slash-separated relative
// path. ServeMux cleans "/" but not "\" — /css/..%5c..%5cx.js survives it
// and, once joined on Windows, would climb out of the app folder.
func safeAssetPath(name string) bool {
	return fs.ValidPath(name) && !strings.Contains(name, `\`)
}

// serveFile prefers the app folder's copy (live-editable); otherwise the
// embedded UI answers, so the binary also works standalone.
func (s *server) serveFile(w http.ResponseWriter, r *http.Request, name, ctype string) {
	if !safeAssetPath(name) {
		http.NotFound(w, r)
		return
	}
	if s.root != "" {
		if raw, err := os.ReadFile(filepath.Join(s.root, name)); err == nil {
			w.Header().Set("Content-Type", ctype)
			w.Write(raw)
			return
		}
	}
	raw, err := ui.Files.ReadFile(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", ctype)
	w.Write(raw)
}

func (s *server) fail(w http.ResponseWriter, code int, msg string) {
	s.json(w, map[string]any{"error": msg}, code)
}

func (s *server) json(w http.ResponseWriter, v any, code ...int) {
	raw, err := json.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "application/json") // before WriteHeader, or it is dropped
	if len(code) > 0 {
		w.WriteHeader(code[0])
	}
	w.Write(raw)
}

// decodeJSON parses one small JSON request body (capped at 1 MiB) and
// answers the request itself when it does not parse.
func (s *server) decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(v); err != nil {
		s.fail(w, http.StatusBadRequest, "bad request body")
		return false
	}
	return true
}

func (s *server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.json(w, map[string]any{
		"version": Version,
		"os":      runtime.GOOS,
		"arch":    runtime.GOARCH,
		"root":    s.root,
	})
}

func (s *server) handleScan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Root  string   `json:"root"`  // single root (backward compatible)
		Roots []string `json:"roots"` // one or more roots
	}
	if !s.decodeJSON(w, r, &req) {
		return
	}
	roots := req.Roots
	if req.Root != "" && len(roots) == 0 {
		roots = []string{req.Root}
	}
	for i := range roots {
		roots[i] = strings.TrimSpace(roots[i])
	}
	if len(roots) == 0 {
		s.fail(w, http.StatusBadRequest, "root (directory path) required")
		return
	}
	if err := s.scanner.Start(roots); err != nil {
		s.fail(w, http.StatusConflict, err.Error())
		return
	}
	s.json(w, map[string]any{"ok": true, "roots": roots})
}

func (s *server) handlePoll(w http.ResponseWriter, r *http.Request) {
	s.json(w, s.scanner.Snapshot())
}

func (s *server) handleCancel(w http.ResponseWriter, r *http.Request) {
	s.scanner.Cancel()
	s.json(w, map[string]any{"ok": true})
}

// handleRoots lists scan presets: home, the OS app/software dirs, and every
// mounted volume — the usual suspects for "what ate my disk".
func (s *server) handleRoots(w http.ResponseWriter, r *http.Request) {
	type Root struct {
		Path string `json:"path"`
		Name string `json:"name"`
	}
	home, _ := os.UserHomeDir()
	roots := []Root{}
	if home != "" {
		roots = append(roots, Root{Path: home, Name: "Home"})
	}
	volumes := func(base string) { // every mounted volume under base
		if entries, err := os.ReadDir(base); err == nil {
			for _, e := range entries {
				if e.IsDir() {
					roots = append(roots, Root{Path: filepath.Join(base, e.Name()), Name: "Volume: " + e.Name()})
				}
			}
		}
	}
	switch runtime.GOOS {
	case "darwin":
		roots = append(roots, Root{Path: "/Applications", Name: "Applications"})
		volumes("/Volumes")
		roots = append(roots, Root{Path: "/", Name: "Macintosh root /"})
	case "windows":
		for c := 'C'; c <= 'Z'; c++ {
			drive := string(c) + `:\`
			if _, err := os.Stat(drive); err == nil {
				roots = append(roots, Root{Path: drive, Name: "Drive " + drive})
			}
		}
		if home != "" {
			roots = append(roots, Root{Path: filepath.Join(home, "AppData"), Name: "AppData"})
		}
	default: // linux
		roots = append(roots, Root{Path: "/", Name: "Root /"})
		roots = append(roots, Root{Path: "/usr", Name: "/usr"})
		if home != "" {
			roots = append(roots, Root{Path: filepath.Dir(home), Name: filepath.Dir(home)})
		}
		for _, base := range []string{"/media", "/run/media", "/mnt"} {
			volumes(base)
		}
	}
	s.json(w, map[string]any{"roots": roots, "home": home})
}

// findRoot walks up from start until a directory holds index.html.
func findRoot(start string) string {
	for dir := start; ; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "index.html")); err == nil {
			return dir
		}
		if dir == filepath.Dir(dir) {
			return ""
		}
	}
}

// resolveRoot finds the app folder (index.html) for static serving: the
// working directory, then the executable's own folder (a double-clicked
// Windows exe may start with an unrelated cwd), each searched upward.
func resolveRoot() string {
	if v := os.Getenv("SPACELENS_ROOT"); v != "" {
		return v
	}
	if wd, err := os.Getwd(); err == nil {
		if dir := findRoot(wd); dir != "" {
			return dir
		}
	}
	if exe, err := os.Executable(); err == nil {
		return findRoot(filepath.Dir(exe))
	}
	return ""
}

func main() {
	host := "127.0.0.1"
	port := 8767

	if v := os.Getenv("APPDECK_HOST"); v != "" {
		host = v
	}
	if p := os.Getenv("APPDECK_PORT"); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			port = n
		}
	} else if p := os.Getenv("PORT"); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			port = n
		}
	}
	for i := 1; i < len(os.Args); i++ {
		switch {
		case os.Args[i] == "--port" && i+1 < len(os.Args):
			if n, err := strconv.Atoi(os.Args[i+1]); err == nil {
				port = n
			}
			i++
		case os.Args[i] == "--host" && i+1 < len(os.Args):
			host = os.Args[i+1]
			i++
		}
	}

	root := resolveRoot()
	srv := &server{root: root, scanner: NewScanner()}
	addr := host + ":" + strconv.Itoa(port)
	println("wGauge " + Version + " — disk space explorer (read-only)")
	println("  serving : http://" + addr)
	if root != "" {
		println("  app root: " + root)
	} else {
		println("  app root: (not found — serving embedded UI)")
	}
	if err := http.ListenAndServe(addr, hostGuard(host, srv.routes())); err != nil {
		println("fatal: " + err.Error())
		os.Exit(1)
	}
}

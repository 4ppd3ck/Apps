// Command wgrid is a stdlib-only local server for the wGrid desktop
// utility: the known-IP intelligence feed — original app, restored from
// the wTower merge. It fetches published network ranges of well-known
// providers (plus git- and file-backed sources), caches them under
// APPDECK_DATA, and serves the provider tables plus a small management
// API. wHawk's checks and wTower's country-block source label known
// endpoints from here.
//
// The server binds to 127.0.0.1 only. Git sources are https-locked and the
// API is read-only except the source editor — nothing on this machine is
// ever modified beyond the app's own data folder.
package main

import (
	"encoding/json"
	"fmt"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	defaultPort = 8768
	// feedRefresh is the background refresh cadence for the provider tables.
	feedRefresh = 24 * time.Hour
)

type server struct {
	root    string // app dir: index.html, css/, js/
	feed    *IntelFeed
	wired   *Wired
	purge   *wPurgeClient
	dataDir string // <APPDECK_DATA>/feed — cache.json, sources.json, repos/
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "wgrid: %v\n", err)
		os.Exit(1)
	}
}

// run accepts a bare port number (AppDeck passes one positionally), or
// nothing — the port then comes from the APPDECK_PORT/PORT environment
// contract, falling back to the manual-run default.
func run(args []string) error {
	port := defaultPort
	if len(args) > 0 {
		p, err := strconv.Atoi(strings.TrimSpace(args[0]))
		if err != nil || p <= 0 {
			return fmt.Errorf("invalid port %q: must be an integer like %d", args[0], defaultPort)
		}
		port = p
	} else {
		for _, k := range []string{"APPDECK_PORT", "PORT"} {
			if v := os.Getenv(k); v != "" {
				if p, err := strconv.Atoi(v); err == nil && p > 0 {
					port = p
				}
				break
			}
		}
	}
	root := resolveRoot()
	if !hasIndexHTML(root) {
		fmt.Fprintf(os.Stderr, "warning: no index.html in %q; set WGRID_ROOT to the app directory\n", root)
	}
	seedMimeTypes()

	// feed state: one-time import from the apps the feed used to live in
	// (wTower's merge kept it under watchdog/, standalone wHawk top-level),
	// then the shipped sources.json seed for a fresh install.
	dataDir := resolveDataDir()
	MigrateFeedState(dataDir)
	SeedIntelSources(dataDir)

	srv := &server{
		root:    root,
		dataDir: dataDir,
		feed:    NewIntelFeed(dataDir, feedRefresh),
		wired:   NewWired(launcherURL(), os.Getenv("WPURGE_URL")),
		purge:   newWPurgeClient(os.Getenv("WPURGE_URL")),
	}
	srv.feed.Load() // sources + cache; kicks a background refresh when stale

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/status", srv.handleStatus)
	mux.HandleFunc("GET /api/networks", srv.handleNetworks)
	mux.HandleFunc("GET /api/intel", srv.handleIntelLookup)
	mux.HandleFunc("POST /api/refresh", srv.handleRefresh)
	mux.HandleFunc("GET /api/sources", srv.handleSources)
	mux.HandleFunc("POST /api/sources/add", srv.handleSourceAdd)
	mux.HandleFunc("POST /api/sources/delete", srv.handleSourceDelete)
	mux.HandleFunc("GET /api/wired", srv.handleWired)
	mux.HandleFunc("GET /api/apps", srv.handleApps)
	mux.Handle("/", logging(noCache(http.FileServer(http.Dir(root)))))

	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("cannot bind %s: %w", addr, err)
	}
	fmt.Printf("📡 wGrid v%s at http://127.0.0.1:%d  (known-IP intel feed — state in %s)\n", appVersion, port, dataDir)
	handler := hostGuard("127.0.0.1", mux)
	handler = tokenFence(os.Getenv("APPDECK_TOKEN"), handler)
	httpSrv := &http.Server{Handler: handler}
	return httpSrv.Serve(ln)
}

// resolveDataDir is the feed's state folder: <APPDECK_DATA>/feed (the
// launcher contract), or ./data for a manual run.
func resolveDataDir() string {
	if home := strings.TrimSpace(os.Getenv("APPDECK_DATA")); home != "" {
		return filepath.Join(home, "feed")
	}
	return "data"
}

/* ---------- http plumbing (mirrors the w-family servers) ---------- */

func resolveRoot() string {
	if r := strings.TrimSpace(os.Getenv("WGRID_ROOT")); r != "" {
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

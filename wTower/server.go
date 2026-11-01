// Dashboard HTTP server: static UI, REST API, and SSE live event stream
// (mirrors monitor/server.py, stdlib net/http instead of http.server).
package wtower

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The dashboard assets are embedded so a single copied binary serves its own
// UI anywhere (the disk web/ dir still wins when present, e.g. during dev).
//
//go:embed web
var webFS embed.FS

var contentTypes = map[string]string{
	".html": "text/html; charset=utf-8",
	".js":   "text/javascript; charset=utf-8",
	".css":  "text/css; charset=utf-8",
	".svg":  "image/svg+xml",
	".png":  "image/png",
	".ico":  "image/x-icon",
}

// Categories mirrors server._CATEGORIES.
var Categories = []string{"privacy", "files", "network", "devices", "logins",
	"appfocus", "battery", "android"}

// PlatformString returns sys.platform-style values ("win32", "darwin", "linux").
func PlatformString() string {
	switch runtime.GOOS {
	case "windows":
		return "win32"
	case "darwin":
		return "darwin"
	default:
		return runtime.GOOS
	}
}

// CurrentUser mirrors server._current_user.
func CurrentUser() string {
	return GetPassUser()
}

// HostInfo mirrors server.host_info: {"hostname", "platform", "python",
// "user", "root"}. The "python" key is kept for dashboard compatibility and
// reports the Go runtime version instead.
func HostInfo() map[string]any {
	hostname, _ := os.Hostname()
	return map[string]any{
		"hostname": hostname,
		"platform": PlatformString(),
		"python":   runtime.Version(),
		"user":     CurrentUser(),
		"root":     isElevated(),
	}
}

// MonitorServer wraps the http.Server with dashboard-specific behaviour
// (debug request logging, quiet client-abort errors).
type MonitorServer struct {
	Listener net.Listener
	HTTP     *http.Server
	Debug    bool
}

// NewMonitorServer binds addr (mirrors MonitorServer((host, port), handler)).
func NewMonitorServer(addr string, handler http.Handler) (*MonitorServer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	srv := &MonitorServer{Listener: ln}
	wrapped := &debugHandler{inner: handler, server: srv}
	srv.HTTP = &http.Server{Handler: hostGuard(hostOf(addr), wrapped)}
	srv.HTTP.ErrorLog = log.New(&filteredWriter{next: os.Stderr},
		"", log.LstdFlags)
	return srv, nil
}

// debugHandler mirrors BaseHTTPRequestHandler.log_message gated on
// server.debug: request lines are only logged in --debug mode.
type debugHandler struct {
	inner  http.Handler
	server *MonitorServer
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (s *statusWriter) WriteHeader(code int) {
	s.code = code
	s.ResponseWriter.WriteHeader(code)
}

func (d *debugHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !d.server.Debug {
		d.inner.ServeHTTP(w, r)
		return
	}
	rw := &statusWriter{ResponseWriter: w, code: 200}
	d.inner.ServeHTTP(rw, r)
	log.Printf("%s %s %d", r.Method, r.URL.RequestURI(), rw.code)
}

// Serve runs the accept loop until the listener is closed.
func (m *MonitorServer) Serve() error { return m.HTTP.Serve(m.Listener) }

// Close closes the listener and the server (server_close).
func (m *MonitorServer) Close() error {
	m.HTTP.Close()
	return m.Listener.Close()
}

// filteredWriter drops the connection noise that Python's handle_error also
// suppresses (ConnectionAborted/Reset/BrokenPipe/Timeout).
type filteredWriter struct{ next *os.File }

func (f *filteredWriter) Write(p []byte) (int, error) {
	s := string(p)
	for _, quiet := range []string{
		"broken pipe", "connection reset", "connection aborted",
		"client disconnected", "context canceled", "i/o timeout",
		"EOF",
	} {
		if strings.Contains(s, quiet) {
			return len(p), nil
		}
	}
	return f.next.Write(p)
}

// ------------------------------------------------------------ handlers ----

// NewHandler builds the dashboard handler (server.make_handler).
func NewHandler(ctx *Ctx) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			doGet(ctx, w, r)
		case http.MethodPost:
			doPost(ctx, w, r)
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "not found"})
		}
	})
	return mux
}

func doGet(ctx *Ctx, w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if path == "/" || path == "/index.html" {
		serveStatic(ctx, w, "index.html")
		return
	}
	if path == "/favicon.ico" { // browser tabs ask for this by convention
		serveStatic(ctx, w, "icon.png")
		return
	}
	if strings.HasPrefix(path, "/web/") {
		serveStatic(ctx, w, path[len("/web/"):])
		return
	}
	payload, code, err := apiGet(ctx, path, r)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	if code == http.StatusSeeOther { // SSE hijack marker
		serveSSE(ctx, w, r)
		return
	}
	writeJSON(w, code, payload)
}

func doPost(ctx *Ctx, w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	switch path {
	case "/api/collectors":
		postCollectors(ctx, w, r)
	case "/api/theme":
		data, ok := readBody(r)
		if !ok {
			writeJSON(w, 400, map[string]any{"error": "invalid body"})
			return
		}
		id, _ := data["theme"].(string)
		theme, err := ctx.Cfg.SetTheme(id)
		if err != nil {
			writeJSON(w, 400, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "theme": theme})
	case "/api/table-visibility":
		data, ok := readBody(r)
		if !ok {
			writeJSON(w, 400, map[string]any{"error": "invalid body"})
			return
		}
		visibility, err := saveTableVisibility(ctx.Cfg, data["visibility"])
		if err != nil {
			writeJSON(w, 400, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "visibility": visibility})
	case "/api/dashboard-layout":
		data, ok := readBody(r)
		if !ok {
			writeJSON(w, 400, map[string]any{"error": "invalid body"})
			return
		}
		layout, err := saveDashboardLayout(ctx.Cfg, data["layout"])
		if err != nil {
			writeJSON(w, 400, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "layout": layout})
	case "/api/gauge-style":
		data, ok := readBody(r)
		if !ok {
			writeJSON(w, 400, map[string]any{"error": "invalid body"})
			return
		}
		style, _ := data["style"].(string)
		switch style {
		case "gauges-solid", "gauges-gradient", "gauges-segmented", "gauges-neon":
		default:
			writeJSON(w, 400, map[string]any{"error": "unknown gauge style"})
			return
		}
		ctx.Cfg.Data["gauge_style"] = style
		if err := ctx.Cfg.Save(); err != nil {
			writeJSON(w, 500, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "style": style})
	case "/api/data/delete":
		postDataDelete(ctx, w, r)
	case "/api/retention":
		postRetention(ctx, w, r)
	case "/api/blocks":
		postBlocks(ctx, w, r)
	case "/api/dns":
		postDNS(ctx, w, r)
	case "/api/block/grant":
		postGrant(ctx, w, r, "block")
	case "/api/files/grant":
		postGrant(ctx, w, r, "files")
	default:
		writeJSON(w, 404, map[string]any{"error": "not found"})
	}
}

func writeJSON(w http.ResponseWriter, code int, obj any) {
	body, err := json.Marshal(obj)
	if err != nil {
		code = 500
		body, _ = json.Marshal(map[string]any{"error": err.Error()})
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(code)
	w.Write(body)
}

func readBody(r *http.Request) (map[string]any, bool) {
	data, err := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return nil, false
	}
	if len(data) == 0 {
		data = []byte("{}")
	}
	var body map[string]any
	if err := json.Unmarshal(data, &body); err != nil {
		return nil, false
	}
	return body, true
}

// ------------------------------------------------------------ static ----

// resolveWebDir locates the dashboard assets. The Python build serves
// <package>/web; a compiled binary checks the working directory and the
// executable directory.
func resolveWebDir() string {
	if env := os.Getenv("MONITOR_WEB_DIR"); env != "" {
		return env
	}
	var candidates []string
	candidates = append(candidates, "web", filepath.Join("monitor", "web"))
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(exeDir, "web"),
			filepath.Join(exeDir, "..", "monitor", "web"),
			filepath.Join(exeDir, "..", "web"),
		)
	}
	candidates = append(candidates,
		filepath.Join("..", "web"),
	)
	for _, c := range candidates {
		if _, err := os.Stat(filepath.Join(c, "index.html")); err == nil {
			return c
		}
	}
	return candidates[0]
}

var webDir = resolveWebDir()

func serveStatic(ctx *Ctx, w http.ResponseWriter, name string) {
	// Root-relative within web/, traversal-proof: Clean of a rooted path can
	// never escape upward, so sub-folder assets (web/flags/*.svg — the country
	// flag sprites) serve too. The old filepath.Base(name) flattened
	// "flags/cn.svg" into "cn.svg" and 404'd every sub-folder asset.
	rel := strings.TrimPrefix(filepath.ToSlash(filepath.Clean("/"+name)), "/")
	if rel == "index.html" || name == "index.html" {
		rel = "index.html"
	}
	if rel == "" || rel == "." || strings.HasPrefix(rel, "../") {
		writeJSON(w, 404, map[string]any{"error": "not found"})
		return
	}
	// Serve the copy embedded in this binary FIRST: it is built together
	// with the code, so it always matches the running API (the gauge-style
	// lesson: a stale extracted apps/<id>/web folder from an older install
	// otherwise shadows the current UI forever, because the deck's extractor
	// only refreshes assets it actually staged). Disk is consulted only when
	// the file isn't embedded — that covers the MONITOR_WEB_DIR dev override
	// and folders carrying extra files the build doesn't know about.
	body, err := webFS.ReadFile("web/" + rel)
	if err != nil {
		body, err = os.ReadFile(filepath.Join(webDir, filepath.FromSlash(rel)))
	}
	if err != nil {
		// Tab/favicon requests hit /favicon.ico by convention; answer with
		// the app icon so browser tabs (and the Windows/macOS app windows)
		// show the AppScope shield.
		if rel == "favicon.ico" {
			if ico, ierr := os.ReadFile(filepath.Join(webDir, "icon.png")); ierr == nil {
				w.Header().Set("Content-Type", "image/png")
				w.Header().Set("Content-Length", strconv.Itoa(len(ico)))
				w.Header().Set("Cache-Control", "no-cache")
				w.WriteHeader(200)
				w.Write(ico)
				return
			}
			if ico, ierr := webFS.ReadFile("web/icon.png"); ierr == nil {
				w.Header().Set("Content-Type", "image/png")
				w.Header().Set("Content-Length", strconv.Itoa(len(ico)))
				w.Header().Set("Cache-Control", "no-cache")
				w.WriteHeader(200)
				w.Write(ico)
				return
			}
		}
		writeJSON(w, 404, map[string]any{"error": "not found"})
		return
	}
	ct := contentTypes[strings.ToLower(filepath.Ext(rel))]
	if ct == "" {
		ct = "application/octet-stream"
	}
	// The dashboard is themed through CSS custom properties that the JS
	// applies only after /api/themes returns — without the inline boot
	// style every load paints the dark defaults first (a visible flash for
	// Light users, and light-form native controls until JS runs). The
	// server knows the active theme, so index.html ships with the palette
	// already in place. localStorage cannot carry the choice (the launcher
	// wipes it), which is why the server is the source of truth here.
	if rel == "index.html" && ctx != nil && ctx.Cfg != nil {
		if i := bytes.Index(bytes.ToLower(body), []byte("</head>")); i >= 0 {
			boot := []byte("<style>" + ThemeBootCSS(ctx.Cfg) + "</style>")
			body = append(body[:i:i], append(boot, body[i:]...)...)
		}
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(200)
	w.Write(body)
}

// --------------------------------------------------------------- APIs ----

func apiGet(ctx *Ctx, path string, r *http.Request) (any, int, error) {
	switch path {
	case "/api/gauge-style":
		style := "gauges-gradient"
		if v, ok := ctx.Cfg.Get("gauge_style"); ok {
			if s, ok := v.(string); ok && s != "" {
				style = s
			}
		}
		return map[string]any{"style": style}, 200, nil
	case "/api/themes":
		themes, err := ctx.Cfg.Themes()
		if err != nil {
			return nil, 500, err
		}
		return map[string]any{
			"themes": themes, "active": ctx.Cfg.ActiveTheme(),
		}, 200, nil
	case "/api/table-visibility":
		return map[string]any{"visibility": tableVisibility(ctx.Cfg)}, 200, nil
	case "/api/dashboard-layout":
		return dashboardLayout(ctx.Cfg), 200, nil
	case "/api/status":
		return apiStatus(ctx), 200, nil
	case "/api/summary":
		return apiSummary(ctx, r.URL.RawQuery)
	case "/api/events":
		return apiEvents(ctx, r.URL.RawQuery)
	case "/api/connections":
		snap := ctx.Net.Snapshot()
		conns, _ := snap["connections"].([]map[string]any)
		enrichConnections(ctx, conns) // geo + first_seen; cache-only, never blocks
		return map[string]any{
			"connections": conns,
			"updated_at":  snap["updated_at"],
		}, 200, nil
	case "/api/destinations":
		qs, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			return nil, 400, err
		}
		since, ok := ToFloat(qsValue(qs, "since", "0"))
		if !ok {
			return nil, 400, fmt.Errorf("invalid since")
		}
		countries, sites, apps, err := destinationSummary(ctx, since)
		if err != nil {
			return nil, 500, err
		}
		if countries == nil {
			countries = []IPCountryRow{}
		}
		if sites == nil {
			sites = []SiteGroup{}
		}
		if apps == nil {
			apps = []AppGroup{}
		}
		return map[string]any{
			"countries": countries, "sites": sites, "apps": apps,
		}, 200, nil
	case "/api/connection-history":
		qs, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			return nil, 400, err
		}
		since, ok := ToFloat(qsValue(qs, "since", "0"))
		if !ok {
			return nil, 400, fmt.Errorf("invalid since")
		}
		limit, err := strconv.Atoi(qsValue(qs, "limit", "500"))
		if err != nil {
			return nil, 400, fmt.Errorf("invalid limit")
		}
		records, err := ctx.Store.QueryConnectionHistory(since, limit)
		if err != nil {
			return nil, 500, err
		}
		if records == nil {
			records = []*ConnectionRecord{}
		}
		enrichConnectionRecords(ctx, records)
		return map[string]any{"connections": records}, 200, nil
	case "/api/traffic":
		snap := ctx.Net.Snapshot()
		history, _ := snap["history"].([]HistoryPoint)
		if len(history) > 180 {
			history = history[len(history)-180:]
		}
		totals, err := ctx.Net.TrafficSummary(ctx.Store)
		if err != nil {
			return nil, 500, err
		}
		return map[string]any{
			"app_rates":       snap["app_rates"],
			"ifaces":          snap["ifaces"],
			"app_connections": snap["app_connections"],
			"history":         history,
			"totals":          totals,
		}, 200, nil
	case "/api/battery":
		info := ctx.Battery()
		out := map[string]any{}
		for k, v := range info {
			out[k] = v
		}
		out["available"] = len(info) > 0
		return out, 200, nil
	case "/api/blocks":
		mode, reason := "", "enforcer unavailable"
		if ctx.Enforcer != nil {
			mode, reason = ctx.Enforcer.Mode, ctx.Enforcer.Reason
		}
		rules, err := ctx.Store.ListBlocks()
		if err != nil {
			return nil, 500, err
		}
		if rules == nil {
			rules = []*Block{}
		}
		_, grantable := grantScript("block")
		ipolice := map[string]any{"available": false}
		countryCIDRs := map[string]int{}
		if ctx.Country != nil {
			ipolice = ctx.Country.Status()
		}
		hasAllow := false
		for _, r := range rules {
			if r.Action == "allow" {
				hasAllow = true
			}
			if r.Type == "country" || r.Type == "provider" {
				countryCIDRs[r.Value] = ctx.Country.CachedCount(r.Value)
				if countryCIDRs[r.Value] == 0 {
					// data not in yet (IPolice's feed refresh races the
					// first fetch): retry in the background, debounced
					if r.Type == "country" {
						go ctx.Country.EnsureBackground(r.Value)
					} else {
						go ctx.Country.EnsureProviderBackground(r.Value)
					}
				}
			}
		}
		return map[string]any{
			"rules": rules,
			"enforcement": map[string]any{
				"mode": mode, "reason": reason,
				"platform":        PlatformString(),
				"grant_supported": grantable,
			},
			"paused":        ctx.Enforcer != nil && ctx.Enforcer.Paused(),
			"ipolice":       ipolice,
			"country_cidrs": countryCIDRs,
			// allow rules need the helper's allow verbs; an installed
			// helper from before them must be re-granted (reinstalled)
			"helper_outdated": hasAllow && ctx.Enforcer != nil &&
				ctx.Enforcer.HelperVersion() < helperAllowMinVersion,
		}, 200, nil
	case "/api/wgrid/providers":
		if ctx.Country == nil {
			return map[string]any{"providers": []string{},
				"error": "country source unavailable"}, 200, nil
		}
		names, err := ctx.Country.ProviderNames()
		if err != nil {
			return map[string]any{"providers": []string{},
				"error": err.Error()}, 200, nil
		}
		return map[string]any{"providers": names}, 200, nil
	case "/api/dns":
		if ctx.DNSShield == nil {
			return map[string]any{"running": false, "lists": []any{},
				"error": "dns shield unavailable"}, 200, nil
		}
		status := ctx.DNSShield.Status()
		status["custom_domains"] = ctx.DNSShield.CustomDomains()
		return status, 200, nil
	case "/api/heatmap":
		qs, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			return nil, 400, err
		}
		hours, ok := ToInt(qsValue(qs, "hours", "24"))
		if !ok || hours <= 0 {
			return nil, 400, fmt.Errorf("invalid hours")
		}
		if hours > 168 {
			hours = 168
		}
		buckets, err := ctx.Store.ActivityByHour(Now() - float64(hours)*3600)
		if err != nil {
			return nil, 500, err
		}
		return map[string]any{"hours": hours, "buckets": buckets}, 200, nil
	case "/api/visits":
		qs, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			return nil, 400, err
		}
		hours, ok := ToInt(qsValue(qs, "hours", "24"))
		if !ok || hours <= 0 {
			return nil, 400, fmt.Errorf("invalid hours")
		}
		if hours > 168 {
			hours = 168
		}
		gap, ok := ToInt(qsValue(qs, "gap", "300"))
		if !ok || gap < 0 {
			return nil, 400, fmt.Errorf("invalid gap")
		}
		if gap > 3600 {
			gap = 3600
		}
		visits, err := BuildVisits(ctx, Now()-float64(hours)*3600, float64(gap))
		if err != nil {
			return nil, 500, err
		}
		if visits == nil {
			visits = []VisitSession{}
		}
		return map[string]any{"visits": visits, "hours": hours, "gap": gap}, 200, nil
	case "/api/retention":
		return map[string]any{"days": ctx.Cfg.RetentionDays()}, 200, nil
	case "/api/stream":
		return nil, http.StatusSeeOther, nil
	default:
		return map[string]any{"error": "not found"}, 404, nil
	}
}

func collectorInfos(cols []Collector) []map[string]any {
	out := make([]map[string]any, 0, len(cols))
	for _, c := range cols {
		out = append(out, map[string]any{
			"name":        c.Name(),
			"category":    c.Category(),
			"description": c.Description(),
			"enabled":     c.Enabled(),
			"status":      c.Status(),
		})
	}
	return out
}

func apiStatus(ctx *Ctx) map[string]any {
	info := HostInfo()
	info["collectors"] = collectorInfos(ctx.Collectors())
	info["android_devices"] = ctx.AndroidDevices()
	info["version"] = Version
	// on-demand file tracing (macOS): the padlock's state source
	info["files_grant"] = map[string]any{
		"supported": runtime.GOOS == "darwin",
		"installed": filesGrantInstalled(),
	}
	return info
}

func apiSummary(ctx *Ctx, rawQuery string) (any, int, error) {
	qs, err := url.ParseQuery(rawQuery)
	if err != nil {
		return nil, 500, err
	}
	minutes, ok := ToInt(qsValue(qs, "minutes", "60"))
	if !ok {
		return nil, 500, fmt.Errorf("invalid minutes")
	}
	since := Now() - float64(minutes)*60
	counts, err := ctx.Store.Counts(since)
	if err != nil {
		return nil, 500, err
	}
	snap := ctx.Net.Snapshot()
	appRates, _ := snap["app_rates"].(map[string]Rate)
	type kv struct {
		app   string
		total int64
	}
	var pairs []kv
	for app, r := range appRates {
		pairs = append(pairs, kv{app, r.TotalIn + r.TotalOut})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].total > pairs[j].total })
	if len(pairs) > 10 {
		pairs = pairs[:10]
	}
	topApps := make([][]any, 0, len(pairs))
	for _, p := range pairs {
		topApps = append(topApps, []any{p.app, p.total})
	}
	conns, _ := snap["connections"].([]map[string]any)
	return map[string]any{
		"minutes":            minutes,
		"counts":             counts,
		"active_connections": len(conns),
		"top_apps":           topApps,
		"app_connections":    snap["app_connections"],
		"ifaces":             snap["ifaces"],
	}, 200, nil
}

// qsValue mirrors parse_qs(...).get(key, [default])[0]: parse_qs drops blank
// values, so an empty value behaves like an absent one.
func qsValue(qs url.Values, key, def string) string {
	v := qs.Get(key)
	if v == "" {
		return def
	}
	return v
}

func apiEvents(ctx *Ctx, rawQuery string) (any, int, error) {
	qs, err := url.ParseQuery(rawQuery)
	if err != nil {
		return nil, 500, err
	}
	sinceStr := qsValue(qs, "since", "0")
	since, ok := ToFloat(sinceStr)
	if !ok {
		return nil, 500, fmt.Errorf("invalid since")
	}
	limit, err := strconv.Atoi(qsValue(qs, "limit", "300"))
	if err != nil {
		return nil, 500, fmt.Errorf("invalid limit")
	}
	if limit > 2000 {
		limit = 2000
	}
	category := qs.Get("category")
	events, err := ctx.Store.Query(category, since, limit, nil)
	if err != nil {
		return nil, 500, err
	}
	if events == nil {
		events = []*Event{}
	}
	return map[string]any{"events": events}, 200, nil
}

// ------------------------------------------------------------ SSE ----

func serveSSE(ctx *Ctx, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(200)
	flusher, canFlush := w.(http.Flusher)
	if !canFlush {
		return
	}
	q := ctx.Bus.Subscribe()
	defer ctx.Bus.Unsubscribe(q)
	if _, err := io.WriteString(w, "retry: 3000\n\n"); err != nil {
		return
	}
	flusher.Flush()
	for {
		select {
		case payload := <-q:
			if _, err := fmt.Fprintf(w, "data: %s\n\n", payload); err != nil {
				return
			}
		case <-time.After(15 * time.Second):
			if _, err := io.WriteString(w, ": ping\n\n"); err != nil {
				return
			}
		case <-r.Context().Done():
			return
		}
		flusher.Flush()
	}
}

// -------------------------------------------------------------- POST ----

func postCollectors(ctx *Ctx, w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(r)
	if !ok {
		writeJSON(w, 400, map[string]any{"error": "bad JSON body"})
		return
	}
	target := StrOf(body["target"])
	enabled := Truthy(body["enabled"])
	sorted := append([]string(nil), Categories...)
	sort.Strings(sorted)
	if target != "all" && !contains(sorted, target) {
		quoted := make([]string, len(sorted))
		for i, s := range sorted {
			quoted[i] = "'" + s + "'"
		}
		writeJSON(w, 400, map[string]any{
			"error": fmt.Sprintf("target must be 'all' or one of [%s]",
				strings.Join(quoted, ", "))})
		return
	}
	writeJSON(w, 200, ToggleCollectors(ctx, target, enabled))
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func postDataDelete(ctx *Ctx, w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(r)
	if !ok {
		writeJSON(w, 400, map[string]any{"error": "bad JSON body"})
		return
	}
	if Truthy(body["all"]) {
		deleted, err := ctx.Store.DeleteBefore(Now() + 1)
		if err != nil {
			writeJSON(w, 500, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "deleted": deleted,
			"scope": "all"})
		return
	}
	hours, ok := ToFloat(body["hours"])
	if !ok {
		writeJSON(w, 400, map[string]any{"error": "body must be {\"hours\": n} or " +
			"{\"all\": true}"})
		return
	}
	if hours <= 0 {
		writeJSON(w, 400, map[string]any{"error": "hours must be > 0"})
		return
	}
	deleted, err := ctx.Store.DeleteBefore(Now() - hours*3600)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "deleted": deleted,
		"scope": fmt.Sprintf("older than %sh", formatFloat(hours))})
}

func formatFloat(f float64) string {
	s := strconv.FormatFloat(f, 'g', -1, 64)
	return s
}

// postRetention sets the automatic purge window (config retention_days).
// The store's retention loop applies it on its next 30-minute pass.
func postRetention(ctx *Ctx, w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(r)
	if !ok {
		writeJSON(w, 400, map[string]any{"error": "bad JSON body"})
		return
	}
	days, ok := ToInt(body["days"])
	if !ok || days < 0 || days > 3650 {
		writeJSON(w, 400, map[string]any{"error": "days must be between 0 and 3650 " +
			"(0 disables automatic purging)"})
		return
	}
	ctx.Cfg.Data["retention_days"] = days
	if err := ctx.Cfg.Save(); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	ctx.Store.SetRetention(days)
	writeJSON(w, 200, map[string]any{"ok": true, "days": days})
}

// ToggleCollectors enables/disables one monitoring category or all and
// persists the setting to config (server.toggle_collectors).
func ToggleCollectors(ctx *Ctx, target string, enabled bool) map[string]any {
	for _, c := range ctx.Collectors() {
		if target != "all" && c.Category() != target {
			continue
		}
		c.SetEnabled(enabled)
		if enabled {
			if ok, reason := c.Available(); ok {
				c.Start()
				c.SetStatus("active", "re-enabled from dashboard")
			} else {
				c.SetStatus("unavailable", reason)
			}
		} else {
			c.Stop()
			c.SetStatus("disabled", "turned off from dashboard")
		}
		// persist per category (categories map 1:1 to collectors here)
		cols := ctx.Cfg.CollectorsCfg()
		if cols == nil {
			cols = map[string]any{}
			ctx.Cfg.Data["collectors"] = cols
		}
		cols[c.Category()] = enabled
	}
	ctx.Cfg.Save()
	return map[string]any{
		"ok":         true,
		"target":     target,
		"enabled":    enabled,
		"collectors": collectorInfos(ctx.Collectors()),
	}
}

// postGrant runs the one-time privileged grant (or revoke) for a target
// ("block" enforcement or "files" tracing) -- loopback only, since it pops
// the platform's elevation dialog on the console session.
func postGrant(ctx *Ctx, w http.ResponseWriter, r *http.Request, target string) {
	if !requestIsLoopback(r) {
		writeJSON(w, 403, map[string]any{"error": "loopback only"})
		return
	}
	body, ok := readBody(r)
	if !ok {
		writeJSON(w, 400, map[string]any{"error": "bad JSON body"})
		return
	}
	action := StrOf(body["action"])
	if action == "" {
		action = "grant"
	}
	if action != "grant" && action != "revoke" {
		writeJSON(w, 400, map[string]any{"error": "action must be grant or revoke"})
		return
	}
	payload, code := Grant(ctx, target, action)
	writeJSON(w, code, payload)
}

func postBlocks(ctx *Ctx, w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(r)
	if !ok {
		writeJSON(w, 400, map[string]any{"error": "bad JSON body"})
		return
	}
	action := StrOf(body["action"])
	enf := ctx.Enforcer
	if enf == nil {
		writeJSON(w, 500, map[string]any{"error": "enforcer unavailable"})
		return
	}
	switch action {
	case "add":
		blockAdd(ctx, enf, body, w)
	case "block", "allow":
		// shorthand: {"action":"allow","type":"ip",…} = add an allow rule
		// (the frontend's {action:"add", …payload} spread would otherwise
		// clobber the dispatcher verb)
		body["rule_action"] = action
		blockAdd(ctx, enf, body, w)
	case "remove":
		bid, rule, found := lookupBlock(ctx, body["id"])
		if !found {
			writeJSON(w, 404, map[string]any{"error": "unknown rule id"})
			return
		}
		status, _ := enf.Unapply(rule)
		ctx.Store.RemoveBlock(bid)
		writeJSON(w, 200, map[string]any{"ok": true, "removed": bid,
			"unenforce_status": status})
	case "reconcile":
		// a freshly installed/updated helper must be re-probed before the
		// rules flow through it again
		enf.ResetHelperProbe()
		applied, err := enf.Reconcile()
		if err != nil {
			writeJSON(w, 500, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "applied": applied})
	case "pause", "resume":
		// global safety valve: lift every enforced rule in one click (a
		// country block or a bad list can cut the machine's own
		// connectivity), then restore with resume. Loopback only — a LAN
		// caller must not be able to disarm the firewall.
		if !requestIsLoopback(r) {
			writeJSON(w, 403, map[string]any{"error": "pause/resume is a local-machine action"})
			return
		}
		if action == "pause" {
			lifted, err := enf.PauseAll()
			if err != nil {
				writeJSON(w, 500, map[string]any{"error": err.Error()})
				return
			}
			writeJSON(w, 200, map[string]any{"ok": true, "paused": true,
				"lifted": lifted})
			return
		}
		applied, err := enf.ResumeAll()
		if err != nil {
			writeJSON(w, 500, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "paused": false,
			"applied": applied})
	default:
		writeJSON(w, 400, map[string]any{"error": "action must be add/remove/reconcile/pause/resume"})
	}
}

// lookupBlock mirrors `str(bid or "").isdigit()` handling: ids may arrive as
// JSON numbers or strings.
func lookupBlock(ctx *Ctx, bidAny any) (int64, *Block, bool) {
	s := StrOf(bidAny)
	if s == "" || s == "<nil>" {
		return 0, nil, false
	}
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0, nil, false
		}
	}
	bid, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, nil, false
	}
	rule, err := ctx.Store.GetBlock(bid)
	if err != nil || rule == nil {
		return 0, nil, false
	}
	return bid, rule, true
}

func blockAdd(ctx *Ctx, enf *Enforcer, body map[string]any, w http.ResponseWriter) {
	rtype := StrOf(body["type"])
	ip := strings.TrimSpace(StrOf(body["ip"]))
	port := strings.TrimSpace(StrOf(body["port"]))
	app := strings.TrimSpace(StrOf(body["app"]))
	pidAny := body["pid"]

	// rule action: "block" (default) or "allow" — an allow rule is an
	// exception that overrides broader block rules for its target. It rides
	// "rule_action" (set by the dispatcher) because "action" is the
	// add/remove/reconcile verb; "action":"allow"/"block" is the shorthand.
	action := StrOf(body["rule_action"])
	if action == "" {
		if a := StrOf(body["action"]); a == "allow" || a == "block" {
			action = a
		}
	}
	if action == "" {
		action = "block"
	}
	if action != "block" && action != "allow" {
		writeJSON(w, 400, map[string]any{"error": "action must be block or allow"})
		return
	}
	// allow rules only make sense as exceptions to block rules, and the
	// application-firewall path has no pass verb — refuse app allows
	if action == "allow" && rtype == "app" {
		writeJSON(w, 400, map[string]any{"error": "allow rules only make sense " +
			"as exceptions to block rules — remove the app block instead"})
		return
	}

	var rule *Block
	switch rtype {
	case "ip":
		if !ValidIP(ip) {
			writeJSON(w, 400, map[string]any{"error": fmt.Sprintf("invalid IPv4: '%s'", ip)})
			return
		}
		// loopback refusal is a block-side guardrail; allowing loopback is
		// a harmless no-op (nothing can block it anyway)
		if action != "allow" && (strings.HasPrefix(ip, "127.") || ip == "::1") {
			writeJSON(w, 400, map[string]any{"error": "refusing to block the loopback " +
				"address (the dashboard)"})
			return
		}
		rule = &Block{Type: "ip", Value: ip}
	case "connection":
		if !ValidIP(ip) {
			writeJSON(w, 400, map[string]any{"error": fmt.Sprintf("invalid IPv4: '%s'", ip)})
			return
		}
		if !allDigits(port) {
			writeJSON(w, 400, map[string]any{"error": fmt.Sprintf("invalid port: '%s'", port)})
			return
		}
		portNum, _ := strconv.Atoi(port)
		if portNum < 1 || portNum > 65535 {
			writeJSON(w, 400, map[string]any{"error": fmt.Sprintf("invalid port: '%s'", port)})
			return
		}
		rule = &Block{Type: "connection", Value: fmt.Sprintf("%s:%s", ip, port)}
	case "app":
		path := app
		if path == "" && Truthy(pidAny) {
			if pid, ok := ToInt(pidAny); ok && allDigits(StrOf(pidAny)) {
				path = ResolveAppPath(pid)
			}
		}
		if path == "" {
			writeJSON(w, 400, map[string]any{"error": "could not resolve the app's " +
				"executable path; enter it manually in the form"})
			return
		}
		rule = &Block{Type: "app", Value: baseNameNoSlash(path), AppPath: &path}
	case "country":
		cc := NormalizeCC(strings.TrimSpace(StrOf(body["cc"])))
		if cc == "" {
			cc = NormalizeCC(ip) // tolerate the generic value field
		}
		if cc == "" {
			writeJSON(w, 400, map[string]any{"error": "invalid country code " +
				"(two-letter ISO 3166-1, e.g. CN)"})
			return
		}
		// guardrail: blocking the machine's own country can cut the
		// user's connectivity — require an explicit UI confirmation
		// (allowing a country only ever permits, so no warning is needed)
		if action == "block" && ctx.Country != nil {
			if own := ctx.Country.OwnCountry(); own != "" && own == cc &&
				!Truthy(body["confirm"]) {
				writeJSON(w, 400, map[string]any{"error": fmt.Sprintf("%s appears "+
					"to be your own country — blocking it can cut your "+
					"connectivity. Confirm the warning to proceed anyway.", cc)})
				return
			}
		}
		rule = &Block{Type: "country", Value: cc}
	case "list":
		path := strings.TrimSpace(StrOf(body["list"]))
		if path == "" && strings.TrimSpace(StrOf(body["list_text"])) != "" {
			// pasted list: persist it under data/blocklists/ so the rule
			// keeps a real file (IPolice's file source reads it too)
			text := strings.TrimSpace(StrOf(body["list_text"]))
			label := SanitizeLabel(StrOf(body["name"]))
			if label == "" {
				label = "uploaded"
			}
			dir := filepath.Join(ctx.Cfg.DataDir(), "blocklists")
			if err := os.MkdirAll(dir, 0o755); err == nil {
				path = filepath.Join(dir, label+".txt")
				if err := os.WriteFile(path, []byte(text+"\n"), 0o600); err != nil {
					path = ""
				}
			}
		}
		if path == "" {
			path = ip // tolerate the generic value field
		}
		if !filepath.IsAbs(path) {
			writeJSON(w, 400, map[string]any{"error": "blocklist file path must " +
				"be absolute (e.g. /path/to/blocklist.txt)"})
			return
		}
		if info, err := os.Stat(path); err != nil || info.IsDir() {
			writeJSON(w, 400, map[string]any{"error": "cannot read the blocklist " +
				"file: " + path})
			return
		}
		cidrs, err := ParseIPFile(path)
		if err != nil {
			writeJSON(w, 400, map[string]any{"error": "cannot parse the " +
				"blocklist file: " + err.Error()})
			return
		}
		if len(cidrs) == 0 {
			writeJSON(w, 400, map[string]any{"error": "no blockable public " +
				"ranges in " + path + " — see sample-blocklist.txt in the " +
				"config scripts folder for the format"})
			return
		}
		label := SanitizeLabel(strings.TrimSuffix(filepath.Base(path),
			filepath.Ext(path)))
		if label == "" {
			label = "blocklist"
		}
		countDetail := fmt.Sprintf("%d ranges parsed at add time", len(cidrs))
		rule = &Block{Type: "list", Value: label, AppPath: &path,
			Detail: &countDetail}
	case "provider":
		name := strings.TrimSpace(StrOf(body["provider"]))
		if name == "" {
			name = ip // tolerate the generic value field
		}
		if name == "" || len(name) > 80 {
			writeJSON(w, 400, map[string]any{"error": "pick a WGrid list " +
				"(provider) to block"})
			return
		}
		rule = &Block{Type: "provider", Value: name}
	default:
		writeJSON(w, 400, map[string]any{"error": "type must be ip, connection, " +
			"country, list, provider or app"})
		return
	}
	appPath := rule.AppPath
	bid, err := ctx.Store.AddBlock(rule.Type, action, rule.Value, appPath, nil)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	rule.ID = bid
	rule.Action = action
	status, detail := enf.Apply(rule)
	ctx.Store.UpdateBlockStatus(bid, status, detail)
	if rule.Type == "country" {
		// warm the CIDR cache while the rule may still be queued, so the
		// panel shows the range count and the grant enforces instantly
		// (both actions read the same cache — blocks and allows alike)
		go ctx.Country.EnsureBackground(rule.Value)
	}
	writeJSON(w, 200, map[string]any{"ok": true, "id": bid, "status": status,
		"detail": detail})
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

// baseNameNoSlash mirrors os.path.basename(path.rstrip("/\\")).
func baseNameNoSlash(path string) string {
	trimmed := strings.TrimRight(path, `/\`)
	if trimmed == "" {
		return ""
	}
	if idx := strings.LastIndexAny(trimmed, `/\`); idx >= 0 {
		return trimmed[idx+1:]
	}
	return trimmed
}

// ResolveAppPath is the best-effort executable path for a pid (used when
// blocking an app).
func ResolveAppPath(pid int) string {
	switch runtime.GOOS {
	case "darwin":
		_, out, _ := Run([]string{"lsof", "-p", strconv.Itoa(pid), "-Fn"}, 8*time.Second)
		var paths []string
		for _, f := range strings.Split(out, "\n") {
			if strings.HasPrefix(f, "n/") && !strings.HasPrefix(f, "n/dev") {
				paths = append(paths, f[1:])
			}
		}
		if len(paths) > 0 {
			return paths[len(paths)-1]
		}
	case "linux":
		if p, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
			return p
		}
		return ""
	case "windows":
		_, out, _ := Run([]string{"powershell.exe", "-NoProfile", "-Command",
			fmt.Sprintf("(Get-Process -Id %d).Path", pid)}, 15*time.Second)
		p := strings.TrimSpace(out)
		return p
	}
	return ""
}

// postDNS drives the DNS shield: start/stop/reload, the system-DNS routing
// toggle (loopback-only — it invokes the privileged pf helper), and domain
// list management.
func postDNS(ctx *Ctx, w http.ResponseWriter, r *http.Request) {
	if ctx.DNSShield == nil {
		writeJSON(w, 500, map[string]any{"error": "dns shield unavailable"})
		return
	}
	data, ok := readBody(r)
	if !ok {
		writeJSON(w, 400, map[string]any{"error": "invalid body"})
		return
	}
	shield := ctx.DNSShield
	switch StrOf(data["action"]) {
	case "start":
		if err := shield.Start(); err != nil {
			writeJSON(w, 500, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "running": true})
	case "stop":
		shield.Stop()
		writeJSON(w, 200, map[string]any{"ok": true, "running": false})
	case "reload":
		shield.Reload()
		writeJSON(w, 200, map[string]any{"ok": true})
	case "route":
		// the toggle invokes the privileged helper — a LAN caller must not
		// reach it (same rule as the elevation dialogs)
		if !requestIsLoopback(r) {
			writeJSON(w, 403, map[string]any{"error": "system DNS routing is a local-machine action"})
			return
		}
		enable := Truthy(data["enabled"])
		if err := shield.RouteSystem(enable); err != nil {
			writeJSON(w, 500, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "routed": shield.Status()["routed"]})
	case "log":
		// opt-in query log: records asked names + resolved IPs in memory
		// only; disabling wipes both. The answer map is what gives the
		// site-visit sessions their exact domain names.
		enabled := Truthy(data["enabled"])
		shield.SetLogEnabled(enabled)
		writeJSON(w, 200, map[string]any{"ok": true, "log_enabled": enabled})
	case "add_list":
		n, err := shield.AddList(StrOf(data["name"]), StrOf(data["text"]))
		if err != nil {
			writeJSON(w, 400, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "domains": n})
	case "remove_list":
		if err := shield.RemoveList(StrOf(data["name"])); err != nil {
			writeJSON(w, 400, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	case "block_domain":
		domain := strings.TrimSpace(StrOf(data["domain"]))
		if err := shield.BlockDomain(domain); err != nil {
			writeJSON(w, 400, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "domain": strings.ToLower(domain)})
	case "unblock_domain":
		domain := strings.TrimSpace(StrOf(data["domain"]))
		if err := shield.UnblockDomain(domain); err != nil {
			writeJSON(w, 400, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "domain": strings.ToLower(domain)})
	case "add_rule":
		// rule_action, not action: the body's top-level action is the API
		// verb (same convention as the firewall's block/allow shorthand)
		id, err := shield.AddRule(StrOf(data["type"]), StrOf(data["rule_action"]),
			StrOf(data["value"]))
		if err != nil {
			writeJSON(w, 400, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "id": id})
	case "remove_rule":
		id, err := strconv.ParseInt(strings.TrimSpace(StrOf(data["id"])), 10, 64)
		if err != nil || id <= 0 {
			writeJSON(w, 400, map[string]any{"ok": false, "error": "rule id must be a positive integer"})
			return
		}
		if err := shield.RemoveRule(id); err != nil {
			writeJSON(w, 400, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		shield.Reload()
		writeJSON(w, 200, map[string]any{"ok": true})
	case "route_mode":
		mode := StrOf(data["mode"])
		if mode != "auto" && mode != "manual" {
			writeJSON(w, 400, map[string]any{"ok": false, "error": "route mode must be auto or manual"})
			return
		}
		shield.SetRouteMode(mode)
		writeJSON(w, 200, map[string]any{"ok": true, "route_mode": shield.RouteMode()})
	default:
		writeJSON(w, 400, map[string]any{"error": "action must be start/stop/reload/route/route_mode/add_rule/remove_rule/add_list/remove_list/block_domain/unblock_domain/log"})
	}
}

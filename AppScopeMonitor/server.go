// Dashboard HTTP server: static UI, REST API, and SSE live event stream
// (mirrors monitor/server.py, stdlib net/http instead of http.server).
package monitor

import (
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
	srv.HTTP = &http.Server{Handler: wrapped}
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
	case "/api/blocks":
		postBlocks(ctx, w, r)
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

func serveStatic(_ *Ctx, w http.ResponseWriter, name string) {
	safe := filepath.Base(name) // no traversal
	if safe == "index.html" || name == "index.html" {
		safe = "index.html"
	}
	if safe == "" || safe == "." || safe == string(filepath.Separator) {
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
	body, err := webFS.ReadFile("web/" + safe)
	if err != nil {
		body, err = os.ReadFile(filepath.Join(webDir, safe))
	}
	if err != nil {
		// Tab/favicon requests hit /favicon.ico by convention; answer with
		// the app icon so browser tabs (and the Windows/macOS app windows)
		// show the AppScope shield.
		if safe == "favicon.ico" {
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
	ct := contentTypes[strings.ToLower(filepath.Ext(safe))]
	if ct == "" {
		ct = "application/octet-stream"
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
		return map[string]any{
			"connections": ctx.Net.Snapshot()["connections"],
			"updated_at":  ctx.Net.UpdatedAt(),
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
		return map[string]any{
			"rules": rules,
			"enforcement": map[string]any{
				"mode": mode, "reason": reason,
				"platform":        PlatformString(),
				"grant_supported": grantable,
			},
		}, 200, nil
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
		applied, err := enf.Reconcile()
		if err != nil {
			writeJSON(w, 500, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "applied": applied})
	default:
		writeJSON(w, 400, map[string]any{"error": "action must be add/remove/reconcile"})
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

	var rule *Block
	switch rtype {
	case "ip":
		if !ValidIP(ip) {
			writeJSON(w, 400, map[string]any{"error": fmt.Sprintf("invalid IPv4: '%s'", ip)})
			return
		}
		if strings.HasPrefix(ip, "127.") || ip == "::1" {
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
	default:
		writeJSON(w, 400, map[string]any{"error": "type must be ip, connection or app"})
		return
	}
	appPath := rule.AppPath
	bid, err := ctx.Store.AddBlock(rule.Type, rule.Value, appPath, nil)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	rule.ID = bid
	status, detail := enf.Apply(rule)
	ctx.Store.UpdateBlockStatus(bid, status, detail)
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

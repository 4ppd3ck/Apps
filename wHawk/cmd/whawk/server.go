package main

// wHawk HTTP API + embedded dashboard. Loopback by default (AppDeck hands
// us APPDECK_HOST); no auth layer beyond loopback + the DNS-rebinding Host
// guard (hostguard.go), matching wTower.

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

//go:embed web
var webFS embed.FS

type Server struct {
	engine     *Engine
	store      *Store
	monitor    *Monitor
	rules      atomic.Pointer[Rules]
	hub        *Hub
	dataDir    string
	exclusions *Exclusions
}

func (s *Server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRoot)
	return mux
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	path := r.URL.Path
	if path == "/" || path == "/index.html" {
		raw, _ := webFS.ReadFile("web/index.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// the dashboard is embedded in the binary; never let a rebuild be
		// masked by a cached copy after the app restarts
		w.Header().Set("Cache-Control", "no-cache")
		w.Write(raw)
		return
	}
	if strings.HasPrefix(path, "/web/") {
		raw, err := webFS.ReadFile(strings.TrimPrefix(path, "/"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		switch {
		case strings.HasSuffix(path, ".js"):
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		case strings.HasSuffix(path, ".css"):
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
		}
		w.Header().Set("Cache-Control", "no-cache")
		w.Write(raw)
		return
	}

	switch path {
	case "/api/status":
		s.json(w, s.apiStatus())
	case "/api/permissions":
		s.json(w, s.exclusions.filterPermissionInventory(permissionInventory()))
	case "/api/exclusions":
		if r.Method == http.MethodPost {
			var req struct {
				App    string `json:"app"`
				Target string `json:"target"`
				Field  string `json:"field"`
				Value  bool   `json:"value"`
				Remove bool   `json:"remove"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil || req.App == "" {
				s.json(w, map[string]any{"error": "app is required"}, 400)
				return
			}
			switch {
			case req.Remove && req.Target != "":
				s.exclusions.RemoveTarget(req.App, req.Target)
			case req.Remove:
				s.exclusions.Remove(req.App)
			case req.Target != "":
				if req.Field == "" {
					s.json(w, map[string]any{"error": "field is required"}, 400)
					return
				}
				s.exclusions.SetTarget(req.App, req.Target, req.Field, req.Value)
			default:
				if req.Field == "" {
					s.json(w, map[string]any{"error": "field is required"}, 400)
					return
				}
				s.exclusions.Set(req.App, req.Field, req.Value)
			}
			// enabling a silencing scope also quiets what is already on
			// the board: its outstanding unacked rows are pre-acked (new
			// findings from watchdog-excluded apps are never recorded
			// anyway; auto-ack apps' findings land acked from now on).
			// This converges state, so rows excluded earlier — before
			// this auto-ack existed — are picked up on the next toggle.
			switch req.Field {
			case "watchdog":
				if req.Value {
					s.store.AckExcluded(s.exclusions.ExcludedByWatchdog)
				}
			case "auto_ack":
				if req.Value {
					s.store.AckExcluded(s.exclusions.ExcludedByAutoAck)
				}
			}
			s.json(w, map[string]any{"ok": true, "exclusions": s.exclusions.List()})
			return
		}
		s.json(w, map[string]any{"exclusions": s.exclusions.List()})
	case "/api/sensitive":
		s.json(w, s.engine.SensitiveSnapshot())
	case "/api/ports":
		ports := s.engine.PortSnapshot()
		up, _, _, _, conns := s.monitor.Snapshot()
		ports.ConnectionsAvailable = up
		if up {
			ports.Connections = portConnectionsFromMonitor(conns)
		} else {
			ports.Connections = []PortConnection{}
		}
		s.json(w, ports)
	case "/api/permissions/remove":
		if r.Method != http.MethodPost {
			s.json(w, map[string]any{"error": "POST required"}, 405)
			return
		}
		var req struct {
			Client, Service string
			Override        bool
		}
		if !s.readJSON(w, r, &req) {
			return
		}
		if req.Client == "" || req.Service == "" {
			s.json(w, map[string]any{"error": "client and service are required"}, 400)
			return
		}
		msg, err := tccRemove(s.dataDir, req.Client, req.Service, req.Override)
		if err != nil {
			s.json(w, map[string]any{"error": FmtErr(err)}, 500)
			return
		}
		s.json(w, map[string]any{"ok": true, "message": msg})
	case "/api/daemon/remove":
		if r.Method != http.MethodPost {
			s.json(w, map[string]any{"error": "POST required"}, 405)
			return
		}
		var req struct {
			Path     string
			Override bool
		}
		if !s.readJSON(w, r, &req) {
			return
		}
		if req.Path == "" {
			s.json(w, map[string]any{"error": "path is required"}, 400)
			return
		}
		msg, err := daemonRemove(req.Path, req.Override)
		if err != nil {
			s.json(w, map[string]any{"error": FmtErr(err)}, 500)
			return
		}
		s.json(w, map[string]any{"ok": true, "message": msg})
	case "/api/firewall/rule":
		if r.Method != http.MethodPost {
			s.json(w, map[string]any{"error": "POST required"}, 405)
			return
		}
		var req struct {
			Action, Dir, Path string
			Override          bool
		}
		if !s.readJSON(w, r, &req) {
			return
		}
		if req.Action == "" || req.Path == "" {
			s.json(w, map[string]any{"error": "action and path are required"}, 400)
			return
		}
		if req.Dir == "" {
			req.Dir = "in"
		}
		msg, err := firewallSetRule(req.Action, req.Dir, req.Path, req.Override)
		if err != nil {
			s.json(w, map[string]any{"error": FmtErr(err)}, 500)
			return
		}
		s.json(w, map[string]any{"ok": true, "message": msg})
	case "/api/alerts":
		if r.Method == http.MethodDelete {
			var req struct {
				ID       int64 `json:"id"`
				AllAcked bool  `json:"allAcked"`
			}
			if !s.readJSON(w, r, &req) {
				return
			}
			removed := s.store.Delete(req.ID, req.AllAcked)
			s.json(w, map[string]any{"ok": true, "removed": removed})
			return
		}
		since, _ := strconv.ParseFloat(r.URL.Query().Get("since"), 64)
		sev := r.URL.Query().Get("severity")
		s.json(w, map[string]any{"alerts": s.store.Alerts(since, sev)})
	case "/api/findings":
		s.json(w, map[string]any{"findings": s.engine.Findings()})
	case "/api/ack":
		if r.Method != http.MethodPost {
			s.json(w, map[string]any{"error": "POST required"}, 405)
			return
		}
		var req struct {
			ID  int64 `json:"id"`
			All bool  `json:"all"`
		}
		if !s.readJSON(w, r, &req) {
			return
		}
		s.store.Ack(req.ID, req.All)
		s.json(w, map[string]any{"ok": true})
	case "/api/rules":
		if r.Method == http.MethodPost {
			var overlay Rules
			if !s.readJSON(w, r, &overlay) {
				return
			}
			if err := SaveJSON(s.dataDir+"/rules.user.json", &overlay); err != nil {
				s.json(w, map[string]any{"error": FmtErr(err)}, 500)
				return
			}
			// atomic swap: scans keep running against the old snapshot while
			// LoadRules reads the file, then every reader sees the new set
			s.rules.Store(LoadRules(s.dataDir))
			s.json(w, map[string]any{"ok": true, "rules": s.rules.Load()})
			return
		}
		s.json(w, s.rules.Load())
	case "/api/baseline":
		if r.Method == http.MethodPost {
			s.store.BaselineReset()
			s.json(w, map[string]any{"ok": true})
			return
		}
		s.json(w, s.store.BaselineList())
	case "/api/monitor":
		s.json(w, s.monitor.Summary())
	case "/api/wtower/block":
		// user-initiated remediation: queue a block rule for this IP in
		// wTower ("wHawk finds it, you approve, AppScope cuts
		// it"). The monitor re-validates everything and its own guardrails
		// still apply; the same protected-range filter here keeps obviously
		// dangerous targets (your router, the LAN, loopback) from ever
		// reaching it.
		if r.Method != http.MethodPost {
			s.json(w, map[string]any{"error": "POST required"}, 405)
			return
		}
		var req struct {
			IP string `json:"ip"`
		}
		if !s.readJSON(w, r, &req) {
			return
		}
		ip := strings.TrimSpace(req.IP)
		if !blockableRemoteIP(ip) {
			s.json(w, map[string]any{"error": "not a blockable public IPv4: " + ip}, 400)
			return
		}
		out, err := s.monitor.BlockIP(ip)
		if err != nil {
			s.json(w, map[string]any{
				"error": FmtErr(err),
				"hint":  "is wTower running? Its dashboard can block this IP directly",
			}, 502)
			return
		}
		s.json(w, map[string]any{"ok": true, "ip": ip, "monitor": out})
	case "/api/scan":
		if r.Method == http.MethodPost {
			s.engine.TriggerManualScan()
			s.json(w, map[string]any{"ok": true})
			return
		}
		s.json(w, map[string]any{"error": "POST required"}, 405)
	case "/api/export":
		alerts := s.store.Alerts(0, "")
		raw, _ := json.MarshalIndent(alerts, "", "  ")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition",
			"attachment; filename=whawk-alerts-"+time.Now().Format("20060102-150405")+".json")
		w.Write(raw)
	case "/api/events":
		// structured log export: every alert as one JSON line (JSONL/ndjson),
		// oldest first, ready for jq / SIEMs / scripts. ?since_id=N returns
		// only newer alerts, so incremental pulls stay cheap.
		sinceID := int64(0)
		if v, err := strconv.ParseInt(r.URL.Query().Get("since_id"), 10, 64); err == nil && v > 0 {
			sinceID = v
		}
		alerts := s.store.Alerts(0, "") // newest-first; walk backwards
		w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
		w.Header().Set("Content-Disposition",
			"attachment; filename=whawk-events-"+time.Now().Format("20060102-150405")+".jsonl")
		enc := json.NewEncoder(w)
		for i := len(alerts) - 1; i >= 0; i-- {
			a := alerts[i]
			if a.ID <= sinceID {
				continue
			}
			_ = enc.Encode(a)
		}
	case "/api/stream":
		s.serveSSE(w, r)
	default:
		s.json(w, map[string]any{"error": "not found"}, 404)
	}
}

func (s *Server) apiStatus() map[string]any {
	status := s.engine.Status()
	status["version"] = Version // peers (wGrid's wiring page) detect drift
	st := s.store.Summary()
	status["alerts"] = st
	status["wtower"] = s.monitor.Summary()
	status["data_dir"] = s.dataDir
	return status
}

// readJSON decodes a small JSON request body into v (1 MiB cap) and answers
// the request itself when it does not parse; false means "response sent".
func (s *Server) readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(v); err != nil {
		s.json(w, map[string]any{"error": "invalid JSON body"}, 400)
		return false
	}
	return true
}

func (s *Server) json(w http.ResponseWriter, v any, code ...int) {
	raw, err := json.Marshal(v)
	if err != nil {
		http.Error(w, FmtErr(err), 500)
		return
	}
	// before WriteHeader: after it, net/http silently drops the header and
	// error bodies go out as text/plain
	w.Header().Set("Content-Type", "application/json")
	if len(code) > 0 {
		w.WriteHeader(code[0])
	}
	w.Write(raw)
}

func (s *Server) serveSSE(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(200)
	flusher, ok := w.(http.Flusher)
	if !ok {
		return
	}
	q := s.hub.Subscribe()
	defer s.hub.Unsubscribe(q)
	fmt.Fprint(w, "retry: 3000\n\n")
	flusher.Flush()
	for {
		select {
		case payload := <-q:
			if _, err := fmt.Fprintf(w, "data: %s\n\n", payload); err != nil {
				return
			}
			flusher.Flush()
		case <-time.After(15 * time.Second):
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

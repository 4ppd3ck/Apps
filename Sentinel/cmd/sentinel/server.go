package main

// Sentinel HTTP API + embedded dashboard. Loopback by default (AppDeck hands
// us APPDECK_HOST); no auth layer beyond loopback + the DNS-rebinding Host
// guard (hostguard.go), matching AppScope Monitor.

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed web
var webFS embed.FS

type Server struct {
	engine     *Engine
	store      *Store
	monitor    *Monitor
	rules      *Rules
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
			body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			var req struct {
				App    string `json:"app"`
				Target string `json:"target"`
				Field  string `json:"field"`
				Value  bool   `json:"value"`
				Remove bool   `json:"remove"`
			}
			if err := json.Unmarshal(body, &req); err != nil || req.App == "" {
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
	case "/api/permissions/remove":
		if r.Method != http.MethodPost {
			s.json(w, map[string]any{"error": "POST required"}, 405)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		var req struct {
			Client, Service string
			Override        bool
		}
		if err := json.Unmarshal(body, &req); err != nil {
			s.json(w, map[string]any{"error": "invalid JSON body"}, 400)
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
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		var req struct {
			Path     string
			Override bool
		}
		if err := json.Unmarshal(body, &req); err != nil {
			s.json(w, map[string]any{"error": "invalid JSON body"}, 400)
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
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		var req struct {
			Action, Dir, Path string
			Override          bool
		}
		if err := json.Unmarshal(body, &req); err != nil {
			s.json(w, map[string]any{"error": "invalid JSON body"}, 400)
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
			body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			var req struct {
				ID       int64 `json:"id"`
				AllAcked bool  `json:"allAcked"`
			}
			if err := json.Unmarshal(body, &req); err != nil {
				s.json(w, map[string]any{"error": "invalid JSON body"}, 400)
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
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		var req struct {
			ID  int64 `json:"id"`
			All bool  `json:"all"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			s.json(w, map[string]any{"error": "invalid JSON body"}, 400)
			return
		}
		s.store.Ack(req.ID, req.All)
		s.json(w, map[string]any{"ok": true})
	case "/api/rules":
		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			var overlay Rules
			if err := json.Unmarshal(body, &overlay); err != nil {
				s.json(w, map[string]any{"error": FmtErr(err)}, 400)
				return
			}
			if err := SaveJSON(s.dataDir+"/rules.user.json", &overlay); err != nil {
				s.json(w, map[string]any{"error": FmtErr(err)}, 500)
				return
			}
			*s.rules = *LoadRules(s.dataDir)
			s.json(w, map[string]any{"ok": true, "rules": s.rules})
			return
		}
		s.json(w, s.rules)
	case "/api/baseline":
		if r.Method == http.MethodPost {
			s.store.BaselineReset()
			s.json(w, map[string]any{"ok": true})
			return
		}
		s.json(w, s.store.BaselineList())
	case "/api/monitor":
		s.json(w, s.monitor.Summary())
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
			"attachment; filename=sentinel-alerts-"+time.Now().Format("20060102-150405")+".json")
		w.Write(raw)
	case "/api/stream":
		s.serveSSE(w, r)
	default:
		s.json(w, map[string]any{"error": "not found"}, 404)
	}
}

func (s *Server) apiStatus() map[string]any {
	status := s.engine.Status()
	status["version"] = Version // peers (IPolice's wiring page) detect drift
	st := s.store.Summary()
	status["alerts"] = st
	status["monitor"] = s.monitor.Summary()
	status["data_dir"] = s.dataDir
	return status
}

func (s *Server) json(w http.ResponseWriter, v any, code ...int) {
	raw, err := json.Marshal(v)
	if err != nil {
		http.Error(w, FmtErr(err), 500)
		return
	}
	if len(code) > 0 {
		w.WriteHeader(code[0])
	}
	w.Header().Set("Content-Type", "application/json")
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

// sortedKeys is only used by tests / debugging output.
func sortedKeys[V any](m map[string]V) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

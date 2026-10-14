package main

// Sentinel HTTP API + embedded dashboard. Loopback by default (AppDeck hands
// us APPDECK_HOST); no auth layer beyond loopback, matching AppScope Monitor.

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
	engine  *Engine
	store   *Store
	monitor *Monitor
	rules   *Rules
	hub     *Hub
	dataDir string
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
		w.Write(raw)
		return
	}

	switch path {
	case "/api/status":
		s.json(w, s.apiStatus())
	case "/api/alerts":
		if r.Method == http.MethodDelete {
			body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			var req struct {
				ID       int64 `json:"id"`
				AllAcked bool  `json:"allAcked"`
			}
			_ = json.Unmarshal(body, &req)
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
		_ = json.Unmarshal(body, &req)
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

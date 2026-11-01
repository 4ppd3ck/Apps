package main

// Loopback HTTP API + embedded status page. The contract Sentinel consumes:
//
//	GET  /api/networks      {providers: [{name, cidrs, updated_at, origin}]}
//	GET  /api/intel?ip=     {known, provider}
//	GET  /api/status
//	POST /api/refresh
//
// Dashboard-only endpoints:
//
//	GET  /api/sources              effective sources with default/error flags
//	POST /api/sources/add          add + persist a source, then refresh
//	POST /api/sources/delete       remove a source (and its orphaned provider)
//	GET  /api/apps                 installed apps via Descale, matched to the catalog

import (
	"embed"
	"encoding/json"
	"io"
	"net/http"
)

//go:embed web
var webFS embed.FS

type Server struct {
	intel   *Intel
	descale *wPurgeClient
	wired   *Wired
}

func (s *Server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handle)
	return mux
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	switch r.URL.Path {
	case "/", "/index.html":
		raw, _ := webFS.ReadFile("web/index.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(raw)
	case "/api/networks":
		s.json(w, map[string]any{"providers": s.intel.Cache().Providers})
	case "/api/intel":
		provider, known := s.intel.Lookup(r.URL.Query().Get("ip"))
		s.json(w, map[string]any{"known": known, "provider": provider})
	case "/api/status":
		st := s.intel.Status()
		st["version"] = Version // Sentinel/wiring pages detect drift
		s.json(w, st)
	case "/api/refresh":
		if r.Method != http.MethodPost {
			s.json(w, map[string]any{"error": "POST required"}, 405)
			return
		}
		go s.intel.Refresh()
		s.json(w, map[string]any{"ok": true, "message": "refreshing in the background"})
	case "/api/sources":
		if r.Method != http.MethodGet {
			s.json(w, map[string]any{"error": "GET required"}, 405)
			return
		}
		s.json(w, map[string]any{"sources": s.intel.SourceViews()})
	case "/api/sources/add":
		var src Source
		if !s.decodeBody(w, r, &src) {
			return
		}
		if err := s.intel.AddSource(src); err != nil {
			s.json(w, map[string]any{"error": FmtErr(err)}, 400)
			return
		}
		go s.intel.Refresh()
		s.json(w, map[string]any{"ok": true, "message": "added — fetching in the background"})
	case "/api/sources/delete":
		var src Source
		if !s.decodeBody(w, r, &src) {
			return
		}
		if err := s.intel.RemoveSource(src); err != nil {
			s.json(w, map[string]any{"error": FmtErr(err)}, 400)
			return
		}
		s.json(w, map[string]any{"ok": true, "message": "removed"})
	case "/api/wired":
		if r.Method != http.MethodGet {
			s.json(w, map[string]any{"error": "GET required"}, 405)
			return
		}
		s.json(w, s.wired.Status())
	case "/api/apps":
		if r.Method != http.MethodGet {
			s.json(w, map[string]any{"error": "GET required"}, 405)
			return
		}
		s.handleApps(w, r)
	default:
		s.json(w, map[string]any{"error": "not found"}, 404)
	}
}

// decodeBody enforces POST and decodes a small JSON body into v.
func (s *Server) decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.Method != http.MethodPost {
		s.json(w, map[string]any{"error": "POST required"}, 405)
		return false
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil || json.Unmarshal(raw, v) != nil {
		s.json(w, map[string]any{"error": "invalid JSON body"}, 400)
		return false
	}
	return true
}

// handleApps joins wPurge's installed-apps inventory with the catalog.
func (s *Server) handleApps(w http.ResponseWriter, r *http.Request) {
	apps, err := s.descale.Apps(r.URL.Query().Get("force") == "1")
	if err != nil {
		s.json(w, map[string]any{"reachable": false, "error": FmtErr(err)})
		return
	}
	entries, unmatched := s.intel.MatchCatalog(apps)
	s.json(w, map[string]any{
		"reachable":  true,
		"apps_count": len(apps),
		"entries":    entries,
		"unmatched":  unmatched,
	})
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

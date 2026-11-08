package main

// The feed's HTTP API — the original wGrid surface, unchanged in shape so
// every consumer keeps working: wTower's country-block source probes
// GET /api/networks (the relocation signature), wHawk's Intel client polls
// the same endpoint, and the dashboard drives the rest. Everything rides
// the hostGuard + tokenFence wrappers (main.go): GETs stay LAN-open,
// non-loopback POSTs need X-AppDeck-Token when APPDECK_TOKEN is set.
//
//	GET  /api/status          feed fields (providers, networks, updated_at, …)
//	GET  /api/networks        {providers:[…]} — the probe signature
//	GET  /api/intel?ip=       {known, provider}
//	POST /api/refresh         background feed refresh
//	GET  /api/sources         effective sources
//	POST /api/sources/add     add + persist a source, then refresh
//	POST /api/sources/delete  remove a source
//	GET  /api/wired           peer status (wPurge, wHawk)
//	GET  /api/apps            installed apps via wPurge, matched to catalog

import (
	"encoding/json"
	"net/http"
)

func (s *server) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.feed.Status())
}

func (s *server) handleNetworks(w http.ResponseWriter, r *http.Request) {
	// Providers is always a non-nil slice (never marshals as JSON null): a
	// consumer probing {"providers":[…]} must see a valid array even before
	// the first refresh populates it.
	writeJSON(w, http.StatusOK, map[string]any{"providers": s.feed.Cache().Providers})
}

func (s *server) handleIntelLookup(w http.ResponseWriter, r *http.Request) {
	provider, known := s.feed.Lookup(r.URL.Query().Get("ip"))
	writeJSON(w, http.StatusOK, map[string]any{"known": known, "provider": provider})
}

func (s *server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	go s.feed.Refresh()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "refreshing in the background"})
}

func (s *server) handleSources(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"sources": s.feed.SourceViews()})
}

// handleWired reports the peers' reachability.
func (s *server) handleWired(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{}
	for k, v := range s.wired.Status() {
		out[k] = v
	}
	writeJSON(w, http.StatusOK, out)
}

// handleApps joins wPurge's installed-apps inventory with the vendor catalog.
func (s *server) handleApps(w http.ResponseWriter, r *http.Request) {
	apps, err := s.purge.Apps(r.URL.Query().Get("force") == "1")
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"reachable": false, "error": FmtErr(err)})
		return
	}
	entries, unmatched := s.feed.MatchCatalog(apps)
	writeJSON(w, http.StatusOK, map[string]any{
		"reachable":  true,
		"apps_count": len(apps),
		"entries":    entries,
		"unmatched":  unmatched,
	})
}

// handleSourceAdd adds + persists an intel source, then refreshes.
func (s *server) handleSourceAdd(w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	raw, _ := json.Marshal(body)
	var src Source
	if err := json.Unmarshal(raw, &src); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON body"})
		return
	}
	if err := s.feed.AddSource(src); err != nil {
		writeJSON(w, 400, map[string]any{"error": FmtErr(err)})
		return
	}
	go s.feed.Refresh()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "added — fetching in the background"})
}

// handleSourceDelete removes an intel source.
func (s *server) handleSourceDelete(w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	raw, _ := json.Marshal(body)
	var src Source
	if err := json.Unmarshal(raw, &src); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON body"})
		return
	}
	if err := s.feed.RemoveSource(src); err != nil {
		writeJSON(w, 400, map[string]any{"error": FmtErr(err)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "removed"})
}

// readBody decodes the request's JSON object body (1 MiB cap).
func readBody(w http.ResponseWriter, r *http.Request) (map[string]any, bool) {
	var body map[string]any
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]any{"error": "bad request body"})
		return nil, false
	}
	return body, true
}

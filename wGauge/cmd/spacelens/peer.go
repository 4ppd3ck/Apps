package main

// Peer discovery for the 🧹 Hand to Clean flow: wPurge (the guarded cleanup
// app) is found through the launcher's /api/apps registry — the same port
// book every w-family peer reads — with the WPURGE_URL env as the manual
// override and wPurge's pinned port as the fallback. Browsing here stays
// read-only; wPurge's token-fenced, guardrailed endpoints do all the
// destructive work when the operator gets there.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// wPurgeDefaultURL is wPurge's pinned port (Apps/wPurge/app.json); only
// used when neither the launcher registry nor WPURGE_URL answer.
const wPurgeDefaultURL = "http://127.0.0.1:8212"

func (s *server) handlePeer(w http.ResponseWriter, r *http.Request) {
	s.json(w, map[string]string{"url": wPurgeURL()})
}

func wPurgeURL() string {
	if v := strings.TrimSpace(os.Getenv("WPURGE_URL")); v != "" {
		return strings.TrimRight(v, "/")
	}
	if u := discoverPeerURL(launcherURL(), "wpurge"); u != "" {
		return u
	}
	return wPurgeDefaultURL
}

// launcherDefaultURL is the AppDeck dashboard, whose /api/apps registry is
// the authoritative port book for launcher-spawned peers.
const launcherDefaultURL = "http://127.0.0.1:9090"

// launcherURL is the AppDeck dashboard base: APPDECK_LAUNCHER_URL when the
// launcher injected it, the well-known default otherwise.
func launcherURL() string {
	if v := os.Getenv("APPDECK_LAUNCHER_URL"); v != "" {
		return strings.TrimRight(v, "/")
	}
	return launcherDefaultURL
}

// discoverPeerURL asks the launcher's /api/apps registry where the app with
// the given id currently serves ("" when unreachable or not listed).
func discoverPeerURL(launcher, id string) string {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(launcher + "/api/apps")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var apps []struct {
		ID   string `json:"id"`
		Port int    `json:"port"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&apps) != nil {
		return ""
	}
	for _, a := range apps {
		if a.ID == id && a.Port != 0 {
			return fmt.Sprintf("http://127.0.0.1:%d", a.Port)
		}
	}
	return ""
}

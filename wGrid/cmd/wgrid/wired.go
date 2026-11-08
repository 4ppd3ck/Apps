package main

// Live status of the peers the intel feed pairs with — wPurge (the
// installed-apps inventory behind /api/apps and the Intel Sources view's
// app scan) and wHawk (the watchdog whose net checks consume the feed).
// Ported from the former wGrid app; the merged-apps detour is undone, so
// every peer is a separate launcher-spawned app again. Discovery prefers
// the AppDeck launcher's registry (dynamic ports); without a reachable
// launcher it falls back to the configured/fixed URL.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// launcherDefaultURL is shared with util.go (the AppDeck dashboard, whose
// /api/apps registry is the authoritative port book).

type Peer struct {
	Name    string `json:"name"`
	Running bool   `json:"running"`
	URL     string `json:"url,omitempty"`
	Error   string `json:"error,omitempty"`
}

type Wired struct {
	hc *http.Client

	launcherURL string
	wpurgeURL   string

	mu  sync.Mutex
	at  float64
	out map[string]Peer
}

func NewWired(launcherURL, wpurgeURL string) *Wired {
	return &Wired{
		hc:          &http.Client{Timeout: 3 * time.Second},
		launcherURL: strings.TrimRight(launcherURL, "/"),
		wpurgeURL:   strings.TrimRight(wpurgeURL, "/"),
	}
}

// Status reports wPurge reachability, cached ~10 s so dashboard polls stay
// cheap. A peer counts as running when its loopback API answers.
func (w *Wired) Status() map[string]Peer {
	w.mu.Lock()
	if w.out != nil && Now()-w.at < 10 {
		out := w.out
		w.mu.Unlock()
		return out
	}
	w.mu.Unlock()

	descURL := w.wpurgeURL
	whawkURL := os.Getenv("WHAWK_URL")
	apps, lerr := w.launcherApps()
	if lerr == nil {
		if u := appURL(apps, "wpurge"); u != "" {
			descURL = u
		}
		if u := appURL(apps, "whawk"); u != "" {
			whawkURL = u
		}
	}
	out := map[string]Peer{
		"wpurge": probe(w.hc, "wPurge", descURL, "/api/info"),
	}
	// wHawk (the standalone original restored from the merge) serves its
	// engine status at the flat /api/status — there is no /api/watchdog/*
	// namespace on it.
	if whawkURL != "" {
		out["whawk"] = probe(w.hc, "wHawk", whawkURL, "/api/status")
	}
	w.mu.Lock()
	w.out, w.at = out, Now()
	w.mu.Unlock()
	return out
}

type launcherApp struct {
	ID      string `json:"id"`
	Port    int    `json:"port"`
	Running bool   `json:"running"`
}

func (w *Wired) launcherApps() ([]launcherApp, error) {
	resp, err := w.hc.Get(w.launcherURL + "/api/apps")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("launcher -> HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	var apps []launcherApp
	if err := json.Unmarshal(raw, &apps); err != nil {
		return nil, err
	}
	return apps, nil
}

func appURL(apps []launcherApp, id string) string {
	for _, a := range apps {
		if a.ID == id && a.Port != 0 {
			return fmt.Sprintf("http://127.0.0.1:%d", a.Port)
		}
	}
	return ""
}

func probe(hc *http.Client, name, base, path string) Peer {
	if base == "" {
		return Peer{Name: name, Error: "no url configured"}
	}
	resp, err := hc.Get(base + path)
	if err != nil {
		return Peer{Name: name, URL: base, Error: err.Error()}
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Peer{Name: name, URL: base, Error: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	}
	return Peer{Name: name, Running: true, URL: base}
}

package main

// Live status of the two apps IPolice pairs with — Sentinel (the consumer of
// this intel) and Descale (the installed-apps inventory). Discovery prefers
// the AppDeck launcher's registry (dynamic ports); without a reachable
// launcher it falls back to the configured/fixed URLs.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const launcherDefaultURL = "http://127.0.0.1:9090"

type Peer struct {
	Name    string `json:"name"`
	Running bool   `json:"running"`
	URL     string `json:"url,omitempty"`
	Error   string `json:"error,omitempty"`
}

type Wired struct {
	hc *http.Client

	launcherURL string
	whawkURL string
	wpurgeURL  string

	mu  sync.Mutex
	at  float64
	out map[string]Peer
}

func NewWired(launcherURL, whawkURL, wpurgeURL string) *Wired {
	return &Wired{
		hc:          &http.Client{Timeout: 3 * time.Second},
		launcherURL: strings.TrimRight(launcherURL, "/"),
		whawkURL: strings.TrimRight(whawkURL, "/"),
		wpurgeURL:  strings.TrimRight(wpurgeURL, "/"),
	}
}

// Status reports wHawk/wPurge reachability, cached ~10 s so dashboard
// polls stay cheap. A peer counts as running when its loopback API answers.
func (w *Wired) Status() map[string]Peer {
	w.mu.Lock()
	if w.out != nil && NowF()-w.at < 10 {
		out := w.out
		w.mu.Unlock()
		return out
	}
	w.mu.Unlock()

	sentURL, descURL := w.whawkURL, w.wpurgeURL
	if apps, err := w.launcherApps(); err == nil {
		if u := appURL(apps, "whawk"); u != "" {
			sentURL = u
		}
		if u := appURL(apps, "wpurge"); u != "" {
			descURL = u
		}
	}
	out := map[string]Peer{
		"whawk":  probe(w.hc, "wHawk", sentURL, "/api/status"),
		"wpurge": probe(w.hc, "wPurge", descURL, "/api/info"),
	}
	w.mu.Lock()
	w.out, w.at = out, NowF()
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

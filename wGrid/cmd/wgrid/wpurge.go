package main

// Loopback client for wPurge's installed-apps inventory. wPurge computes
// the list live from the OS (see its apps.go), so wGrid polls it and keeps
// a short-lived cache instead of persisting anything.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	wpurgeDefaultURL  = "http://127.0.0.1:8212"
	whawkDefaultURL = "http://127.0.0.1:8899"
)

// wPurgeApp mirrors wPurge's GET /api/apps entries.
type wPurgeApp struct {
	Path    string `json:"path"`
	Name    string `json:"name"`
	ID      string `json:"id"`
	Version string `json:"version"`
	Kind    string `json:"kind,omitempty"`
	Running bool   `json:"running"`
}

type wPurgeClient struct {
	base string
	hc   *http.Client

	mu   sync.Mutex
	apps []wPurgeApp
	at   float64
}

func NewwPurgeClient(base string) *wPurgeClient {
	if strings.TrimSpace(base) == "" {
		base = wpurgeDefaultURL
	}
	return &wPurgeClient{
		base: strings.TrimRight(base, "/"),
		hc:   &http.Client{Timeout: 5 * time.Second},
	}
}

// Apps returns wPurge's installed apps, cached for a minute unless force.
// Failures are never cached — the dashboard can retry immediately.
func (d *wPurgeClient) Apps(force bool) ([]wPurgeApp, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !force && d.apps != nil && NowF()-d.at < 60 {
		return d.apps, nil
	}
	d.apps = nil
	resp, err := d.hc.Get(d.base + "/api/apps")
	if err != nil {
		return nil, fmt.Errorf("wpurge at %s: %w", d.base, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wpurge /api/apps -> HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	var out struct {
		Apps []wPurgeApp `json:"apps"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("wpurge response: %w", err)
	}
	d.apps, d.at = out.Apps, NowF()
	return d.apps, nil
}

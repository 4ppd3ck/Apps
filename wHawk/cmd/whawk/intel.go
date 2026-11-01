package main

// Client for IPolice, the optional known-IP intelligence companion app.
// Sentinel never fetches from the internet itself — it bulk-loads provider
// network tables from IPolice over loopback (mirroring the AppScope Monitor
// client in integ.go) and consults them when classifying endpoints.
//
// Modes (rules.intel_match) govern what a known match means for alerts; see
// rules.go. With IPolice offline everything behaves exactly as before.

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

type intelProvider struct {
	Name      string   `json:"name"`
	Cidrs     []string `json:"cidrs"`
	UpdatedAt float64  `json:"updated_at"`
	Origin    string   `json:"origin"`
}

type Intel struct {
	baseURL string
	hc      *http.Client
	mu      sync.Mutex

	up      bool
	lastErr string
	lastTry float64
	updated float64
	nets    map[string][]*net.IPNet // provider -> parsed networks
	// providers lists names in a stable order for display
	providers []string
	count     int
}

func NewIntel(baseURL string) *Intel {
	return &Intel{
		baseURL: trimRight(baseURL, "/"),
		hc:      &http.Client{Timeout: 6 * time.Second},
		nets:    map[string][]*net.IPNet{},
	}
}

func trimRight(s, cut string) string {
	for len(s) > 0 && s[len(s)-len(cut):] == cut {
		s = s[:len(s)-len(cut)]
	}
	return s
}

// RetryIfDown re-polls after a failed attempt once minGap seconds passed —
// IPolice may simply be starting up (Sentinel's first poll can race its
// bind). Once up, slow-tick polls keep the tables fresh.
func (it *Intel) RetryIfDown(minGap float64) {
	it.mu.Lock()
	if it.up || NowF()-it.lastTry < minGap {
		it.mu.Unlock()
		return
	}
	it.mu.Unlock()
	it.Poll()
}

// Poll refreshes the provider tables from IPolice. Called on the slow tick;
// offline IPolice keeps the last good tables in memory.
func (it *Intel) Poll() {
	it.mu.Lock()
	it.lastTry = NowF()
	it.mu.Unlock()

	resp, err := it.hc.Get(it.baseURL + "/api/networks")
	if err != nil {
		it.mu.Lock()
		it.up = false
		it.lastErr = FmtErr(err)
		it.mu.Unlock()
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		it.mu.Lock()
		it.up = false
		it.lastErr = fmt.Sprintf("/api/networks -> %d", resp.StatusCode)
		it.mu.Unlock()
		return
	}
	var payload struct {
		Providers []intelProvider `json:"providers"`
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, 32<<20))
	if err := dec.Decode(&payload); err != nil {
		it.mu.Lock()
		it.up = false
		it.lastErr = FmtErr(err)
		it.mu.Unlock()
		return
	}

	nets := map[string][]*net.IPNet{}
	names := []string{}
	count := 0
	updated := float64(0)
	for _, p := range payload.Providers {
		if p.Name == "" {
			continue
		}
		for _, c := range p.Cidrs {
			if _, n, err := net.ParseCIDR(c); err == nil {
				nets[p.Name] = append(nets[p.Name], n)
				count++
			}
		}
		if len(nets[p.Name]) > 0 {
			names = append(names, p.Name)
		}
		if p.UpdatedAt > updated {
			updated = p.UpdatedAt
		}
	}
	it.mu.Lock()
	it.up = true
	it.lastErr = ""
	it.updated = updated
	it.nets = nets
	it.providers = names
	it.count = count
	it.mu.Unlock()
}

// Lookup reports the provider whose range contains ip. Offline or unknown →
// ("", false); errors never surface (intel must never break a check).
func (it *Intel) Lookup(ipStr string) (string, bool) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", false
	}
	it.mu.Lock()
	defer it.mu.Unlock()
	for name, nets := range it.nets {
		for _, n := range nets {
			if n.Contains(ip) {
				return name, true
			}
		}
	}
	return "", false
}

// IntelMode normalizes rules.intel_match: "" (unset) and "label" behave the
// same; unknown values fail safe to "off" (never silence on a typo).
func (r *Rules) IntelMode() string {
	switch r.IntelMatch {
	case "", "label":
		return "label"
	case "suppress", "autoack":
		return r.IntelMatch
	default:
		return "off"
	}
}

// KnownRemote is the nil-safe correlation lookup used by the exfil and
// sensitive checks: ("Google & YouTube", true) for a known range, ("", false)
// otherwise. A nil Intel (IPolice disabled) is simply never-known.
func (it *Intel) KnownRemote(ipStr string) (string, bool) {
	if it == nil {
		return "", false
	}
	return it.Lookup(ipStr)
}

func (it *Intel) Snapshot() (up bool, lastErr string, updated float64, providers []string, networks int) {
	it.mu.Lock()
	defer it.mu.Unlock()
	return it.up, it.lastErr, it.updated, append([]string(nil), it.providers...), it.count
}

func (it *Intel) Summary() map[string]any {
	up, lastErr, updated, providers, networks := it.Snapshot()
	return map[string]any{
		"url":        it.baseURL,
		"up":         up,
		"last_error": lastErr,
		"updated_at": updated,
		"providers":  providers,
		"networks":   networks,
	}
}

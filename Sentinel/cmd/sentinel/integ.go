package main

// Client for AppScope Monitor (the "appscan" source). Sentinel keeps its own
// host checks running even when the monitor is offline; monitor data adds
// event correlation (camera/mic/file + connections) and a live connection
// table with per-app attribution.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type MonitorEvent struct {
	ID        int64   `json:"id"`
	Ts        float64 `json:"ts"`
	Category  string  `json:"category"`
	Kind      string  `json:"kind"`
	App       any     `json:"app"`
	Pid       any     `json:"pid"`
	User      any     `json:"user"`
	Device    any     `json:"device"`
	Path      any     `json:"path"`
	Remote    any     `json:"remote"`
	Local     any     `json:"local"`
	Proto     any     `json:"proto"`
	Direction any     `json:"direction"`
	Detail    any     `json:"detail"`
}

type MonitorConn struct {
	App        string `json:"app"`
	Pid        any    `json:"pid"`
	Proto      string `json:"proto"`
	State      string `json:"state"`
	LocalIP    string `json:"local_ip"`
	LocalPort  any    `json:"local_port"`
	RemoteIP   string `json:"remote_ip"`
	RemotePort any    `json:"remote_port"`
	Scope      string `json:"scope"`
	Service    string `json:"service"`
	Direction  string `json:"direction"`
	Host       string `json:"host"`
}

func (c *MonitorConn) RemotePortInt() int { return AnyInt(c.RemotePort) }
func (c *MonitorConn) LocalPortInt() int  { return AnyInt(c.LocalPort) }

func AnyInt(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case int64:
		return int(n)
	case string:
		var i int
		fmt.Sscanf(n, "%d", &i)
		return i
	}
	return 0
}

// Monitor wraps a polling client against the AppScope Monitor HTTP API.
type Monitor struct {
	baseURL string
	hc      *http.Client
	mu      sync.Mutex

	up        bool
	lastErr   string
	lastPoll  float64
	platform  string
	events    []MonitorEvent // ring of recent events (last ~15 min)
	conns     []MonitorConn
	lastSince float64
}

func NewMonitor(baseURL string) *Monitor {
	return &Monitor{
		baseURL: strings.TrimRight(baseURL, "/"),
		hc:      &http.Client{Timeout: 4 * time.Second},
	}
}

func (m *Monitor) get(path string, out any) error {
	resp, err := m.hc.Get(m.baseURL + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("monitor %s -> %d", path, resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

// Poll refreshes events + connections. Cheap enough for the fast tick.
func (m *Monitor) Poll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := NowF()

	// connections
	var cs struct {
		Connections []MonitorConn `json:"connections"`
		UpdatedAt   float64       `json:"updated_at"`
	}
	if err := m.get("/api/connections", &cs); err != nil {
		m.up = false
		m.lastErr = FmtErr(err)
		return
	}
	m.up = true
	m.lastErr = ""
	m.lastPoll = now
	if cs.Connections != nil {
		m.conns = cs.Connections
	}

	// events since the last cursor (with a small overlap window)
	var es struct {
		Events []MonitorEvent `json:"events"`
	}
	path := fmt.Sprintf("/api/events?since=%.0f&limit=500", m.lastSince-30)
	if err := m.get(path, &es); err != nil {
		return // connections still worked; events are best-effort
	}
	m.lastSince = now
	if len(es.Events) > 0 {
		m.events = append(m.events, es.Events...)
	}
	cut := now - 15*60
	keep := m.events[:0]
	for _, e := range m.events {
		if e.Ts >= cut {
			keep = append(keep, e)
		}
	}
	m.events = keep
}

func (m *Monitor) Snapshot() (up bool, lastErr string, lastPoll float64,
	events []MonitorEvent, conns []MonitorConn) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.up, m.lastErr, m.lastPoll, m.events, m.conns
}

func (m *Monitor) Summary() map[string]any {
	up, lastErr, lastPoll, events, conns := m.Snapshot()
	return map[string]any{
		"url":         m.baseURL,
		"up":          up,
		"last_error":  lastErr,
		"last_poll":   lastPoll,
		"events":      len(events),
		"connections": len(conns),
	}
}

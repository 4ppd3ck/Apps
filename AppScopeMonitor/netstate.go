// Shared, thread-safe state of current network activity, served to the
// dashboard (mirrors monitor/netstate.py).
package monitor

import (
	"fmt"
	"strings"
	"sync"
)

// DirectionOf is the heuristic connection direction; documented as best-effort.
// Mirrors Python: int() conversion failure -> "outbound".
func DirectionOf(localPort, remotePort any) string {
	lp, lpOK := ToInt(localPort)
	rp, rpOK := ToInt(remotePort)
	if !lpOK || !rpOK {
		return "outbound"
	}
	if (rp != 0 && rp < 1024) || ServiceName(rp) != "" {
		return "outbound"
	}
	if (lp != 0 && lp < 1024) || ServiceName(lp) != "" {
		return "inbound"
	}
	if lp >= 49152 && rp >= 49152 {
		return "outbound"
	}
	return "outbound"
}

// Rate is a traffic rate entry: {"in", "out", "total_in", "total_out"}.
type Rate struct {
	In       float64 `json:"in"`
	Out      float64 `json:"out"`
	TotalIn  int64   `json:"total_in"`
	TotalOut int64   `json:"total_out"`
}

// HistoryPoint is one traffic-history sample: {"ts", "in", "out"}.
type HistoryPoint struct {
	Ts  float64 `json:"ts"`
	In  float64 `json:"in"`
	Out float64 `json:"out"`
}

// TrafficSample is one cumulative interface-counter observation.
type TrafficSample struct {
	Ts      float64
	RxBytes int64
	TxBytes int64
}

// NetState holds the latest connection table + per-app traffic rates +
// interface totals history.
type NetState struct {
	mu           sync.Mutex
	connections  []map[string]any
	appRates     map[string]Rate
	ifaces       map[string]Rate
	history      []HistoryPoint
	historyLen   int
	updatedAt    float64
	store        *Store
	sessionStart float64
}

// NewNetState creates the shared network state.
func NewNetState(historyLen int) *NetState {
	return &NetState{
		appRates:     map[string]Rate{},
		ifaces:       map[string]Rate{},
		historyLen:   historyLen,
		sessionStart: Now(),
	}
}

// SetStore attaches persistent traffic history storage.
func (n *NetState) SetStore(store *Store) {
	n.mu.Lock()
	n.store = store
	n.mu.Unlock()
}

// connStateAliases maps every platform's spelling of a connection state to
// the netstat-style long name the dashboard filters on. Keyed by the
// upper-cased input with "-" and "_" stripped, so Linux `ss` ("ESTAB",
// "FIN-WAIT-1"), Windows PowerShell ("SYNSENT", "TIMEWAIT") and macOS lsof
// ("SYN_RCVD") all collapse onto one form. Without this, the dashboard's
// state filter matches only Windows rows and Linux connections never show.
var connStateAliases = map[string]string{
	"ESTABLISHED": "ESTABLISHED",
	"ESTAB":       "ESTABLISHED",
	"SYNSENT":     "SYN_SENT",
	"SYNRCVD":     "SYN_RECV",
	"SYNRECV":     "SYN_RECV",
	"SYNRECEIVED": "SYN_RECV",
	"FINWAIT1":    "FIN_WAIT_1",
	"FINWAIT2":    "FIN_WAIT_2",
	"CLOSEWAIT":   "CLOSE_WAIT",
	"CLOSING":     "CLOSING",
	"LASTACK":     "LAST_ACK",
	"TIMEWAIT":    "TIME_WAIT",
	"LISTEN":      "LISTEN",
	"UNCONN":      "UNCONN",
	"CLOSED":      "CLOSED",
	"BOUND":       "BOUND",
}

// NormalizeConnState canonicalises a collector-reported connection state
// (unknown spellings pass through upper-cased).
func NormalizeConnState(state string) string {
	if state == "" {
		return ""
	}
	compact := strings.NewReplacer("-", "", "_", "").Replace(strings.ToUpper(state))
	if canon, ok := connStateAliases[compact]; ok {
		return canon
	}
	return strings.ToUpper(state)
}

// UpdateConnections replaces the connection table. Rows are normalised in
// place (collectors hand over freshly built per-poll maps), so the snapshot
// and the connection events emitted afterwards share one state spelling.
func (n *NetState) UpdateConnections(conns []map[string]any) {
	for _, conn := range conns {
		if state, ok := conn["state"].(string); ok {
			conn["state"] = NormalizeConnState(state)
		}
	}
	n.mu.Lock()
	n.connections = conns
	ts := Now()
	n.updatedAt = ts
	store := n.store
	n.mu.Unlock()
	if store != nil {
		if err := store.RecordConnectionSnapshot(ts, conns); err != nil {
			fmt.Printf("[network] connection history error: %v\n", err)
		}
	}
}

// UpdateTraffic stores per-app/per-interface rates and appends a rate-history
// point; available cumulative interface counters are also persisted.
func (n *NetState) UpdateTraffic(appRates, ifaces map[string]Rate, totalIn, totalOut float64) {
	ts := Now()
	var rxBytes, txBytes int64
	hasTotals := false
	for _, rate := range ifaces {
		rxBytes += rate.TotalIn
		txBytes += rate.TotalOut
		hasTotals = true
	}
	n.mu.Lock()
	if appRates != nil {
		n.appRates = appRates
	}
	if ifaces != nil {
		n.ifaces = ifaces
	}
	n.history = append(n.history, HistoryPoint{
		Ts:  ts,
		In:  totalIn,
		Out: totalOut,
	})
	if len(n.history) > n.historyLen {
		n.history = n.history[len(n.history)-n.historyLen:]
	}
	store := n.store
	n.mu.Unlock()
	if store != nil && hasTotals {
		if err := store.InsertTrafficSample(ts, rxBytes, txBytes); err != nil {
			fmt.Printf("[network] traffic history error: %v\n", err)
		}
	}
}

// TrafficSummary returns cumulative totals for dashboard-selected periods.
func (n *NetState) TrafficSummary(store *Store) (map[string]any, error) {
	n.mu.Lock()
	ifaces := make(map[string]Rate, len(n.ifaces))
	for name, rate := range n.ifaces {
		ifaces[name] = rate
	}
	sessionStart := n.sessionStart
	n.mu.Unlock()
	var rx, tx int64
	for _, rate := range ifaces {
		rx += rate.TotalIn
		tx += rate.TotalOut
	}
	available := len(ifaces) > 0
	result := map[string]any{
		"available":  available,
		"source":     "network interface counters",
		"since_boot": map[string]any{"available": available, "rx": rx, "tx": tx},
		"session":    map[string]any{"available": false, "rx": int64(0), "tx": int64(0)},
		"hour":       map[string]any{"available": false, "rx": int64(0), "tx": int64(0)},
		"six_hours":  map[string]any{"available": false, "rx": int64(0), "tx": int64(0)},
		"day":        map[string]any{"available": false, "rx": int64(0), "tx": int64(0)},
		"retained":   map[string]any{"available": false, "rx": int64(0), "tx": int64(0)},
	}
	if !available {
		return result, nil
	}
	if store == nil {
		return nil, fmt.Errorf("traffic history store is unavailable")
	}
	now := Now()
	if base, ok, err := store.FirstTrafficSampleAfter(sessionStart); err != nil {
		return nil, err
	} else if ok {
		result["session"] = counterDelta(base, rx, tx, base.Ts)
	}
	for key, duration := range map[string]float64{
		"hour": 3600, "six_hours": 6 * 3600, "day": 24 * 3600,
	} {
		base, ok, err := store.TrafficSampleBefore(now - duration)
		if err != nil {
			return nil, err
		}
		if !ok {
			base, ok, err = store.FirstTrafficSample()
			if err != nil {
				return nil, err
			}
		}
		if ok {
			result[key] = counterDelta(base, rx, tx, base.Ts)
		}
	}
	if base, ok, err := store.FirstTrafficSample(); err != nil {
		return nil, err
	} else if ok {
		result["retained"] = counterDelta(base, rx, tx, base.Ts)
	}
	return result, nil
}

func counterDelta(base TrafficSample, rx, tx int64, since float64) map[string]any {
	deltaRX, deltaTX := rx-base.RxBytes, tx-base.TxBytes
	if deltaRX < 0 {
		deltaRX = 0
	}
	if deltaTX < 0 {
		deltaTX = 0
	}
	return map[string]any{
		"available": true, "rx": deltaRX, "tx": deltaTX, "since": since,
	}
}

// UpdatedAt returns the timestamp of the last connection update.
func (n *NetState) UpdatedAt() float64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.updatedAt
}

// Snapshot returns the enriched view served to the dashboard.
func (n *NetState) Snapshot() map[string]any {
	n.mu.Lock()
	conns := make([]map[string]any, len(n.connections))
	copy(conns, n.connections)
	rates := make(map[string]Rate, len(n.appRates))
	for k, v := range n.appRates {
		rates[k] = v
	}
	ifaces := make(map[string]Rate, len(n.ifaces))
	for k, v := range n.ifaces {
		ifaces[k] = v
	}
	hist := make([]HistoryPoint, len(n.history))
	copy(hist, n.history)
	updatedAt := n.updatedAt
	n.mu.Unlock()

	appConnections := map[string]int{}
	for _, conn := range conns {
		app, ok := conn["app"].(string)
		if !ok || app == "" {
			app = "Unknown"
		}
		appConnections[app]++
	}

	enriched := make([]map[string]any, 0, len(conns))
	seenHosts := map[string]string{}
	for _, c := range conns {
		if len(enriched) >= 600 {
			break
		}
		remoteIP, _ := c["remote_ip"].(string)
		host, seen := seenHosts[remoteIP]
		if !seen {
			host = rdns.Get(remoteIP)
			seenHosts[remoteIP] = host
		}
		row := make(map[string]any, len(c)+4)
		for k, v := range c {
			row[k] = v
		}
		row["scope"] = ClassifyIP(remoteIP)
		row["service"] = ServiceName(IntOr(c["remote_port"], 0))
		if row["service"] == "" {
			row["service"] = ServiceName(IntOr(c["local_port"], 0))
		}
		if host != "" {
			row["host"] = host
		}
		enriched = append(enriched, row)
	}
	return map[string]any{
		"connections":     enriched,
		"app_rates":       rates,
		"app_connections": appConnections,
		"ifaces":          ifaces,
		"history":         hist,
		"updated_at":      updatedAt,
	}
}

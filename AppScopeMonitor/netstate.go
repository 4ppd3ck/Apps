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
	connBytes    map[string][2]int64 // best-effort per-connection counters

	// per-destination byte accounting: connBytes are cumulative per socket
	// and vanish when the socket closes, so each counter sample is diffed
	// against the previous one and the deltas accumulate per (app, remote
	// IP) until they flush to the store's destination_traffic table.
	destPending   map[string][2]int64 // keyed "app\x00remote ip"
	lastDestFlush float64

	// per-app process-level byte accounting (nettop per-process totals,
	// TCP+UDP): same diff-and-accumulate pattern, flushed into app_traffic.
	// QUIC/UDP traffic has no observable remote endpoint, so this is the
	// only source that captures it.
	appPending   map[string][2]int64
	lastAppBytes map[string][2]int64
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

// ConnBytesKey builds the per-connection byte-counter key: normalised proto
// ("tcp"/"udp", tcp4/tcp6 collapse to "tcp") plus local and remote
// "ip:port" endpoints. Shared by the macOS nettop collector and the
// snapshot enrichment so both sides agree on one key.
func ConnBytesKey(proto, local, remote string) string {
	p := strings.ToLower(strings.TrimSpace(proto))
	if len(p) > 1 && (p[len(p)-1] == '4' || p[len(p)-1] == '6') {
		p = p[:len(p)-1] // tcp4/tcp6/udp6 -> tcp/udp
	}
	return p + "|" + local + "|" + remote
}

// destFlushInterval paces destination_traffic writes; a killed daemon loses
// at most this window of byte deltas.
const destFlushInterval = 30.0 // seconds

// UpdateConnBytes replaces the best-effort per-connection byte counters
// (cumulative since socket creation; macOS nettop per-socket output). A nil
// map clears the previous counters. Counters are diffed against the previous
// sample and the deltas accumulate per (app, remote IP) destination, flushed
// to the store every destFlushInterval so per-site totals survive socket
// churn. Attributing a socket needs the current connection table, so
// unattributable sockets are skipped this round.
func (n *NetState) UpdateConnBytes(counters map[string][2]int64) {
	n.mu.Lock()
	prev := n.connBytes
	n.connBytes = counters

	appBySock := make(map[string]string, len(n.connections))
	ipBySock := make(map[string]string, len(n.connections))
	for _, conn := range n.connections {
		key := ConnBytesKey(StrOf(conn["proto"]),
			formatConnectionEndpoint(conn["local_ip"], conn["local_port"]),
			formatConnectionEndpoint(conn["remote_ip"], conn["remote_port"]))
		app, _ := conn["app"].(string)
		if app == "" {
			app = "Unknown"
		}
		appBySock[key] = app
		if ip, _ := conn["remote_ip"].(string); ClassifyIP(ip) == "external" {
			ipBySock[key] = ip
		}
	}
	now := Now()
	if n.destPending == nil {
		n.destPending = map[string][2]int64{}
	}
	for key, cur := range counters {
		dIn, dOut := cur[0], cur[1]
		if last, ok := prev[key]; ok {
			// same socket: only the growth is new traffic (a decrease means
			// the counter went away and came back — keep the remainder)
			if cur[0] > last[0] {
				dIn = cur[0] - last[0]
			} else {
				dIn = 0
			}
			if cur[1] > last[1] {
				dOut = cur[1] - last[1]
			} else {
				dOut = 0
			}
		}
		if dIn == 0 && dOut == 0 {
			continue
		}
		app, ip := appBySock[key], ipBySock[key]
		if app == "" || ip == "" {
			continue
		}
		dkey := app + "\x00" + ip
		d := n.destPending[dkey]
		d[0] += dIn
		d[1] += dOut
		n.destPending[dkey] = d
	}
	flushDest := n.store != nil && len(n.destPending) > 0 &&
		now-n.lastDestFlush >= destFlushInterval
	var batch []DestinationDelta
	if flushDest {
		batch = make([]DestinationDelta, 0, len(n.destPending))
		for key, v := range n.destPending {
			app, ip, _ := strings.Cut(key, "\x00")
			batch = append(batch, DestinationDelta{
				App: app, RemoteIP: ip, BytesIn: v[0], BytesOut: v[1],
			})
		}
		n.destPending = map[string][2]int64{}
		n.lastDestFlush = now
	}
	flushApp := n.store != nil && len(n.appPending) > 0 &&
		now-n.lastDestFlush >= destFlushInterval
	var appBatch []DestinationDelta
	if flushApp {
		appBatch = make([]DestinationDelta, 0, len(n.appPending))
		for app, v := range n.appPending {
			appBatch = append(appBatch, DestinationDelta{
				App: app, BytesIn: v[0], BytesOut: v[1],
			})
		}
		n.appPending = map[string][2]int64{}
	}
	n.mu.Unlock()

	if flushDest {
		if err := n.store.AddDestinationBytes(batch, now); err != nil {
			fmt.Printf("[network] destination traffic error: %v\n", err)
		}
	}
	if flushApp {
		if err := n.store.AddAppTraffic(appBatch, now); err != nil {
			fmt.Printf("[network] app traffic error: %v\n", err)
		}
	}
}

// UpdateAppBytes replaces the per-process cumulative byte totals (nettop
// per-process aggregates, TCP+UDP). Deltas against the previous sample
// accumulate per app until the shared flush interval elapses. nettop
// sometimes reports a truncated process name, so names are reconciled
// against the live connection table's app names when unambiguous.
func (n *NetState) UpdateAppBytes(appTotals map[string][2]int64) {
	n.mu.Lock()
	prev := n.lastAppBytes
	if n.appPending == nil {
		n.appPending = map[string][2]int64{}
	}
	knownApps := make(map[string]bool, len(n.connections))
	for _, conn := range n.connections {
		if app, ok := conn["app"].(string); ok && app != "" {
			knownApps[app] = true
		}
	}
	for app, cur := range appTotals {
		if app == "" {
			continue
		}
		if !knownApps[app] {
			for known := range knownApps {
				// "Code Helper" is the nettop-truncated tail of "ZCode Helper"
				if strings.HasSuffix(known, " "+app) {
					app = known
					break
				}
			}
		}
		dIn, dOut := cur[0], cur[1]
		if last, ok := prev[app]; ok {
			if cur[0] > last[0] {
				dIn = cur[0] - last[0]
			} else {
				dIn = 0
			}
			if cur[1] > last[1] {
				dOut = cur[1] - last[1]
			} else {
				dOut = 0
			}
		}
		if dIn == 0 && dOut == 0 {
			continue
		}
		d := n.appPending[app]
		d[0] += dIn
		d[1] += dOut
		n.appPending[app] = d
	}
	n.lastAppBytes = appTotals
	n.mu.Unlock()
}

// FlushDestinationBytes persists any pending per-destination and per-app
// byte deltas immediately (used before shutdown and by tests).
func (n *NetState) FlushDestinationBytes() {
	n.mu.Lock()
	if n.store == nil || (len(n.destPending) == 0 && len(n.appPending) == 0) {
		n.mu.Unlock()
		return
	}
	batch := make([]DestinationDelta, 0, len(n.destPending))
	for key, v := range n.destPending {
		app, ip, _ := strings.Cut(key, "\x00")
		batch = append(batch, DestinationDelta{
			App: app, RemoteIP: ip, BytesIn: v[0], BytesOut: v[1],
		})
	}
	n.destPending = map[string][2]int64{}
	appBatch := make([]DestinationDelta, 0, len(n.appPending))
	for app, v := range n.appPending {
		appBatch = append(appBatch, DestinationDelta{
			App: app, BytesIn: v[0], BytesOut: v[1],
		})
	}
	n.appPending = map[string][2]int64{}
	ts := Now()
	n.lastDestFlush = ts
	store := n.store
	n.mu.Unlock()
	if len(batch) > 0 {
		if err := store.AddDestinationBytes(batch, ts); err != nil {
			fmt.Printf("[network] destination traffic error: %v\n", err)
		}
	}
	if len(appBatch) > 0 {
		if err := store.AddAppTraffic(appBatch, ts); err != nil {
			fmt.Printf("[network] app traffic error: %v\n", err)
		}
	}
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
	connBytes := make(map[string][2]int64, len(n.connBytes))
	for k, v := range n.connBytes {
		connBytes[k] = v
	}
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
		if counters, ok := connBytes[ConnBytesKey(
			StrOf(c["proto"]),
			formatConnectionEndpoint(c["local_ip"], c["local_port"]),
			formatConnectionEndpoint(c["remote_ip"], c["remote_port"]),
		)]; ok {
			row["bytes_in"], row["bytes_out"] = counters[0], counters[1]
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

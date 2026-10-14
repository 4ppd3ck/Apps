package main

// Event-based endpoint & beacon tracking.
//
// AppScope Monitor emits one `connection` event per NEW (process, remote ip,
// remote port) pair — a persistent session fires once, every reconnect fires
// again. Those timestamps are real connection times, so interval statistics
// on them detect clockwork C2 callbacks that a snapshot poll would miss.
//
// Endpoint state lives in baseline["endpoints"][key]:
//   {first, last, n, ivals:[up to 12 recent inter-arrival seconds]}
// The ID cursor (baseline["last_event_id"]) makes processing idempotent
// across overlapping polls and monitor restarts.

import (
	"fmt"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
)

const (
	beaconMinSeen   = 6      // sightings before the math means anything
	beaconMinIv     = 5.0    // seconds — faster than this is one session
	beaconMaxIv     = 3600.0 // seconds — slower than hourly is not clockwork
	beaconMaxJitter = 0.15   // stdev/mean — real check-ins are tight (CS-style sleep jitter lands ~0.1)
	beaconIvalsKept = 12     // recent intervals kept per endpoint
	burstNewLimit   = 15     // > this many new keys in one pass = rescan
)

type Sighting struct {
	App  string
	IP   string
	Port int
	Host string
	Ts   float64
}

// splitRemote parses the monitor's Remote field ("ip:port", "[v6]:port",
// bare ip, "ip:port (host)" variants tolerated).
func splitRemote(remote string) (string, int) {
	s := strings.TrimSpace(remote)
	if i := strings.IndexByte(s, ' '); i > 0 { // "1.2.3.4:443 (host)" safety
		s = s[:i]
	}
	if host, portStr, err := net.SplitHostPort(s); err == nil {
		port, _ := strconv.Atoi(portStr)
		return strings.Trim(host, "[]"), port
	}
	return strings.Trim(s, "[]"), 0
}

// TrackEndpoints processes connection events (ID-ordered ascending, already
// filtered to ID > cursor) and returns findings plus the updated endpoint map.
// learnUntil suppresses new-endpoint low alerts while the baseline is young.
func TrackEndpoints(rules *Rules, events []MonitorEvent, endpoints map[string]any,
	learnUntil float64, now float64) ([]Finding, map[string]any) {

	findings := []Finding{}
	newThisPass := 0
	perApp := map[string][]newEp{} // first-seen endpoints this batch, per app

	for i := range events {
		e := &events[i]
		if e.Category != "network" || e.Kind != "connection" {
			continue
		}
		ip, port := splitRemote(FmtAny(e.Remote))
		if ip == "" || !IsExternal(ip, rules) {
			continue
		}
		app := strings.ToLower(FmtAny(e.App))
		if app == "" || StrHasAny(FmtAny(e.App), rules.ProcessAllow) {
			continue
		}
		s := Sighting{App: app, IP: ip, Port: port, Ts: e.Ts}

		key := app + "|" + ip + ":" + strconv.Itoa(port)
		raw, ok := endpoints[key]
		info, _ := raw.(map[string]any)
		if !ok || info == nil {
			// first sighting ever — recorded always, alerted per-app below
			// (one aggregated alert per app per window instead of one per IP;
			// browsers alone would flood a per-IP stream)
			newThisPass++
			if e.Ts >= learnUntil {
				perApp[app] = append(perApp[app], newEp{
					appDisp: FmtAny(e.App), ip: ip, port: port, pid: e.Pid,
				})
			}
			endpoints[key] = map[string]any{"first": s.Ts, "last": s.Ts, "n": 1}
			continue
		}

		n := AnyInt(info["n"]) + 1
		first := AnyFloat(info["first"])
		last := AnyFloat(info["last"])
		ivals, _ := info["ivals"].([]any)
		iv := s.Ts - last
		if iv >= beaconMinIv && iv <= beaconMaxIv {
			ivals = append(ivals, iv)
			if len(ivals) > beaconIvalsKept {
				ivals = ivals[len(ivals)-beaconIvalsKept:]
			}
		} else if iv > beaconMaxIv {
			ivals = nil // a long gap breaks the rhythm; start the window over
		}
		info["n"] = n
		info["last"] = s.Ts
		info["ivals"] = ivals

		// beacon: enough sightings, tight clockwork intervals. Emitted once
		// per endpoint (flagged in state); the alert's hit counter takes over.
		if !AnyBool(info["beacon"]) && n >= beaconMinSeen && len(ivals) >= beaconMinSeen-1 {
			fs := float64Slice(ivals)
			if mean, sd := meanStdev(fs); len(fs) >= beaconMinSeen-1 &&
				mean >= beaconMinIv && mean <= beaconMaxIv && sd/mean < beaconMaxJitter {
				info["beacon"] = true
				findings = append(findings, Finding{
					Check:    "beacon",
					Severity: SevMedium,
					Title: fmt.Sprintf("Clockwork callback pattern: %s → %s:%d",
						FmtAny(e.App), ip, port),
					Detail: fmt.Sprintf("%d connections to one endpoint at a "+
						"mean interval of %.0fs (±%.0fs jitter). Regular check-ins "+
						"to a public address are the strongest software-beacon "+
						"signature — confirm you expect this app to phone home.",
						n, mean, sd),
					Evidence: map[string]any{
						"app": FmtAny(e.App), "remote": ip + ":" + strconv.Itoa(port),
						"count": n, "mean_interval_s": int(mean),
						"jitter_s": int(sd), "since": int(now - first),
					},
					Fingerprint: FingerprintOf("beacon", key),
				})
			}
		}
	}

	// Emit one aggregated finding per app per window (6h bucket): the count
	// and destination list travel in evidence, so a browser hitting 4 new
	// CDNs is one low alert, not four. Apps on the quiet list (browsers,
	// updaters — endpoint churn is their nature) are baselined but silent.
	// A non-quiet app bursting past new_endpoint_burst first-seen
	// destinations in a single batch escalates to medium: mass new
	// destinations from a small utility is spread/scanner behaviour.
	window := now / newEndpointWindowSecs
	for appName, eps := range perApp {
		if isQuietApp(appName, rules) {
			continue
		}
		appDisp := eps[0].appDisp
		sev := SevLow
		title := fmt.Sprintf("New outbound endpoints from %s (%d)",
			appDisp, len(eps))
		detail := fmt.Sprintf("First seen in this window: %s. Recorded to the "+
			"baseline; repeat check-ins to the same endpoint are tracked for "+
			"beacon patterns separately.", epList(eps, 6))
		if len(eps) >= rules.NewEndpointBurst {
			sev = SevMedium
			title = fmt.Sprintf("Endpoint expansion: %s reached %d new destinations",
				appDisp, len(eps))
			detail = fmt.Sprintf("%d brand-new public destinations in one scan "+
				"(%s). For a small utility this is scanner or spread behaviour — "+
				"confirm the app.", len(eps), epList(eps, 6))
		}
		findings = append(findings, Finding{
			Check:    "new_endpoint",
			Severity: sev,
			Title:    title,
			Detail:   detail,
			Evidence: map[string]any{
				"app":          appDisp,
				"new_count":    len(eps),
				"endpoints":    epList(eps, 20),
				"window_hours": int(newEndpointWindowSecs / 3600),
			},
			Fingerprint: FingerprintOf("new_endpoint",
				appName+"|"+strconv.FormatInt(int64(window), 10)),
		})
	}

	// Collector restarts re-emit every existing connection as "new" — a burst
	// of first-sightings in one pass means rescan, not compromise. Learn them
	// silently and say so.
	if newThisPass > burstNewLimit {
		findings = filterNewEndpoint(findings)
		findings = append(findings, Finding{
			Check:    "endpoints",
			Severity: SevInfo,
			Title:    fmt.Sprintf("Learned %d endpoints after an AppScope Monitor rescan", newThisPass),
			Detail: "A large batch of first-seen connections at once means the " +
				"monitor's collectors restarted (fresh seen-table), not a burst " +
				"of new traffic. Recorded without alerting.",
		})
	}

	// prune stale endpoints (>72h idle)
	cut := now - 72*3600
	out := map[string]any{}
	for k, v := range endpoints {
		if info, ok := v.(map[string]any); ok && AnyFloat(info["last"]) < cut {
			continue
		}
		out[k] = v
	}
	return findings, out
}

// EventsAfterID filters+sorts monitor events to a monotonically increasing
// ID cursor, so overlapping polls never double-count a connection.
func EventsAfterID(events []MonitorEvent, afterID int64) []MonitorEvent {
	out := []MonitorEvent{}
	for _, e := range events {
		if e.ID > afterID {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func filterNewEndpoint(fs []Finding) []Finding {
	out := fs[:0]
	for _, f := range fs {
		if f.Check != "new_endpoint" {
			out = append(out, f)
		}
	}
	return out
}

func float64Slice(v []any) []float64 {
	out := make([]float64, 0, len(v))
	for _, x := range v {
		if f := AnyFloat(x); f > 0 {
			out = append(out, f)
		}
	}
	return out
}

func meanStdev(v []float64) (float64, float64) {
	if len(v) == 0 {
		return 0, 0
	}
	var sum float64
	for _, x := range v {
		sum += x
	}
	mean := sum / float64(len(v))
	var sq float64
	for _, x := range v {
		sq += (x - mean) * (x - mean)
	}
	return mean, math.Sqrt(sq / float64(len(v)))
}

const newEndpointWindowSecs = 6 * 3600

// isQuietApp: endpoint churn is the app's nature (browsers, updaters) —
// baseline silently, never alert on new_endpoint.
func isQuietApp(appLower string, rules *Rules) bool {
	return StrHasAny(appLower, rules.QuietApps)
}

// epList renders up to max endpoints as "ip:port (host)" for evidence.
func epList(eps []newEp, max int) string {
	parts := []string{}
	for i, e := range eps {
		if i >= max {
			parts = append(parts, fmt.Sprintf("… +%d more", len(eps)-max))
			break
		}
		p := fmt.Sprintf("%s:%d", e.ip, e.port)
		parts = append(parts, p)
	}
	return strings.Join(parts, ", ")
}

// newEp is one first-seen destination in the current batch.
type newEp struct {
	appDisp string
	ip      string
	port    int
	pid     any
}

package main

// Engine: schedules the checks, converts findings into deduplicated alerts,
// pushes desktop notifications, and keeps the last scan snapshot for the API.

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"
)

type checkDef struct {
	def Check
	fn  func() []Finding
}

type Engine struct {
	rules      *Rules
	store      *Store
	monitor    *Monitor
	intel      *Intel
	exclusions *Exclusions
	hub        *Hub

	mu        sync.Mutex
	set       []checkDef
	statuses  map[string]*CheckStatus
	lastScan  map[string][]Finding // check -> latest findings (all, incl. transient)
	zombie    map[int]float64
	sensitive SensitiveSnapshot // latest Live Access scan (served at /api/sensitive)
	started   time.Time
	stopCh    chan struct{}
}

func NewEngine(rules *Rules, store *Store, monitor *Monitor, intel *Intel,
	exclusions *Exclusions, hub *Hub) *Engine {
	e := &Engine{
		rules: rules, store: store, monitor: monitor, intel: intel,
		exclusions: exclusions, hub: hub,
		statuses: map[string]*CheckStatus{},
		lastScan: map[string][]Finding{},
		zombie:   map[int]float64{},
		started:  time.Now(),
		stopCh:   make(chan struct{}),
	}
	e.defineChecks()
	return e
}

func (e *Engine) defineChecks() {
	e.set = []checkDef{
		{Check{Name: "processes", Description: "Zombies, orphans, known attack-tool names, temp-dir execution", Interval: "fast"},
			func() []Finding {
				procs, err := listProcs()
				if err != nil {
					return []Finding{{Check: "processes", Severity: SevInfo,
						Title: "Process scan unavailable", Detail: FmtErr(err)}}
				}
				return procFindings(e.rules, procs, e.zombie, NowF())
			}},
		{Check{Name: "network", Description: "RAT/backdoor listeners, rogue remotes, beacon callbacks (uses AppScope Monitor)", Interval: "fast"},
			func() []Finding {
				socks, err := listeningSocks()
				if err != nil {
					return []Finding{{Check: "network", Severity: SevInfo,
						Title: "Socket scan unavailable", Detail: FmtErr(err)}}
				}
				sortSocks(socks)
				procs, _ := listProcs()
				_, lastErr, _, events, conns := e.monitor.Snapshot()
				out := netFindings(e.rules, socks, procs, conns, NowF())
				out = append(out, e.trackEndpoints(events)...)
				if !e.monitor.up {
					out = append(out, Finding{
						Check: "network", Severity: SevInfo,
						Title: "AppScope Monitor offline — rogue-remote scope reduced",
						Detail: "Connection table and privacy correlation come from " +
							"AppScope Monitor (" + strings.TrimSpace(lastErr) +
							"). Start it from AppDeck for full coverage; listener and " +
							"process checks still run.",
					})
				}
				if e.rules.IntelMode() != "off" {
					if up, intelErr, _, _, _ := e.intel.Snapshot(); !up {
						out = append(out, Finding{
							Check: "network", Severity: SevInfo,
							Title: "IPolice offline — known-provider labelling disabled",
							Detail: "Known-provider ranges come from IPolice (" +
								strings.TrimSpace(intelErr) +
								"). Endpoints count as unknown until it answers; " +
								"detection itself is unaffected.",
						})
					}
				}
				return out
			}},
		{Check{Name: "mitm", Description: "Gateway MAC change, ARP conflicts/spoofing, DNS resolver change, rebinding probe", Interval: "fast"},
			func() []Finding { return mitmFindings(e.store, e.rules) }},
		{Check{Name: "persistence", Description: "New launch agents/daemons, cron, autostart, systemd units, Run keys, startup folders", Interval: "slow"},
			func() []Finding { return persistFindings(e.store) }},
		{Check{Name: "firewall", Description: "Firewall state, default policies and per-app allow rules (socketfilterfw / Windows firewall / firewalld / pf)", Interval: "slow"},
			func() []Finding { return firewallFindings(e.store) }},
		{Check{Name: "exfil", Description: "TCC permission grants (macOS), keylogger names, camera/mic/file + outbound correlation", Interval: "slow"},
			func() []Finding {
				procs, err := listProcs()
				if err != nil {
					procs = nil
				}
				_, _, _, events, conns := e.monitor.Snapshot()
				return exfilFindings(e.store, e.rules, procs, events, conns, NowF(), e.intel)
			}},
		{Check{Name: "sensitive", Description: "Live access watch: apps holding or attempting mic/camera devices, password-manager data or sensitive files (lsof · /proc · TCC · CapabilityAccessManager)", Interval: "fast"},
			func() []Finding {
				snap := scanSensitive(e.rules)
				_, _, _, events, conns := e.monitor.Snapshot()
				mergeMonitorPrivacy(&snap, events, NowF())
				snap.Access = e.filterLiveExcluded(snap.Access)
				e.setSensitive(snap)
				return sensitiveFindings(e.rules, snap, conns, NowF(), e.intel)
			}},
	}
}

// set holds the ordered check list (declared above).

func (e *Engine) Run() {
	slowTick := time.NewTicker(time.Duration(e.effectiveSlow()) * time.Second)
	defer slowTick.Stop()
	fastTick := time.NewTicker(time.Duration(e.effectiveFast()) * time.Second)
	defer fastTick.Stop()

	e.intel.Poll() // prime the known-IP tables before the first scan
	e.runOnce("fast")
	e.runOnce("slow")
	for {
		select {
		case <-e.stopCh:
			return
		case <-fastTick.C:
			e.runOnce("fast")
		case <-slowTick.C:
			e.intel.Poll() // refresh known-IP tables on the slow cadence
			e.runOnce("slow")
		}
	}
}

// effectiveFast/effectiveSlow are the tick lengths Run() schedules with —
// config values clamped to their minimums. Exposed via Status() so the
// dashboard shows the real cadence.
func (e *Engine) effectiveFast() int {
	s := e.rules.TickSeconds
	if s < 5 {
		s = 5
	}
	return s
}

func (e *Engine) effectiveSlow() int {
	m := e.rules.SlowMinutes
	if m < 1 {
		m = 1
	}
	return m * 60
}

// pollMonitor refreshes AppScope Monitor data; called at the start of every
// fast scan so the network/exfil checks see a live connection table.
func (e *Engine) pollMonitor() { e.monitor.Poll() }

// trackEndpoints runs the event-based endpoint/beacon tracker with the
// baseline's ID cursor and learning window, persisting the updated map.
func (e *Engine) trackEndpoints(events []MonitorEvent) []Finding {
	now := NowF()
	started, _ := e.store.BaselineKey("started_at", now)
	learnUntil := AnyFloat(started) + float64(e.rules.LearnMinutes)*60
	cursorVal, _ := e.store.BaselineKey("last_event_id", int64(0))

	batch := EventsAfterID(events, int64(AnyFloat(cursorVal)))
	if len(batch) == 0 {
		return nil
	}
	findings, endpoints := TrackEndpoints(e.rules, batch, e.store.Endpoints(),
		learnUntil, now, e.intel)
	e.store.SaveEndpoints(endpoints)
	maxID := int64(0)
	for _, ev := range batch {
		if ev.ID > maxID {
			maxID = ev.ID
		}
	}
	e.store.BaselineUpdate("last_event_id", maxID)
	return findings
}

func (e *Engine) Stop() { close(e.stopCh) }

// runOnceExport powers `sentinel --once`: one full scan, findings on stdout.
func (e *Engine) runOnceExport() {
	e.runOnce("fast")
	e.runOnce("slow")
	fmt.Println()
	findings := e.Findings()
	if len(findings) == 0 {
		fmt.Println("no findings — machine looks quiet")
		return
	}
	for _, f := range findings {
		fmt.Printf("[%s] %s\n  %s\n", strings.ToUpper(f.Severity), f.Title, f.Detail)
	}
	alerts := e.store.Alerts(0, "")
	fmt.Printf("\n%d finding(s), %d alert(s) recorded\n", len(findings), len(alerts))
}

func (e *Engine) runOnce(interval string) {
	e.exclusions.MaybeReload() // on-disk changes (other processes, edits) apply immediately
	if interval == "fast" {
		e.pollMonitor()
		e.intel.RetryIfDown(10) // re-try a starting/offline IPolice (loopback: cheap)
	} else {
		e.intel.Poll() // slow tick keeps the known-IP tables fresh
	}
	now := NowF()
	for _, cd := range e.set {
		if cd.def.Interval != interval {
			continue
		}
		t0 := time.Now()
		findings := cd.fn()
		ms := time.Since(t0).Milliseconds()

		e.mu.Lock()
		st, ok := e.statuses[cd.def.Name]
		if !ok {
			st = &CheckStatus{Name: cd.def.Name, Description: cd.def.Description}
			e.statuses[cd.def.Name] = st
		}
		st.LastRun = now
		st.LastMs = ms
		unavailable := false
		for _, f := range findings {
			if f.Title == "Process scan unavailable" || f.Title == "Socket scan unavailable" ||
				f.Title == "Network baseline unavailable" || f.Title == "Persistence scan unavailable" ||
				f.Title == "Permission database not readable" || f.Title == "Firewall scan unavailable" ||
				f.Title == "Sensitive access scan unavailable" {
				unavailable = true
				st.Reason = f.Detail
			}
		}
		if unavailable {
			st.Status = "unavailable"
		} else {
			st.Status = "ok"
			st.Reason = ""
		}
		kept := make([]Finding, 0, len(findings))
		for _, f := range findings {
			if f.Title == "AppScope Monitor offline — rogue-remote scope reduced" ||
				f.Title == "IPolice offline — known-provider labelling disabled" ||
				e.exclusions.ExcludedByWatchdog(f) {
				continue // excluded apps never surface in findings…
			}
			kept = append(kept, f)
		}
		e.lastScan[cd.def.Name] = kept
		e.mu.Unlock()

		// …and never become alerts or notifications
		e.dispatch(e.exclusions.filterWatchdogExcluded(findings))
	}
	e.hub.Broadcast(map[string]any{"type": "scan", "interval": interval, "ts": now})
}

// dispatch turns findings into alerts (deduped) and desktop notifications.
func (e *Engine) dispatch(findings []Finding) {
	minSev := e.rules.Notify.MinSeverity
	if minSev == "" {
		minSev = SevMedium
	}
	for _, f := range findings {
		if f.Fingerprint == "" {
			continue
		}
		alert, reNotify := e.store.Record(f, 30*time.Minute)
		// auto-ack exclusions: the alert stays recorded (history, counts)
		// but lands pre-acked and never notifies — the user's version of
		// the intel "autoack" treatment below
		if alert != nil && e.exclusions.ExcludedByAutoAck(f) {
			e.store.AckByFingerprint(f.Fingerprint)
			reNotify = false
		}
		// intel "autoack" mode: known-provider new-endpoint alerts land
		// pre-acked (history + counts, never a notification)
		if alert != nil && FmtAny(f.Evidence["intel_known"]) != "" {
			e.store.AckByFingerprint(f.Fingerprint)
			reNotify = false
		}
		if alert != nil && reNotify && SevGE(f.Severity, minSev) && f.Severity != SevInfo {
			if e.rules.Notify.Desktop {
				NotifyAlert(alert, e.rules.Notify.Sound)
			}
			NotifyWebhook(alert, &e.rules.Notify)
		}
	}
}

// API views --------------------------------------------------------------

func (e *Engine) Status() map[string]any {
	e.mu.Lock()
	defer e.mu.Unlock()
	infos := []*CheckStatus{}
	for _, cd := range e.set {
		if st, ok := e.statuses[cd.def.Name]; ok {
			infos = append(infos, st)
		} else {
			infos = append(infos, &CheckStatus{Name: cd.def.Name,
				Description: cd.def.Description, Status: "ok"})
		}
	}
	return map[string]any{
		"platform": runtime.GOOS + "/" + runtime.GOARCH,
		"os":       runtime.GOOS,
		"arch":     runtime.GOARCH,
		"go":       runtime.Version(),
		"uptime_s": int(time.Since(e.started).Seconds()),
		"checks":   infos,
		"scan":     e.lastScan,
		"notify":   e.rules.Notify,
		"intel":    e.intel.Summary(),
		// effective tick lengths, same clamps Run() applies — the dashboard
		// shows what the scanner really does, not the raw config
		"tick_s": e.effectiveFast(),
		"slow_s": e.effectiveSlow(),
	}
}

func (e *Engine) Findings() []Finding {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := []Finding{}
	for _, fs := range e.lastScan {
		out = append(out, fs...)
	}
	return out
}

func (e *Engine) TriggerManualScan() {
	go func() {
		e.runOnce("fast")
		e.runOnce("slow")
	}()
}

// filterLiveExcluded drops Live Access rows for apps carrying the "live"
// exclusion (the whole app disappears from the tab, not just one row), and
// single rows carrying their own per-target "live" exclusion.
func (e *Engine) filterLiveExcluded(access []SensitiveAccess) []SensitiveAccess {
	if e.exclusions == nil {
		return access
	}
	out := access[:0]
	for _, a := range access {
		if e.exclusions.Excludes("live", a.App) ||
			e.exclusions.ExcludesTarget("live", a.App, a.Target) {
			continue
		}
		out = append(out, a)
	}
	return out
}

// setSensitive stores the latest Live Access snapshot for the API.
func (e *Engine) setSensitive(snap SensitiveSnapshot) {
	e.mu.Lock()
	e.sensitive = snap
	e.mu.Unlock()
}

// SensitiveSnapshot returns the latest Live Access scan (zero value before
// the first fast scan completes).
func (e *Engine) SensitiveSnapshot() SensitiveSnapshot {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.sensitive
}

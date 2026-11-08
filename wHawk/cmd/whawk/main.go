// wHawk — AppDeck host-compromise watchdog.
//
// Reads AppScope Monitor's live data (connections, privacy/file events) and
// layers its own per-OS checks on top, alerting when the machine shows
// compromise indicators: zombie/orphan processes, known RAT / keylogger /
// tunneller tooling, listeners on remote-control ports, rogue public
// endpoints and beacon callbacks, gateway MAC changes / ARP spoofing / DNS
// hijack & rebinding, new persistence entries, and new Accessibility /
// Input-Monitoring / Screen-Capture grants.
//
// Pure stdlib (no cgo, no SQLite) so build.sh covers every GOOS/GOARCH.
package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"time"
)

const Version = "1.0"

func main() {
	var (
		host      = flag.String("host", "127.0.0.1", "bind address")
		port      = flag.Int("port", 8899, "port to serve on")
		dataFl    = flag.String("data", "", "data directory (default APPDECK_DATA or ./data)")
		wtowerFl = flag.String("wtower", "", "wTower base URL (default MONITOR_URL env, then rules)")
		wgridFl   = flag.String("wgrid", "", "wGrid base URL (default IPOLICE_URL env, then rules)")
		once      = flag.Bool("once", false, "run one full scan, print findings, exit")
		_         = flag.Bool("debug", false, "verbose logging (reserved)")
	)
	flag.Parse()

	dataDir := *dataFl
	if dataDir == "" {
		dataDir = os.Getenv("APPDECK_DATA")
	}
	if dataDir == "" {
		dataDir = "data"
	}

	// The launcher passes PORT/APPDECK_PORT for {port} substitution; honour
	// them like every other AppDeck app.
	if *port == 8899 {
		if p := os.Getenv("APPDECK_PORT"); p != "" {
			if v, err := strconv.Atoi(p); err == nil {
				*port = v
			}
		} else if p := os.Getenv("PORT"); p != "" {
			if v, err := strconv.Atoi(p); err == nil {
				*port = v
			}
		}
	}
	if h := os.Getenv("APPDECK_HOST"); h != "" && *host == "127.0.0.1" {
		*host = h
	}

	migrateWatchdogState(dataDir)

	rules := LoadRules(dataDir)
	// Peer URLs: flag > env > launcher registry > rules. The hardcoded rules
	// defaults only work while the launcher hands every app its usual port;
	// the registry lookup keeps the interlinks alive when apps are
	// auto-assigned (port 0) and their assignments drift.
	if *wtowerFl != "" {
		rules.MonitorURL = *wtowerFl
	} else if v := os.Getenv("WTOWER_URL"); v != "" {
		rules.MonitorURL = v
	}
	if *wgridFl != "" {
		rules.IntelURL = *wgridFl
	} else if v := os.Getenv("WGRID_URL"); v != "" {
		rules.IntelURL = v
	} else if u := discoverPeerURL(launcherURL(), "wgrid"); u != "" {
		// the wGrid app is port 0 (launcher auto-assigns): the registry is
		// the only static-free way to find it
		rules.IntelURL = u
	}
	warnPortConflicts(rules)

	fmt.Printf("wHawk %s  (%s/%s, %s)\n", Version, runtime.GOOS, runtime.GOARCH, runtime.Version())
	fmt.Printf("  data dir : %s\n", dataDir)
	fmt.Printf("  monitor  : %s\n", rules.MonitorURL)
	fmt.Printf("  intel    : %s\n", rules.IntelURL)
	fmt.Printf("  ticks    : fast %ds / slow %dm\n", rules.TickSeconds, rules.SlowMinutes)

	hub := NewHub()
	store, err := NewStore(dataDir, hub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: data dir %s: %v\n", dataDir, err)
		os.Exit(1)
	}
	monitor := NewMonitor(rules.MonitorURL)
	intel := NewIntel(rules.IntelURL)
	exclusions := LoadExclusions(dataDir)
	engine := NewEngine(rules, store, monitor, intel, exclusions, hub)

	if *once {
		monitor.Poll()
		engine.runOnceExport()
		return
	}

	go engine.Run()

	addr := net.JoinHostPort(*host, strconv.Itoa(*port))
	// macOS notification clicks (terminal-notifier) open the dashboard here
	NotifyURL = "http://" + addr + "/"
	srv := &Server{
		engine: engine, store: store, monitor: monitor,
		rules: rules, hub: hub, dataDir: dataDir, exclusions: exclusions,
	}
	fmt.Printf("  serving  : http://%s  (started %s)\n", addr, time.Now().Format("15:04:05"))
	if err := http.ListenAndServe(addr, hostGuard(*host, srv.routes())); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

// warnPortConflicts flags configured bad_ports that something on this host
// already listens on — the AppDeck-9090 class of false positive. Advisory
// only (printed once at startup); the check still runs.
func warnPortConflicts(rules *Rules) {
	socks, err := listeningSocks()
	if err != nil {
		return
	}
	bad := map[int]bool{}
	for _, p := range rules.BadPorts {
		bad[p] = true
	}
	for _, s := range socks {
		if bad[s.Port] {
			fmt.Printf("  note     : port %d is in bad_ports but %q is already "+
				"listening on it — allowlist that process in rules.user.json "+
				"or expect a finding on every scan\n", s.Port, s.ProcName)
		}
	}
}

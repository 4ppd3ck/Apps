// Sentinel — AppDeck host-compromise watchdog.
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
		monitorFl = flag.String("monitor", "", "AppScope Monitor base URL (default from rules)")
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

	rules := LoadRules(dataDir)
	if *monitorFl != "" {
		rules.MonitorURL = *monitorFl
	}
	warnPortConflicts(rules)

	fmt.Printf("Sentinel %s  (%s/%s, %s)\n", Version, runtime.GOOS, runtime.GOARCH, runtime.Version())
	fmt.Printf("  data dir : %s\n", dataDir)
	fmt.Printf("  monitor  : %s\n", rules.MonitorURL)
	fmt.Printf("  ticks    : fast %ds / slow %dm\n", rules.TickSeconds, rules.SlowMinutes)

	hub := NewHub()
	store, err := NewStore(dataDir, hub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: data dir %s: %v\n", dataDir, err)
		os.Exit(1)
	}
	monitor := NewMonitor(rules.MonitorURL)
	engine := NewEngine(rules, store, monitor, hub)

	if *once {
		monitor.Poll()
		engine.runOnceExport()
		return
	}

	go engine.Run()

	addr := net.JoinHostPort(*host, strconv.Itoa(*port))
	srv := &Server{
		engine: engine, store: store, monitor: monitor,
		rules: rules, hub: hub, dataDir: dataDir,
	}
	fmt.Printf("  serving  : http://%s  (started %s)\n", addr, time.Now().Format("15:04:05"))
	if err := http.ListenAndServe(addr, srv.routes()); err != nil {
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

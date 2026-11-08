// CLI entrypoint: `monitor` (mirrors python -m monitor / __main__.py).
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"wtower"
	"wtower/collectors"
)

func main() {
	configPath := flag.String("config", "", "path to config.json")
	host := flag.String("host", "", "bind address (default from config: 127.0.0.1)")
	port := flag.Int("port", 0, "port (default from config: 8765)")
	openBrowserFlag := flag.Bool("open", false, "open the dashboard in the default browser")
	debug := flag.Bool("debug", false, "verbose HTTP logging")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: monitor [--config PATH] [--host HOST] "+
			"[--port PORT] [--open] [--debug]\n\n"+
			"wTower - privacy (camera/mic/file) & network activity "+
			"monitor with a local dashboard.\n\nflags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	// PORT/APPDECK_PORT contract: the deck assigns a stable port via env
	// unless --port was passed explicitly.
	if *port == 0 {
		for _, k := range []string{"APPDECK_PORT", "PORT"} {
			if v := os.Getenv(k); v != "" {
				if p, err := strconv.Atoi(v); err == nil && p > 0 {
					*port = p
				}
				break
			}
		}
	}

	cfg := wtower.LoadConfig(*configPath)
	if *host != "" {
		cfg.Data["host"] = *host
	}
	if *port != 0 {
		cfg.Data["port"] = *port
	}

	store, err := wtower.NewStore(filepath.Join(cfg.DataDir(), "wtower.db"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot open store: %v\n", err)
		os.Exit(1)
	}
	store.Start(cfg.RetentionDays())
	bus := wtower.NewEventBus(store)
	ctx := wtower.NewCtx(cfg, store, bus)

	// The host watchdog and the IP intel feed live in their own apps since
	// the split (wHawk and wGrid); the country-block source discovers wGrid
	// on its own (launcher registry + signature probe).

	ctx.SetCollectors(collectors.BuildCollectors(ctx))
	// external-IP geo enrichment: async ip-api.com lookups + persistent cache
	ctx.Geo = wtower.NewGeoCache(filepath.Join(cfg.DataDir(), "geo_cache.json"))

	// blocking enforcement: materialize the packaged helper/grant scripts
	// beside the config and probe privilege level. The stored-rule
	// re-apply (StartupReconcile) deliberately runs AFTER the dashboard
	// binds below: it can feed thousands of CIDRs to the privileged
	// helper, and the launcher's start probe must see the port answer
	// long before that finishes.
	if err := wtower.MaterializeScripts(
		filepath.Join(filepath.Dir(cfg.Path), "scripts")); err != nil {
		fmt.Printf("[blocks] scripts: %v\n", err)
	}
	enf := wtower.NewEnforcer(ctx)
	ctx.Enforcer = enf
	enf.Probe()

	// DNS shield: the local filtering resolver. Off unless dns_shield is
	// set in the config (the dashboard's DNS panel can start it any time).
	shield := wtower.NewDNSShield(ctx)
	ctx.DNSShield = shield
	if cfg.GetBool("dns_shield", false) {
		if err := shield.Start(); err != nil {
			fmt.Printf("[dns] shield: %v\n", err)
		} else {
			fmt.Printf("[dns] shield listening on 127.0.0.1:%d\n", shield.Port())
		}
	}
	// the Report tab's daily usage rollup names destinations at flush time
	wtower.WireReportRollup(ctx)

	for _, col := range ctx.Collectors() {
		if !col.Enabled() {
			col.SetStatus("disabled", "turned off in settings")
			continue
		}
		if ok, reason := col.Available(); ok {
			col.Start()
		} else {
			col.SetStatus("unavailable", reason)
		}
	}

	bindHost := strings.Trim(cfg.Host(), "[]")
	addr := net.JoinHostPort(bindHost, strconv.Itoa(cfg.Port()))
	srv, err := wtower.NewMonitorServer(addr, wtower.NewHandler(ctx))
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot bind %s (%v) -- is another monitor "+
			"instance already running?\n", addr, err)
		os.Exit(1)
	}
	srv.Debug = *debug
	info := wtower.HostInfo()
	browserHost := strings.Trim(cfg.Host(), "[]")
	if browserHost == "" || browserHost == "0.0.0.0" || browserHost == "::" {
		browserHost = "127.0.0.1"
	}
	url := "http://" + net.JoinHostPort(browserHost, strconv.Itoa(cfg.Port()))
	fmt.Printf("wTower on %s (%s, user=%s, root=%s)\n",
		info["hostname"], info["platform"], info["user"], pyBool(info["root"]))
	fmt.Printf("Dashboard: %s\n", url)
	for _, col := range ctx.Collectors() {
		st := col.Status()
		mark := "?"
		switch st.State {
		case "active":
			mark = "+"
		case "unavailable":
			mark = "-"
		case "degraded":
			mark = "!"
		case "disabled":
			mark = "x"
		}
		extra := ""
		if st.Detail != "" {
			extra = " -- " + st.Detail
		}
		fmt.Printf("  [%s] %-16s %s%s\n", mark, col.Name(), st.State, extra)
	}

	// serve BEFORE the slow startup work: the launcher opens the dashboard
	// the moment the port answers, so HTTP must be live while the firewall
	// reconcile and first collector polls still run in the background
	serveErr := make(chan error, 1)
	go func() {
		if err := srv.Serve(); err != nil && err != http.ErrServerClosed {
			serveErr <- err
		}
	}()

	// re-apply stored rules while the dashboard is already serving: pf
	// anchors reload without holding the web UI hostage
	if _, err := enf.StartupReconcile(); err != nil {
		fmt.Printf("[blocks] reconcile error: %v\n", err)
	}
	if enf.Paused() {
		fmt.Println("[blocks] blocking is PAUSED — stored rules stay " +
			"unenforced until resumed from the dashboard")
	}

	if *openBrowserFlag || cfg.GetBool("open_browser", false) {
		openBrowser(url)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	select {
	case <-sigCh:
		fmt.Println("\nshutting down...")
		for _, col := range ctx.Collectors() {
			col.Stop()
		}
		shield.Stop()
		store.Stop()
		srv.Close()
	case err := <-serveErr:
		log.Printf("server error: %v", err)
	}
	_ = store.Close()
}

func pyBool(v any) string {
	if b, ok := v.(bool); ok && b {
		return "True"
	}
	if b, ok := v.(bool); ok && !b {
		return "False"
	}
	return fmt.Sprintf("%v", v)
}

// openBrowser mirrors webbrowser.open() for the supported platforms.
func openBrowser(url string) {
	var cmd *exec.Cmd
	if browser := os.Getenv("BROWSER"); browser != "" {
		parts := strings.Fields(browser)
		cmd = exec.Command(parts[0], append(parts[1:], url)...)
	} else if runtime.GOOS == "windows" {
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	} else if runtime.GOOS == "darwin" {
		cmd = exec.Command("open", url)
	} else {
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}

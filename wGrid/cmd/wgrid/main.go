// wGrid — known-IP intelligence for wHawk (AppDeck).
//
// Fetches published network ranges of well-known providers on a schedule
// (http feeds, local files, or git repos), keeps a bundled static seed for
// providers without feeds, and serves both over loopback so wHawk can
// label/suppress known endpoints. IPolice is the only component of the pair
// that talks to the internet. The dashboard can also match installed apps
// (via wPurge) against a catalog of official vendor feeds.
package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"
)

const Version = "1.2"

func main() {
	var (
		host        = flag.String("host", "127.0.0.1", "bind address")
		port        = flag.Int("port", 8770, "port to serve on")
		dataFl      = flag.String("data", "", "data directory (default APPDECK_DATA or ./data)")
		refreshHrs  = flag.Float64("refresh-hours", 24, "hours between feed refreshes")
		wpurgeURL  = flag.String("wpurge-url", "", "wPurge base URL for installed-app scanning (default WPURGE_URL or http://127.0.0.1:8212)")
		whawkURL = flag.String("whawk-url", "", "wHawk base URL for status wiring (default WHAWK_URL or http://127.0.0.1:8899; auto-discovered via the launcher when possible)")
		launcherURL = flag.String("launcher-url", "", "AppDeck launcher URL for peer discovery (default APPDECK_URL or http://127.0.0.1:9090)")
	)
	flag.Parse()

	dataDir := *dataFl
	if dataDir == "" {
		dataDir = os.Getenv("APPDECK_DATA")
	}
	if dataDir == "" {
		dataDir = "data"
	}
	if *port == 8770 {
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
	desc := *wpurgeURL
	if desc == "" {
		desc = os.Getenv("WPURGE_URL")
	}
	if desc == "" {
		desc = wpurgeDefaultURL
	}
	sent := *whawkURL
	if sent == "" {
		sent = os.Getenv("WHAWK_URL")
	}
	if sent == "" {
		sent = whawkDefaultURL
	}
	launch := *launcherURL
	if launch == "" {
		launch = os.Getenv("APPDECK_URL")
	}
	if launch == "" {
		launch = launcherDefaultURL
	}

	fmt.Printf("wGrid %s — known-IP intelligence for wHawk\n", Version)
	fmt.Printf("  data dir : %s\n", dataDir)
	fmt.Printf("  refresh  : every %.0fh\n", *refreshHrs)
	fmt.Printf("  wpurge : %s\n", desc)

	intel := NewIntel(dataDir, time.Duration(*refreshHrs*float64(time.Hour)))
	intel.Load()
	stop := make(chan struct{})
	go intel.RefreshLoop(stop)

	addr := net.JoinHostPort(*host, strconv.Itoa(*port))
	srv := &Server{
		intel:   intel,
		descale: NewwPurgeClient(desc),
		wired:   NewWired(launch, sent, desc),
	}
	fmt.Printf("  serving  : http://%s  (started %s)\n", addr, time.Now().Format("15:04:05"))
	if err := http.ListenAndServe(addr, hostGuard(*host, srv.routes())); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

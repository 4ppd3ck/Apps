package main

// Small shared helpers the feed carries — copied from the wTower merge so
// the app stays stdlib-only and self-contained.

import (
	"os"
	"strings"
	"time"
)

// appVersion mirrors app.json's version.
const appVersion = "1.0"

// launcherDefaultURL is the AppDeck dashboard, whose /api/apps registry is
// the authoritative port book for launcher-spawned peers.
const launcherDefaultURL = "http://127.0.0.1:9090"

// Now returns the current unix epoch seconds (time.time()).
func Now() float64 {
	return float64(time.Now().UnixNano()) / 1e9
}

// FmtErr renders an error as text ("" for nil) — the feed endpoints lean
// on it everywhere.
func FmtErr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// launcherURL is the dashboard base URL: APPDECK_LAUNCHER_URL when the
// launcher injected it, the well-known default otherwise.
func launcherURL() string {
	if v := os.Getenv("APPDECK_LAUNCHER_URL"); v != "" {
		return strings.TrimRight(v, "/")
	}
	return launcherDefaultURL
}

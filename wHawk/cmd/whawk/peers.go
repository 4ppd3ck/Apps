package main

// Peer discovery + state migration helpers (the launcher-era glue the
// original standalone app predated): the launcher's /api/apps registry is
// the authoritative port book for auto-assigned sibling apps, and the
// merged-apps detour left the watchdog state one folder deeper than this
// app reads it.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// launcherDefaultURL is the AppDeck dashboard, whose /api/apps registry is
// the authoritative port book for launcher-spawned peers.
const launcherDefaultURL = "http://127.0.0.1:9090"

func launcherURL() string {
	if v := os.Getenv("APPDECK_LAUNCHER_URL"); v != "" {
		return v
	}
	return launcherDefaultURL
}

// discoverPeerURL asks the launcher's /api/apps registry where the app with
// the given id currently serves ("" when unreachable or not listed).
func discoverPeerURL(launcher, id string) string {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(launcher + "/api/apps")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var apps []struct {
		ID   string `json:"id"`
		Port int    `json:"port"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&apps) != nil {
		return ""
	}
	for _, a := range apps {
		if a.ID == id && a.Port != 0 {
			return fmt.Sprintf("http://127.0.0.1:%d", a.Port)
		}
	}
	return ""
}

// migrateWatchdogState files comes from two older layouts this app's own
// readers predate:
//   - the merged wTower install kept the state one folder deeper
//     (<APPDECK_DATA>/watchdog/) — the layout wTower's migration wrote;
//   - a previous launcher-era run of THIS app under its merged packaging
//     may have done the same.
//
// Files at the top level win (never overwritten); anything the watchdog
// subfolder has that the top level lacks is copied up once, logged.
func migrateWatchdogState(dataDir string) {
	if dataDir == "" {
		return
	}
	sub := filepath.Join(dataDir, "watchdog")
	if fi, err := os.Stat(sub); err != nil || !fi.IsDir() {
		return
	}
	var moved []string
	for _, name := range []string{
		"rules.user.json", "exclusions.json", "alerts.json",
		"baseline.json", "tcc-removed-backup.jsonl",
	} {
		dst := filepath.Join(dataDir, name)
		if _, err := os.Stat(dst); err == nil {
			continue // top level already has it — never overwrite
		}
		raw, err := os.ReadFile(filepath.Join(sub, name))
		if err != nil {
			continue
		}
		if err := os.WriteFile(dst, raw, 0o644); err != nil {
			fmt.Printf("[whawk] migrate %s: %v\n", name, err)
			continue
		}
		moved = append(moved, name)
	}
	if len(moved) > 0 {
		fmt.Printf("[whawk] migrated watchdog state from watchdog/: %v\n", moved)
	}
}

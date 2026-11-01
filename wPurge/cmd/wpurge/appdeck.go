package main

/* AppDeck bridge.
 *
 * The Uninstall tab's AppDeck sub-list is AppDeck's own app registry,
 * queried live from the launcher (127.0.0.1:9090/api/apps), so an app
 * added in AppDeck shows up in Descale immediately. Uninstalling delegates
 * to AppDeck's /api/uninstall: the launcher stops the app, removes its
 * folder and records the removal exactly as its own dashboard does — same
 * semantics, same rules (registry apps are refused there, and the reason
 * is surfaced here verbatim).
 *
 * When the launcher is not running, the list falls back to scanning the
 * Apps folder's app.json manifests (minus the ids in AppDeck's
 * uninstalled.json) and Descale removes the folder to the Trash itself,
 * journalled and restorable, recording the id in uninstalled.json so an
 * embedded launcher does not resurrect the app on its next start.
 */

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// appDeckAPIBase is overridable so the tests can point the bridge at a
// fake launcher.
var appDeckAPIBase = "http://127.0.0.1:9090"

// appDeckDataRoot is AppDeck's per-user data directory.
func appDeckDataRoot() string {
	return filepath.Dir(appDeckAppsDir())
}

// appDeckApp is the slice of AppDeck's /api/apps status payload Descale
// uses. Apps with Hidden manifests never appear in that payload.
type appDeckApp struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Source  string `json:"source"` // registry | manifest | discovered
	Running bool   `json:"running"`
}

// errAppDeckDown marks "no launcher answered", the one bridge failure that
// has a local fallback. Every other failure (refused uninstall, bad JSON)
// is a real error the caller must surface.
var errAppDeckDown = errors.New("AppDeck is not running")

func appDeckGet(path string, out any) error {
	client := &http.Client{Timeout: 2500 * time.Millisecond}
	resp, err := client.Get(appDeckAPIBase + path)
	if err != nil {
		return errAppDeckDown
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("AppDeck returned 404 for %s (version too old?)", path)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("AppDeck returned HTTP %d for %s", resp.StatusCode, path)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// listAppDeckApps lists every AppDeck app. Live launcher first; manifest
// scan fallback when it is down. Each entry's Path is the Apps/<id>
// folder AppDeck manages — that folder is the install.
func listAppDeckApps() []AppInfo {
	if apps, err := appDeckListLive(); err == nil {
		return apps
	}
	return appDeckListFromManifests()
}

func appDeckListLive() ([]AppInfo, error) {
	var status []appDeckApp
	if err := appDeckGet("/api/apps", &status); err != nil {
		return nil, err
	}
	out := make([]AppInfo, 0, len(status))
	for _, a := range status {
		if a.ID == "" {
			continue
		}
		name := a.Name
		if name == "" {
			name = a.ID
		}
		out = append(out, AppInfo{
			Path:    filepath.Join(appDeckAppsDir(), a.ID),
			Name:    name,
			ID:      a.ID,
			Version: a.Version,
			Kind:    "appdeck",
			Scope:   "appdeck",
			Source:  a.Source,
			Running: a.Running,
		})
	}
	return out, nil
}

// appDeckListFromManifests: the launcher-down inventory. Every
// Apps/<id>/app.json is an app; ids listed in uninstalled.json were
// removed from this install and stay gone.
func appDeckListFromManifests() []AppInfo {
	uninstalled := map[string]bool{}
	raw, _ := os.ReadFile(filepath.Join(appDeckDataRoot(), "uninstalled.json"))
	var ids []string
	if json.Unmarshal(raw, &ids) == nil {
		for _, id := range ids {
			uninstalled[id] = true
		}
	}
	entries, err := os.ReadDir(appDeckAppsDir())
	if err != nil {
		return nil
	}
	var out []AppInfo
	for _, e := range entries {
		id := e.Name()
		if !e.IsDir() || strings.HasPrefix(id, ".") || uninstalled[id] {
			continue
		}
		manifest := filepath.Join(appDeckAppsDir(), id, "app.json")
		data, err := os.ReadFile(manifest)
		if err != nil {
			continue
		}
		var m struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			Version string `json:"version"`
			Hidden  bool   `json:"hidden"`
		}
		if json.Unmarshal(data, &m) != nil || m.Hidden {
			continue
		}
		name, mid := m.Name, m.ID
		if mid == "" {
			mid = id
		}
		if name == "" {
			name = mid
		}
		out = append(out, AppInfo{
			Path:    filepath.Join(appDeckAppsDir(), id),
			Name:    name,
			ID:      mid,
			Version: m.Version,
			Kind:    "appdeck",
			Scope:   "appdeck",
			Source:  "manifest",
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// appDeckUninstall delegates the uninstall to a running launcher. It
// returns the launcher's note on success; errAppDeckDown when no launcher
// answered (caller falls back to local removal); any other error verbatim
// (e.g. "registered in apps.json — remove its entry there first") with
// nothing removed.
func appDeckUninstall(id string) (string, error) {
	body, _ := json.Marshal(map[string]any{"id": id, "removeData": false})
	req, err := http.NewRequest(http.MethodPost, appDeckAPIBase+"/api/uninstall", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return "", errAppDeckDown
	}
	defer resp.Body.Close()
	var out struct {
		OK    bool   `json:"ok"`
		Note  string `json:"note"`
		Error string `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	switch {
	case resp.StatusCode == http.StatusOK && out.OK:
		return out.Note, nil
	case out.Error != "":
		return "", errors.New(out.Error)
	default:
		return "", fmt.Errorf("AppDeck returned HTTP %d", resp.StatusCode)
	}
}

// recordAppDeckUninstalled appends the id to AppDeck's uninstalled.json so
// an embedded launcher (whose payload still carries the app) does not
// resurrect it on the next start. Mirrors AppDeck's own markAppUninstalled
// format. Best-effort: without the file an embedded launcher re-extracts
// the app, which is visible and fixable, not silent data loss.
func recordAppDeckUninstalled(id string) {
	path := filepath.Join(appDeckDataRoot(), "uninstalled.json")
	ids := map[string]bool{}
	raw, _ := os.ReadFile(path)
	var list []string
	if json.Unmarshal(raw, &list) == nil {
		for _, v := range list {
			if v != "" {
				ids[v] = true
			}
		}
	}
	if ids[id] {
		return
	}
	ids[id] = true
	list = list[:0]
	for v := range ids {
		list = append(list, v)
	}
	sort.Strings(list)
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	tmp := path + ".tmp"
	if os.WriteFile(tmp, append(data, '\n'), 0o644) == nil {
		_ = os.Rename(tmp, path)
	}
}

// appDeckBundleID sniffs the bundle id out of a .app bundle inside an
// AppDeck app folder (some apps, like Descale itself, are wrapped apps).
// The leftover hunt keys off it; empty when the folder holds no bundle.
func appDeckBundleID(folder string) string {
	matches, _ := filepath.Glob(filepath.Join(folder, "*.app"))
	for _, b := range matches {
		if d, err := readPlist(filepath.Join(b, "Contents", "Info.plist")); err == nil {
			if v, ok := d["CFBundleIdentifier"].(string); ok && v != "" {
				return v
			}
		}
	}
	return ""
}

package main

// Persistence scan: launch agents/daemons, cron, autostart, systemd user
// units, Windows Run keys & startup folders. New entries vs baseline alert.
// (Detection only — removal is manual by design.)

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

type PersistItem struct {
	Kind   string  `json:"kind"` // launchagent | launchdaemon | cron | autostart | systemd-user | run-key | startup-folder
	Name   string  `json:"name"`
	Path   string  `json:"path,omitempty"`
	Detail string  `json:"detail,omitempty"`
	Mtime  float64 `json:"mtime,omitempty"`
}

func persistItems() ([]PersistItem, error) {
	switch runtime.GOOS {
	case "darwin":
		return persistDarwin()
	case "linux", "freebsd", "openbsd", "netbsd":
		return persistPOSIX()
	case "windows":
		return persistWindows()
	}
	return nil, fmt.Errorf("persistence scan unavailable on %s", runtime.GOOS)
}

func persistDarwin() ([]PersistItem, error) {
	home, _ := os.UserHomeDir()
	dirs := []struct {
		path, kind string
	}{
		{filepath.Join(home, "Library", "LaunchAgents"), "launchagent"},
		{"/Library/LaunchAgents", "launchagent"},
		{"/Library/LaunchDaemons", "launchdaemon"},
	}
	items := []PersistItem{}
	for _, d := range dirs {
		ents, err := os.ReadDir(d.path)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".plist") {
				continue
			}
			full := filepath.Join(d.path, e.Name())
			info, err := e.Info()
			mt := float64(0)
			if err == nil {
				mt = float64(info.ModTime().UnixNano()) / 1e9
			}
			detail := ""
			if raw, err := os.ReadFile(full); err == nil {
				s := string(raw)
				if i := strings.Index(s, "<key>ProgramArguments</key>"); i >= 0 {
					chunk := s[i:]
					if j := strings.Index(chunk, "</array>"); j > 0 {
						chunk = chunk[:j]
					}
					detail = firstLine(chunk, 200)
				} else if i := strings.Index(s, "<key>Program</key>"); i >= 0 {
					detail = firstLine(s[i:], 200)
				}
				if strings.Contains(s, "RunAtLoad") || strings.Contains(s, "KeepAlive") {
					detail += " [auto-run]"
				}
			}
			items = append(items, PersistItem{Kind: d.kind, Name: e.Name(),
				Path: full, Detail: detail, Mtime: mt})
		}
	}
	if out, err := RunOut(5*time.Second, "sh", "-c", "crontab -l 2>/dev/null"); err == nil && out != "" {
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			items = append(items, PersistItem{Kind: "cron", Name: "crontab",
				Detail: line})
		}
	}
	return items, nil
}

func persistPOSIX() ([]PersistItem, error) {
	home, _ := os.UserHomeDir()
	items := []PersistItem{}
	dirs := []struct {
		path, kind string
	}{
		{filepath.Join(home, ".config", "autostart"), "autostart"},
		{filepath.Join(home, ".config", "systemd", "user"), "systemd-user"},
		{"/etc/systemd/system", "systemd-user"},
		{"/etc/xdg/autostart", "autostart"},
	}
	for _, d := range dirs {
		ents, err := os.ReadDir(d.path)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if e.IsDir() || !(strings.HasSuffix(e.Name(), ".desktop") || strings.HasSuffix(e.Name(), ".service")) {
				continue
			}
			full := filepath.Join(d.path, e.Name())
			info, _ := e.Info()
			mt := float64(0)
			if info != nil {
				mt = float64(info.ModTime().UnixNano()) / 1e9
			}
			detail := ""
			if raw, err := os.ReadFile(full); err == nil {
				detail = firstLine(string(raw), 200)
			}
			items = append(items, PersistItem{Kind: d.kind, Name: e.Name(),
				Path: full, Detail: detail, Mtime: mt})
		}
	}
	if out, err := RunOut(5*time.Second, "sh", "-c", "crontab -l 2>/dev/null"); err == nil && out != "" {
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			items = append(items, PersistItem{Kind: "cron", Name: "crontab", Detail: line})
		}
	}
	return items, nil
}

func persistWindows() ([]PersistItem, error) {
	items := []PersistItem{}
	keys := []struct {
		key, kind string
	}{
		{`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, "run-key"},
		{`HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`, "run-key"},
		{`HKLM\Software\Microsoft\Windows\CurrentVersion\Run`, "run-key"},
		{`HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`, "run-key"},
	}
	for _, k := range keys {
		out, err := RunOut(10*time.Second, "reg", "query", k.key)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "HKEY_") || strings.HasPrefix(line, "The operation completed") {
				continue
			}
			items = append(items, PersistItem{Kind: k.kind, Name: k.key, Detail: line})
		}
	}
	home, _ := os.UserHomeDir()
	for _, dir := range []string{
		filepath.Join(home, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
		`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup`,
	} {
		ents, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if e.IsDir() {
				continue
			}
			items = append(items, PersistItem{Kind: "startup-folder",
				Name: e.Name(), Path: filepath.Join(dir, e.Name())})
		}
	}
	return items, nil
}

func persistFindings(store *Store) []Finding {
	items, err := persistItems()
	if err != nil {
		return []Finding{{
			Check: "persistence", Severity: SevInfo,
			Title: "Persistence scan unavailable", Detail: FmtErr(err),
		}}
	}
	// fingerprint each item: kind|name|path|detail
	cur := map[string]PersistItem{}
	for _, it := range items {
		fp := FingerprintOf("persist", it.Kind+"|"+it.Name+"|"+it.Path+"|"+it.Detail)
		cur[fp] = it
	}
	prevVal, existed := store.BaselineKey("persistence", mapKeys(cur))
	findings := []Finding{}
	if existed {
		prev, _ := prevVal.(map[string]any)
		for fp, it := range cur {
			if _, known := prev[fp]; known {
				continue
			}
			sev := SevLow
			note := ""
			if looksSuspiciousPersist(it) {
				sev = SevHigh
				note = " The target sits in a temp path or references script " +
					"downloaders — a classic stager persistence entry."
			}
			findings = append(findings, Finding{
				Check:    "persistence",
				Severity: sev,
				Title:    fmt.Sprintf("New auto-start entry: %s (%s)", it.Name, it.Kind),
				Detail: fmt.Sprintf("%s%s First seen %s. If you did not install "+
					"this, remove it and investigate what wrote it.",
					it.Path, note, time.Unix(int64(it.Mtime), 0).Format("2006-01-02")),
				Evidence: map[string]any{
					"kind": it.Kind, "name": it.Name, "path": it.Path,
					"detail": it.Detail, "fingerprint": fp,
				},
				Fingerprint: FingerprintOf("persist_new", fp),
			})
		}
	}
	// refresh baseline
	rebuilt := map[string]any{}
	for fp, it := range cur {
		rebuilt[fp] = it
	}
	store.BaselineUpdate("persistence", rebuilt)
	return findings
}

func mapKeys[V any](m map[string]V) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		out[k] = v
	}
	return out
}

func looksSuspiciousPersist(it PersistItem) bool {
	ls := strings.ToLower(it.Path + " " + it.Detail)
	if runsFromTemp(it.Path) {
		return true
	}
	for _, tok := range []string{"curl ", "wget ", "invoke-webrequest", "iex ", "iex(",
		"base64", "certutil", "bitsadmin", "nc ", "ncat", "/dev/tcp", "osascript -e"} {
		if strings.Contains(ls, tok) {
			return true
		}
	}
	return false
}

func firstLine(s string, max int) string {
	sc := bufio.NewScanner(strings.NewReader(s))
	out := ""
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "<key>") || line == "<array>" || line == "</array>" || line == "<dict>" || line == "</dict>" {
			continue
		}
		out = strings.Trim(line, "<>")
		break
	}
	out = strings.TrimPrefix(out, "string>")
	if len(out) > max {
		out = out[:max] + "…"
	}
	return out
}

func sortItems(items []PersistItem) {
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
}

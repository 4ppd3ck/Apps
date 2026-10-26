package main

// Credential / keystroke / screen-capture exfiltration indicators:
//   - macOS: TCC permission grants (Accessibility, Input Monitoring /
//     ListenEvent, ScreenCapture, PostEvent) — new clients vs baseline
//   - per-OS: process-name heuristics for keyloggers/clipboard grabbers
//   - correlation with AppScope Monitor: privacy events (camera/mic) and
//     sensitive-file events paired with live outbound connections

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// macOS TCC services worth watching, with plain-language labels.
var tccWatch = map[string]string{
	"kTCCServiceAccessibility":                "Accessibility (key injection/reading)",
	"kTCCServiceListenEvent":                  "Input Monitoring (global keystrokes)",
	"kTCCServicePostEvent":                    "Send keystrokes (synthetic input)",
	"kTCCServiceScreenCapture":                "Screen recording",
	"kTCCServiceCamera":                       "Camera",
	"kTCCServiceMicrophone":                   "Microphone",
	"kTCCServiceAppleEvents":                  "Control other apps (AppleEvents)",
	"kTCCServiceSystemPolicyAllFiles":         "Full Disk Access",
	"kTCCServiceSystemPolicyDesktopFolder":    "Desktop folder",
	"kTCCServiceSystemPolicyDocumentsFolder":  "Documents folder",
	"kTCCServiceSystemPolicyDownloadsFolder":  "Downloads folder",
	"kTCCServiceSystemPolicyNetworkVolumes":   "Network volumes",
	"kTCCServiceSystemPolicyRemovableVolumes": "Removable volumes",
	"kTCCServiceSystemPolicyAppData":          "Other app data",
	"kTCCServiceSystemPolicySysAdminFiles":    "System administration files",
	"kTCCServiceSystemPolicyDeveloperFiles":   "Developer files",
	"kTCCServiceBluetoothAlways":              "Bluetooth",
	"kTCCServiceSpeechRecognition":            "Speech recognition",
	"kTCCServiceLocalNetwork":                 "Local network devices",
}

// tccRow is one access row from a TCC database. DB records which database
// the row came from ("user" or "system") — system rows need root to remove.
type tccRow struct {
	Service, Client, Auth, LastUsed string
	DB                              string
}

func tccEntries() ([]tccRow, error) {
	if runtime.GOOS != "darwin" {
		return nil, fmt.Errorf("TCC is macOS-only")
	}
	home, _ := os.UserHomeDir()
	dbs := []struct {
		path, label string
	}{
		{filepath.Join(home, "Library", "Application Support", "com.apple.TCC", "TCC.db"), "user"},
		{"/Library/Application Support/com.apple.TCC/TCC.db", "system"},
	}
	rows := []tccRow{}
	var lastErr error
	for _, db := range dbs {
		out, err := RunOut(8*time.Second, "sqlite3", "-csv", db.path,
			"select service, client, auth_value, last_used_time from access;")
		if err != nil {
			// Older TCC schemas do not expose last_used_time.
			out, err = RunOut(8*time.Second, "sqlite3", "-csv", db.path,
				"select service, client, auth_value from access;")
			if err != nil {
				lastErr = err
				continue // unreadable (needs Full Disk Access) — try the next db
			}
		}
		reader := csv.NewReader(strings.NewReader(out))
		reader.FieldsPerRecord = -1
		for {
			fields, readErr := reader.Read()
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				return nil, readErr
			}
			if len(fields) >= 3 {
				row := tccRow{Service: fields[0], Client: fields[1], Auth: fields[2], DB: db.label}
				if len(fields) >= 4 {
					row.LastUsed = fields[3]
				}
				rows = append(rows, row)
			}
		}
	}
	if len(rows) > 0 {
		return rows, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no TCC database returned permission rows")
	}
	return nil, fmt.Errorf("TCC.db unreadable — grant Sentinel's terminal Full Disk Access for permission-change tracking: %w", lastErr)
}

func exfilFindings(store *Store, rules *Rules, procs []Proc,
	monEvents []MonitorEvent, monConns []MonitorConn, now float64,
	intel *Intel) []Finding {

	findings := []Finding{}

	// ---- macOS TCC permission grants
	if runtime.GOOS == "darwin" {
		rows, err := tccEntries()
		if err != nil {
			findings = append(findings, Finding{
				Check: "tcc", Severity: SevInfo,
				Title:  "Permission database not readable",
				Detail: FmtErr(err),
			})
		} else {
			cur := map[string]string{} // "service|client" -> auth
			for _, r := range rows {
				cur[r.Service+"|"+r.Client] = r.Auth
			}
			prevVal, existed := store.BaselineKey("tcc", mapToAny(cur))
			if existed {
				prev, _ := prevVal.(map[string]any)
				for key, auth := range cur {
					prevAuth, known := prev[key]
					if known && fmt.Sprint(prevAuth) == auth {
						continue
					}
					parts := strings.SplitN(key, "|", 2)
					svc, client := parts[0], parts[1]
					label, watched := tccWatch[svc]
					if !watched || auth == "0" || auth == "1" { // denied/undetermined
						continue
					}
					lc := strings.ToLower(client)
					suspicious := StrHasAny(lc, rules.BadTCCClient) ||
						strings.Contains(lc, "temp") || strings.HasPrefix(lc, "python")
					sev := SevMedium
					if suspicious {
						sev = SevHigh
					}
					findings = append(findings, Finding{
						Check:    "tcc_grant",
						Severity: sev,
						Title:    fmt.Sprintf("New %s grant: %s", label, client),
						Detail: fmt.Sprintf("%s was granted %s (auth=%s). These are "+
							"the exact permissions keystroke loggers, screen "+
							"scrapers and remote-control implants ask for. If you "+
							"did not knowingly grant this, remove it in System "+
							"Settings → Privacy & Security.", client, label, auth),
						Evidence: map[string]any{
							"service": svc, "client": client, "auth": auth,
						},
						Fingerprint: FingerprintOf("tcc_grant", key+"|"+auth),
					})
				}
			}
			store.BaselineUpdate("tcc", mapToAny(cur))
		}
	}

	// ---- keylogger-ish / clipboard-grabber process names (all OS)
	for _, p := range procs {
		lname := strings.ToLower(p.Name)
		for _, tok := range []string{"keylog", "logkeys", "kidlog", "refog",
			"hookhook", "keyboardhook", "clipb"} {
			if strings.Contains(lname, tok) {
				findings = append(findings, Finding{
					Check:    "keylogger_name",
					Severity: SevHigh,
					Title:    fmt.Sprintf("Possible keystroke monitor running: %s", p.Name),
					Detail: fmt.Sprintf("pid %d (%s) matches keylogger/clipboard-"+
						"monitor naming patterns.", p.Pid, p.Path),
					Evidence: map[string]any{"pid": p.Pid, "path": p.Path},
					Fingerprint: FingerprintOf("keylogger_name",
						p.Name+"|"+fmt.Sprint(p.Pid)),
				})
				break
			}
		}
	}

	// ---- correlate AppScope Monitor privacy/file events with live outbound
	// connections from the same app: surveillance tooling phones home.
	connsByApp := map[string][]MonitorConn{}
	for _, c := range monConns {
		if strings.HasPrefix(strings.ToUpper(c.State), "ESTAB") && IsExternal(c.RemoteIP, rules) {
			connsByApp[strings.ToLower(c.App)] = append(connsByApp[strings.ToLower(c.App)], c)
		}
	}
	for _, e := range monEvents {
		app := strings.ToLower(FmtAny(e.App))
		if app == "" {
			continue
		}
		// Windows/Linux collectors emit start/stop transitions, macOS streams
		// momentary *_access observations — all mean "the device was used"
		what := ""
		switch strings.ToLower(strings.TrimSpace(FmtAny(e.Kind))) {
		case "camera_start", "camera_access":
			what = "camera"
		case "mic_start", "mic_access", "microphone_start", "microphone_access":
			what = "microphone"
		}
		if what != "" {
			if cs, ok := connsByApp[app]; ok && len(cs) > 0 {
				c := cs[0]
				sev := SevHigh
				knownNote := ""
				if prov, known := intel.KnownRemote(c.RemoteIP); known {
					// a call to a known provider (Meet, Teams, Zoom's own
					// ranges…) is expected — keep it visible but calm
					sev = SevMedium
					knownNote = fmt.Sprintf(" The peer is a known %s range "+
						"(IPolice) — expected for calls.", prov)
				}
				// target names the device the way the Live Access row shows
				// it (device path when the platform reports one, the plain
				// kind otherwise) so a per-target exclusion made from that
				// row's popup button silences this correlation too
				evTarget := strings.TrimSpace(FmtAny(e.Path))
				if evTarget == "" {
					evTarget = what
				}
				findings = append(findings, Finding{
					Check:    "privacy_exfil",
					Severity: sev,
					Title: fmt.Sprintf("%s active in %s while it talks to %s",
						what, e.App, c.RemoteIP),
					Detail: fmt.Sprintf("AppScope Monitor saw the %s turn on for "+
						"this app, and the same app currently holds an outbound "+
						"connection to a public address%s. Expected for a video "+
						"call; otherwise it is spyware behaviour.%s",
						what, hostSuffix(c.Host), knownNote),
					Evidence: map[string]any{
						"app": e.App, "event": e.Kind, "ts": e.Ts,
						"target": evTarget,
						"remote": c.RemoteIP + ":" + fmt.Sprint(c.RemotePortInt()),
						"host":   c.Host,
					},
					Fingerprint: FingerprintOf("privacy_exfil",
						what+"|"+app+"|"+fmt.Sprint(int64(e.Ts/1800))),
				})
			}
			continue
		}
		if e.Category == "file" && e.Path != nil {
			p := strings.ToLower(FmtAny(e.Path))
			if StrHasAny(p, rules.SensitivePaths) {
				if cs, ok := connsByApp[app]; ok && len(cs) > 0 {
					c := cs[0]
					sev := SevHigh
					knownNote := ""
					if prov, known := intel.KnownRemote(c.RemoteIP); known {
						sev = SevMedium
						knownNote = fmt.Sprintf(" The peer is a known %s "+
							"range (IPolice) — downgraded, still worth a "+
							"glance.", prov)
					}
					findings = append(findings, Finding{
						Check:    "file_exfil",
						Severity: sev,
						Title: fmt.Sprintf("Sensitive file access with live "+
							"outbound: %s", e.App),
						Detail: fmt.Sprintf("%s touched %q — which matches your "+
							"sensitive-path list — while holding an outbound "+
							"connection to %s%s. Credential/keychain readers "+
							"behave exactly like this.%s",
							e.App, p, c.RemoteIP, hostSuffix(c.Host), knownNote),
						Evidence: map[string]any{
							"app": e.App, "path": FmtAny(e.Path), "kind": e.Kind,
							"remote": c.RemoteIP, "ts": e.Ts,
						},
						Fingerprint: FingerprintOf("file_exfil",
							app+"|"+p+"|"+fmt.Sprint(int64(e.Ts/1800))),
					})
				}
			}
		}
	}
	return findings
}

func mapToAny(m map[string]string) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		out[k] = v
	}
	return out
}

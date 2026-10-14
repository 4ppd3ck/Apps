package main

// Credential / keystroke / screen-capture exfiltration indicators:
//   - macOS: TCC permission grants (Accessibility, Input Monitoring /
//     ListenEvent, ScreenCapture, PostEvent) — new clients vs baseline
//   - per-OS: process-name heuristics for keyloggers/clipboard grabbers
//   - correlation with AppScope Monitor: privacy events (camera/mic) and
//     sensitive-file events paired with live outbound connections

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// macOS TCC services worth watching, with plain-language labels.
var tccWatch = map[string]string{
	"kTCCServiceAccessibility":        "Accessibility (key injection/reading)",
	"kTCCServiceListenEvent":          "Input Monitoring (global keystrokes)",
	"kTCCServicePostEvent":            "Send keystrokes (synthetic input)",
	"kTCCServiceScreenCapture":        "Screen recording",
	"kTCCServiceAppleEvents":          "Control other apps (AppleEvents)",
	"kTCCServiceSystemPolicyAllFiles": "Full Disk Access",
}

func tccEntries() ([][3]string, error) {
	if runtime.GOOS != "darwin" {
		return nil, fmt.Errorf("TCC is macOS-only")
	}
	home, _ := os.UserHomeDir()
	dbs := []string{
		filepath.Join(home, "Library", "Application Support", "com.apple.TCC", "TCC.db"),
		"/Library/Application Support/com.apple.TCC/TCC.db",
	}
	for _, db := range dbs {
		out, err := RunOut(8*time.Second, "sqlite3", "-csv", db,
			"select service, client, auth_value from access;")
		if err != nil {
			continue // unreadable (needs Full Disk Access) — try the next db
		}
		rows := [][3]string{}
		for _, line := range strings.Split(out, "\n") {
			f := strings.Split(strings.TrimSpace(line), ",")
			if len(f) >= 3 {
				rows = append(rows, [3]string{f[0], f[1], f[2]})
			}
		}
		return rows, nil
	}
	return nil, fmt.Errorf("TCC.db unreadable — grant Sentinel's terminal Full Disk Access for permission-change tracking")
}

func exfilFindings(store *Store, rules *Rules, procs []Proc,
	monEvents []MonitorEvent, monConns []MonitorConn, now float64) []Finding {

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
				cur[r[0]+"|"+r[1]] = r[2]
			}
			prevVal, existed := store.BaselineKey("tcc", mapToAny(cur))
			if existed {
				prev, _ := prevVal.(map[string]any)
				for key, auth := range cur {
					if _, known := prev[key]; known {
						continue
					}
					parts := strings.SplitN(key, "|", 2)
					svc, client := parts[0], parts[1]
					label, watched := tccWatch[svc]
					if !watched || auth == "0" || auth == "2" { // denied/absent
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
		switch e.Kind {
		case "camera_start", "mic_start":
			if cs, ok := connsByApp[app]; ok && len(cs) > 0 {
				c := cs[0]
				findings = append(findings, Finding{
					Check:    "privacy_exfil",
					Severity: SevHigh,
					Title: fmt.Sprintf("%s active in %s while it talks to %s",
						strings.TrimSuffix(e.Kind, "_start"), e.App, c.RemoteIP),
					Detail: fmt.Sprintf("AppScope Monitor saw the %s turn on for "+
						"this app, and the same app currently holds an outbound "+
						"connection to a public address%s. Expected for a video "+
						"call; otherwise it is spyware behaviour.",
						strings.TrimSuffix(e.Kind, "_start"), hostSuffix(c.Host)),
					Evidence: map[string]any{
						"app": e.App, "event": e.Kind, "ts": e.Ts,
						"remote": c.RemoteIP + ":" + fmt.Sprint(c.RemotePortInt()),
						"host":   c.Host,
					},
					Fingerprint: FingerprintOf("privacy_exfil",
						e.Kind+"|"+app+"|"+fmt.Sprint(int64(e.Ts/1800))),
				})
			}
		default:
			if e.Category == "file" && e.Path != nil {
				p := strings.ToLower(FmtAny(e.Path))
				if StrHasAny(p, rules.SensitivePaths) {
					if cs, ok := connsByApp[app]; ok && len(cs) > 0 {
						c := cs[0]
						findings = append(findings, Finding{
							Check:    "file_exfil",
							Severity: SevHigh,
							Title: fmt.Sprintf("Sensitive file access with live "+
								"outbound: %s", e.App),
							Detail: fmt.Sprintf("%s touched %q — which matches your "+
								"sensitive-path list — while holding an outbound "+
								"connection to %s%s. Credential/keychain readers "+
								"behave exactly like this.",
								e.App, p, c.RemoteIP, hostSuffix(c.Host)),
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

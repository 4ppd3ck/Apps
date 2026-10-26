package main

// Live "sensitive access" watch: which apps are holding or attempting
// access to the microphone, camera, password-manager data or sensitive
// files — Sentinel's own per-OS primitives, independent of AppScope Monitor:
//
//   Linux  : /proc/<pid>/fd readlink — V4L2 camera nodes, ALSA capture
//            devices, password stores and sensitive paths open per process
//   macOS  : lsof for open password-manager / sensitive files; TCC
//            last_used_time for per-app camera & microphone use (device
//            holds themselves are not lsof-visible on macOS)
//   Windows: CapabilityAccessManager consent store — per-app webcam and
//            microphone use (in-use-now, last-used timestamp, and denied
//            attempts), packaged apps and classic exes alike
//   BSD    : lsof when installed, fstat otherwise — /dev/video* (webcamd),
//            /dev/dsp* (OSS audio), sensitive paths
//
// Held-device and foreign password-store findings escalate to high when the
// same app also holds an established connection to a public address (same
// fingerprint vocabulary as the monitor-event correlation in exfil.go, so
// the two paths dedupe into one alert instead of two).

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	KindCamera          = "camera"
	KindMicrophone      = "microphone"
	KindPasswordManager = "password_manager"
	KindSensitiveFile   = "sensitive_file"
	MaxRecentUseSeconds = 2 * 60 * 60
)

// SensitiveAccess is one app ↔ sensitive-thing observation.
type SensitiveAccess struct {
	App      string  `json:"app"`
	Pid      int     `json:"pid,omitempty"`
	Kind     string  `json:"kind"` // camera | microphone | password_manager | sensitive_file
	Target   string  `json:"target"`
	Detail   string  `json:"detail,omitempty"`
	Source   string  `json:"source"`
	Live     bool    `json:"live"` // held / in use at scan time
	LastUsed float64 `json:"last_used,omitempty"`
	Denied   bool    `json:"denied,omitempty"` // attempting while the OS refuses
}

// SensitiveSnapshot is the latest scan result, served at /api/sensitive.
type SensitiveSnapshot struct {
	Platform    string            `json:"platform"`
	ScannedAt   float64           `json:"scanned_at"`
	Access      []SensitiveAccess `json:"access"`
	Unavailable string            `json:"unavailable,omitempty"`
	Notes       []string          `json:"notes,omitempty"`
}

// scanSensitive collects the current sensitive-access state for this OS.
func scanSensitive(rules *Rules) SensitiveSnapshot {
	snap := SensitiveSnapshot{
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
		ScannedAt: NowF(), Access: []SensitiveAccess{},
	}
	switch runtime.GOOS {
	case "linux":
		scanProcFDs(&snap, rules)
	case "darwin":
		scanLsofSensitive(&snap, rules)
		scanTCCLastUse(&snap)
		snap.Notes = append(snap.Notes,
			"Camera/microphone device holds are not lsof-visible on macOS; per-app use comes from TCC last-used timestamps (second granularity, macOS 15+) and from AppScope Monitor's privacy event stream when it is running.",
			"lsof lists this user's processes; other users' and root processes need Sentinel's Elevated launch.")
	case "windows":
		scanConsentStore(&snap)
		snap.Notes = append(snap.Notes,
			"Webcam/microphone use comes from the CapabilityAccessManager consent store (classic exes under NonPackaged included).",
			"Windows exposes no supported per-app open-file enumeration; sensitive-file and password-manager access needs AppScope Monitor file events.")
	case "freebsd", "openbsd", "netbsd":
		snap.Notes = append(snap.Notes,
			"BSD has no central privacy-grant database; detection is open-device/open-file based (lsof, or fstat when lsof is not installed).")
		if !scanLsofSensitive(&snap, rules) {
			scanFstatSensitive(&snap, rules)
		}
	default:
		snap.Unavailable = fmt.Sprintf(
			"sensitive-access scanning is not implemented for %s", runtime.GOOS)
	}
	finalizeAccess(&snap.Access)
	return snap
}

// finalizeAccess collapses duplicate observations and sorts the list the way
// every scan path (local scan, monitor merge) hands it to the API.
func finalizeAccess(access *[]SensitiveAccess) {
	*access = dedupeAccess(*access)
	sort.Slice(*access, func(i, j int) bool {
		if (*access)[i].App != (*access)[j].App {
			return strings.ToLower((*access)[i].App) < strings.ToLower((*access)[j].App)
		}
		return (*access)[i].Kind < (*access)[j].Kind
	})
}

// nameOverlap is the case-insensitive containment match exclusions use:
// either name containing the other counts as the same app ("FaceTime"
// vs "com.apple.FaceTime").
func nameOverlap(a, b string) bool {
	la, lb := strings.ToLower(strings.TrimSpace(a)), strings.ToLower(strings.TrimSpace(b))
	if la == "" || lb == "" {
		return false
	}
	return la == lb || strings.Contains(la, lb) || strings.Contains(lb, la)
}

// classifySensitivePath maps an open file/device target to a sensitive kind.
// Empty kind means "not interesting". Device-node checks come first so a
// path can never be both a device and a data file.
func classifySensitivePath(path string, rules *Rules) (kind, note string) {
	if path == "" {
		return "", ""
	}
	if !strings.HasPrefix(path, "/") {
		return "", "" // sockets, pipes, TCP rows, non-POSIX text
	}
	ls := strings.ToLower(path)
	switch {
	case strings.HasPrefix(ls, "/dev/video") || strings.HasPrefix(ls, "/dev/v4l"):
		return KindCamera, "V4L2 video capture device open"
	case strings.HasPrefix(ls, "/dev/snd/pcm") && strings.HasSuffix(ls, "c"):
		return KindMicrophone, "ALSA PCM capture device open"
	case strings.HasPrefix(ls, "/dev/dsp") || strings.HasPrefix(ls, "/dev/audio"):
		return KindMicrophone, "OSS audio capture device open"
	}
	if StrHasAny(path, rules.PasswordManagerPaths) {
		return KindPasswordManager, "password-manager data/store"
	}
	if StrHasAny(path, rules.SensitivePaths) {
		return KindSensitiveFile, "matches sensitive_paths rules"
	}
	return "", ""
}

// managerProcessTokens: process names that legitimately hold password-manager
// data — the managers themselves and their browser-integration helpers.
var managerProcessTokens = []string{
	"1password", "bitwarden", "keepass", "lastpass", "dashlane", "enpass",
	"kwallet", "gnome-keyring", "keyring", "seahorse", "securityd",
	"keychainaccess", "pwsafe", "gopass",
	// Apple's keychain/security infrastructure holds the keychain by design
	"keychain", "secd", "trustedpeers", "cloudkeychain", "akd",
}

// noiseProcessTokens: system services that read everything on disk by design
// (indexers, backup daemons). They are listed in the snapshot but never
// alerted — their access to password stores is not suspicious on its own.
var noiseProcessTokens = []string{
	"mds", "mdworker", "mds_stores", "fseventsd", "spotlight",
	"backupd", "tmhelper", "time machine", "carboncopycloner",
	"chronosync", "restic", "borg", "rsync", "sentinel", "spotlightd",
}

func isManagerProcess(name string) bool { return StrHasAny(name, managerProcessTokens) }
func isNoiseProcess(name string) bool   { return StrHasAny(name, noiseProcessTokens) }

// ------------------------------------------------------------- linux ----

// scanProcFDs walks /proc/<pid>/fd readlinks. Unreadable pids (other users)
// are skipped silently — coverage is this user's processes plus root's when
// Sentinel runs elevated.
func scanProcFDs(snap *SensitiveSnapshot, rules *Rules) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		snap.Unavailable = "sensitive-access scan unavailable: /proc not readable: " + FmtErr(err)
		return
	}
	self := os.Getpid()
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self {
			continue
		}
		fds, err := os.ReadDir(filepath.Join("/proc", e.Name(), "fd"))
		if err != nil {
			continue
		}
		name := procComm(pid)
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join("/proc", e.Name(), "fd", fd.Name()))
			if err != nil {
				continue
			}
			kind, note := classifySensitivePath(target, rules)
			if kind == "" {
				continue
			}
			snap.Access = append(snap.Access, SensitiveAccess{
				App: name, Pid: pid, Kind: kind, Target: target,
				Detail: note, Source: "/proc fd scan", Live: true,
			})
		}
	}
	if len(snap.Access) == 0 {
		snap.Notes = append(snap.Notes,
			"No process currently holds a camera/mic device or a file under the sensitive or password-manager path rules.",
			"Audio servers (pipewire/pulseaudio) legitimately hold the capture device while any app records; the holder shown is the device opener, which on PulseAudio/PipeWire systems is the audio daemon.")
	}
}

// procComm reads the kernel's short command name for a pid.
func procComm(pid int) string {
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm"))
	if err == nil {
		if s := strings.TrimSpace(string(raw)); s != "" {
			return s
		}
	}
	return fmt.Sprintf("pid %d", pid)
}

// ------------------------------------------------------------- darwin ----

// scanLsofSensitive parses `lsof -F pcn` blocks. Returns false when lsof
// itself failed (caller decides on the fstat fallback — BSD).
func scanLsofSensitive(snap *SensitiveSnapshot, rules *Rules) bool {
	out, err := RunOut(20*time.Second, "lsof", "+c", "0", "-w", "-n", "-F", "pcn")
	if err != nil {
		snap.Unavailable = "sensitive-access scan unavailable: lsof failed: " + FmtErr(err)
		return false
	}
	pid, cmd := 0, ""
	self := os.Getpid()
	for _, line := range strings.Split(out, "\n") {
		if len(line) < 2 {
			continue
		}
		tag, val := line[0], line[1:]
		switch tag {
		case 'p':
			pid, _ = strconv.Atoi(val)
		case 'c':
			cmd = val
		case 'n':
			if pid == self {
				continue
			}
			kind, note := classifySensitivePath(val, rules)
			if kind == "" || cmd == "" {
				continue
			}
			snap.Access = append(snap.Access, SensitiveAccess{
				App: cmd, Pid: pid, Kind: kind, Target: val,
				Detail: note, Source: "lsof", Live: true,
			})
		}
	}
	return true
}

// scanTCCLastUse turns TCC last_used_time for camera/microphone into
// per-app "recently used" rows — the only per-app camera/mic usage signal
// macOS exposes to a non-privileged process (updated when the grant is
// actually exercised, not when it is merely held).
func scanTCCLastUse(snap *SensitiveSnapshot) {
	rows, err := tccEntries()
	if err != nil {
		snap.Notes = append(snap.Notes,
			"TCC last-used unavailable (camera/mic recent-use rows skipped): "+FmtErr(err))
		return
	}
	for _, row := range rows {
		var kind string
		switch row.Service {
		case "kTCCServiceCamera":
			kind = KindCamera
		case "kTCCServiceMicrophone":
			kind = KindMicrophone
		default:
			continue
		}
		used := tccLastAccessed(row.LastUsed)
		if used == nil || *used <= 0 || *used < NowF()-MaxRecentUseSeconds {
			continue
		}
		name := row.Client
		if strings.HasPrefix(row.Client, "/") {
			name = strings.TrimSuffix(filepath.Base(row.Client), filepath.Ext(row.Client))
		} else if p := strings.LastIndex(row.Client, "."); p >= 0 {
			name = row.Client[p+1:]
		}
		detail := "TCC grant last exercised at the timestamp shown"
		if row.Auth == "0" {
			detail += " — currently denied, so this is an earlier use"
		}
		snap.Access = append(snap.Access, SensitiveAccess{
			App: name, Kind: kind, Target: row.Client, Detail: detail,
			Source: "macOS TCC last-used", LastUsed: *used,
		})
	}
}

// monitorLiveWindow is how fresh a momentary "access" event (macOS TCC
// stream) must be for its row to count as live rather than recent use — a
// few fast ticks, so a FaceTime call opened seconds ago lights up as live.
const monitorLiveWindow = 90.0

// monitorPrivacyKind maps an AppScope Monitor privacy event kind to a
// sensitive-access kind plus how that platform's collector streams it:
//
//	start/stop — Windows & Linux emit explicit in-use transitions
//	access     — macOS streams momentary TCC access observations
func monitorPrivacyKind(kind string) (string, string) {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "camera_start":
		return KindCamera, "start"
	case "camera_stop":
		return KindCamera, "stop"
	case "camera_access":
		return KindCamera, "access"
	case "mic_start", "microphone_start":
		return KindMicrophone, "start"
	case "mic_stop", "microphone_stop":
		return KindMicrophone, "stop"
	case "mic_access", "microphone_access":
		return KindMicrophone, "access"
	}
	return "", ""
}

// mergeMonitorPrivacy folds AppScope Monitor's privacy events (camera /
// microphone) into the snapshot. This is the macOS gap-filler: device holds
// are not lsof-visible and TCC.db needs Full Disk Access, but the monitor's
// TCC log stream sees every access — with it, Live Access shows camera/mic
// use even when the local scan cannot. A stop event ends the row; a local
// scan row of the same app+kind wins (its timestamp is refreshed instead of
// duplicating the row).
func mergeMonitorPrivacy(snap *SensitiveSnapshot, events []MonitorEvent, now float64) {
	type evState struct {
		app, kind, target, detail, mode string
		pid                             int
		ts                              float64
	}
	latest := map[string]evState{}
	for _, e := range events {
		if e.Category != "privacy" {
			continue
		}
		kind, mode := monitorPrivacyKind(FmtAny(e.Kind))
		if kind == "" {
			continue
		}
		app := strings.TrimSpace(FmtAny(e.App))
		if app == "" {
			continue
		}
		key := strings.ToLower(app) + "|" + fmt.Sprint(AnyInt(e.Pid)) + "|" + kind
		// the monitor's event ring is newest-first; keep the newest per key
		if prev, ok := latest[key]; ok && prev.ts >= e.Ts {
			continue
		}
		target := strings.TrimSpace(FmtAny(e.Path))
		if target == "" {
			target = kind
		}
		latest[key] = evState{app: app, kind: kind, target: target,
			detail: strings.TrimSpace(FmtAny(e.Detail)), pid: AnyInt(e.Pid),
			ts: e.Ts, mode: mode}
	}
	for _, st := range latest {
		if st.mode == "stop" {
			continue // the use ended; no row
		}
		covered := false
		for i := range snap.Access {
			a := &snap.Access[i]
			if a.Kind != st.kind || !nameOverlap(a.App, st.app) {
				continue
			}
			covered = true
			if st.ts > a.LastUsed {
				a.LastUsed = st.ts
			}
		}
		if covered {
			continue
		}
		detail := st.detail
		if detail == "" {
			detail = st.kind + " access observed by AppScope Monitor"
		}
		snap.Access = append(snap.Access, SensitiveAccess{
			App: st.app, Pid: st.pid, Kind: st.kind, Target: st.target,
			Detail: detail, Source: "AppScope Monitor",
			Live:     st.mode == "start" || now-st.ts <= monitorLiveWindow,
			LastUsed: st.ts,
			Denied:   strings.Contains(strings.ToLower(st.detail), "denied"),
		})
	}
	finalizeAccess(&snap.Access)
}

// ------------------------------------------------------------ windows ----

// scanConsentStore reads the CapabilityAccessManager consent store:
// per-app webcam/microphone use, including classic (non-packaged) exes and
// apps that keep attempting access while Windows answers "Deny".
func scanConsentStore(snap *SensitiveSnapshot) {
	script := `$ErrorActionPreference='Stop'; $rows=@(); ` +
		`foreach($cap in @('webcam','microphone')){ ` +
		`$base='HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\'+$cap; ` +
		`foreach($k in @(Get-ChildItem $base -ErrorAction SilentlyContinue)){ ` +
		`if($k.PSChildName -eq 'NonPackaged'){ ` +
		`foreach($np in @(Get-ChildItem $k.PSPath -ErrorAction SilentlyContinue)){ ` +
		`$p=Get-ItemProperty $np.PSPath -ErrorAction SilentlyContinue; ` +
		`$rows += [pscustomobject]@{cap=$cap; app=$np.PSChildName; ` +
		`start=[int64]$p.LastUsedTimeStart; stop=[int64]$p.LastUsedTimeStop; consent=[string]$p.Value} } } ` +
		`else { $p=Get-ItemProperty $k.PSPath -ErrorAction SilentlyContinue; ` +
		`$rows += [pscustomobject]@{cap=$cap; app=$k.PSChildName; ` +
		`start=[int64]$p.LastUsedTimeStart; stop=[int64]$p.LastUsedTimeStop; consent=[string]$p.Value} } } }; ` +
		`$rows | ConvertTo-Json -Compress`
	out, err := RunOut(25*time.Second, "powershell", "-NoProfile", "-Command", script)
	if err != nil {
		snap.Unavailable = "sensitive-access scan unavailable: consent store unreadable: " + FmtErr(err)
		return
	}
	type consentRow struct {
		Cap     string `json:"cap"`
		App     string `json:"app"`
		Start   int64  `json:"start"`
		Stop    int64  `json:"stop"`
		Consent string `json:"consent"`
	}
	rows, err := decodeJSONRows[consentRow]([]byte(out))
	if err != nil {
		snap.Unavailable = "sensitive-access scan unavailable: consent store response: " + FmtErr(err)
		return
	}
	for _, r := range rows {
		if r.App == "" {
			continue
		}
		kind := KindCamera
		if r.Cap == "microphone" {
			kind = KindMicrophone
		}
		live := r.Start > 0 && r.Stop == 0
		last := filetimeUnix(r.Stop)
		if last == 0 {
			last = filetimeUnix(r.Start)
		}
		detail := "CapabilityAccessManager record for this app"
		if live && r.Stop == 0 && r.Start > 0 && filetimeUnix(r.Start) > 0 &&
			filetimeUnix(r.Start) < NowF()-MaxRecentUseSeconds {
			detail = "stale in-use record (start set, no stop) — treat as last-used"
		}
		snap.Access = append(snap.Access, SensitiveAccess{
			App: consentAppName(r.App), Kind: kind, Target: r.App,
			Detail: detail, Source: "CapabilityAccessManager",
			Live: live, LastUsed: last,
			Denied: strings.EqualFold(strings.TrimSpace(r.Consent), "Deny"),
		})
	}
}

// consentAppName trims a consent-store key name to a readable app name:
// packaged entries are family names, NonPackaged entries are exe paths
// (a trailing '#' is a registry key-name artifact of backslash-bearing
// paths and is stripped before leafing).
func consentAppName(key string) string {
	name := strings.TrimSuffix(key, "#")
	if i := strings.LastIndex(name, `\`); i >= 0 && i < len(name)-1 {
		if leaf := name[i+1:]; strings.Contains(leaf, ".") {
			return leaf
		}
	}
	return name
}

// filetimeUnix converts a Windows FILETIME (100ns ticks since 1601-01-01)
// to unix seconds; 0 stays 0.
func filetimeUnix(ft int64) float64 {
	if ft <= 0 {
		return 0
	}
	return float64(ft)/1e7 - 11644473600
}

// --------------------------------------------------------------- BSD ----

// scanFstatSensitive is the base-system fallback when lsof is absent.
// fstat's trailing column is the vnode path when one exists.
func scanFstatSensitive(snap *SensitiveSnapshot, rules *Rules) {
	out, err := RunOut(20*time.Second, "fstat")
	if err != nil {
		snap.Unavailable = "sensitive-access scan unavailable: no lsof and fstat failed: " + FmtErr(err)
		return
	}
	self := os.Getpid()
	for _, raw := range strings.Split(out, "\n") {
		f := strings.Fields(raw)
		if len(f) < 5 {
			continue
		}
		pid, err := strconv.Atoi(f[2])
		if err != nil || pid == self {
			continue
		}
		path := f[len(f)-1]
		kind, note := classifySensitivePath(path, rules)
		if kind == "" {
			continue
		}
		snap.Access = append(snap.Access, SensitiveAccess{
			App: f[1], Pid: pid, Kind: kind, Target: path,
			Detail: note, Source: "fstat", Live: true,
		})
	}
}

// --------------------------------------------------------------- all ----

// storeIdentity normalizes an open-file target for the alert fingerprint so
// SQLite sidecars (-wal/-shm) of one store collapse into the same alert.
func storeIdentity(target string) string {
	ls := strings.ToLower(target)
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		ls = strings.TrimSuffix(ls, suffix)
	}
	return ls
}

func dedupeAccess(in []SensitiveAccess) []SensitiveAccess {
	seen := map[string]int{}
	out := []SensitiveAccess{}
	for _, a := range in {
		key := fmt.Sprintf("%s|%d|%s|%s|%v", strings.ToLower(a.App), a.Pid, a.Kind, a.Target, a.Live)
		if i, ok := seen[key]; ok {
			if a.LastUsed > out[i].LastUsed {
				out[i].LastUsed = a.LastUsed
			}
			out[i].Denied = out[i].Denied || a.Denied
			continue
		}
		seen[key] = len(out)
		out = append(out, a)
	}
	return out
}

// sensitiveFindings converts a snapshot into findings. intel (may be nil —
// IPolice offline) downgrades the network correlation when the paired
// outbound peer is a known provider: a Meet/Teams call keeps the device-hold
// severity with an annotation instead of "spyware behaviour", and a
// sensitive file held while talking to a known range drops to medium.
// Alert policy:
//   - camera/mic in use now → medium; high when the app also holds an
//     established public connection (fingerprint shared with exfil.go's
//     monitor-event correlation so both paths are one alert)
//   - camera/mic use while Windows denies consent → medium attempt alert
//   - password-manager data held by a process outside the manager family
//     (and not an indexer/backup service) → high
//   - sensitive files open → listed only (no alert); high with the exfil
//     fingerprint when the same app holds a public connection
//   - quiet_apps (browsers, updaters) keep file/credential findings
//     list-only — their profile data matches the path rules by design
func sensitiveFindings(rules *Rules, snap SensitiveSnapshot,
	conns []MonitorConn, now float64, intel *Intel) []Finding {

	findings := []Finding{}
	if snap.Unavailable != "" {
		findings = append(findings, Finding{
			Check: "sensitive", Severity: SevInfo,
			Title:  "Sensitive access scan unavailable",
			Detail: snap.Unavailable,
		})
		return findings
	}

	connsByApp := map[string][]MonitorConn{}
	for _, c := range conns {
		if strings.HasPrefix(strings.ToUpper(c.State), "ESTAB") && IsExternal(c.RemoteIP, rules) {
			connsByApp[strings.ToLower(c.App)] = append(connsByApp[strings.ToLower(c.App)], c)
		}
	}
	quiet := func(app string) bool { return StrHasAny(app, rules.QuietApps) }

	for _, a := range snap.Access {
		lapp := strings.ToLower(a.App)
		cs := connsByApp[lapp]
		// "via <source>" marks externally-reported rows in the title: the
		// app is the one using the device, the source is the witness that
		// reported it (only AppScope Monitor is an external witness — local
		// scans are Sentinel's own eyes and add no suffix)
		via := ""
		if a.Source == "AppScope Monitor" {
			via = " via AppScope Monitor"
		}

		switch a.Kind {
		case KindCamera, KindMicrophone:
			what := "camera"
			evKind := "camera_start"
			if a.Kind == KindMicrophone {
				what = "microphone"
				evKind = "mic_start"
			}
			if a.Live {
				f := Finding{
					Check: "sensitive", Severity: SevMedium,
					Title: fmt.Sprintf("%s is using the %s right now%s", a.App, what, via),
					Evidence: map[string]any{
						"app": a.App, "pid": a.Pid, "kind": a.Kind,
						"target": a.Target, "source": a.Source,
					},
					Fingerprint: FingerprintOf("device_hold",
						a.Kind+"|"+lapp+"|"+a.Target),
				}
				if a.Denied {
					f.Title = fmt.Sprintf("%s keeps trying to use the %s (denied)%s", a.App, what, via)
					f.Detail = fmt.Sprintf("The OS is blocking the request, but the app "+
						"keeps asking (%s, pid %d, %s). Repeated denied attempts are "+
						"how probing apps behave.", a.Source, a.Pid, a.Target)
					f.Fingerprint = FingerprintOf("consent_attempt",
						a.Kind+"|"+lapp)
					findings = append(findings, f)
					continue
				}
				// the wording separates actor from witness: the app named in
				// the title is the one using the device; the source is only
				// how Sentinel learned it
				if a.Source == "AppScope Monitor" {
					f.Detail = fmt.Sprintf("AppScope Monitor saw the %s turn on for "+
						"%s (macOS TCC log). The monitor is the witness here — it "+
						"reports device access, it does not capture anything itself.",
						what, a.App)
				} else {
					f.Detail = fmt.Sprintf("pid %d holds %q (%s). If this is not an "+
						"app you expect to capture %s input, close it and check its "+
						"network activity.", a.Pid, a.Target, a.Source, what)
				}
				if len(cs) > 0 {
					c := cs[0]
					if prov, known := intel.KnownRemote(c.RemoteIP); known {
						// a call to a known provider is expected behaviour —
						// keep the hold severity, say who the peer is
						f.Detail += fmt.Sprintf(" The same app currently holds an "+
							"outbound connection to %s%s — a known %s range "+
							"(IPolice), expected for calls.", c.RemoteIP,
							hostSuffix(c.Host), prov)
					} else {
						f.Severity = SevHigh
						f.Title = fmt.Sprintf("%s using the %s while talking to %s",
							a.App, what, c.RemoteIP)
						f.Detail += fmt.Sprintf(" The same app currently holds an "+
							"outbound connection to a public address%s. Expected for a "+
							"call; otherwise it is spyware behaviour.", hostSuffix(c.Host))
						f.Fingerprint = FingerprintOf("privacy_exfil",
							evKind+"|"+lapp+"|"+fmt.Sprint(int64(now/1800)))
					}
				}
				findings = append(findings, f)
			} else if a.LastUsed > 0 {
				// recent (not live) use — macOS TCC / Windows consent history
				detail := fmt.Sprintf("%s shows %s use at %s. Audit trail only — "+
					"no device is held now.", a.Source, what,
					time.Unix(int64(a.LastUsed), 0).Format("15:04:05"))
				if a.Source == "AppScope Monitor" {
					detail = fmt.Sprintf("%s exercised the %s at %s — AppScope "+
						"Monitor saw it in the TCC log. The monitor is the "+
						"reporter, not the user; audit trail only, no device is "+
						"held now.", a.App, what,
						time.Unix(int64(a.LastUsed), 0).Format("15:04:05"))
				}
				findings = append(findings, Finding{
					Check: "sensitive", Severity: SevLow,
					Title:  fmt.Sprintf("%s used the %s recently%s", a.App, what, via),
					Detail: detail,
					Evidence: map[string]any{
						"app": a.App, "kind": a.Kind, "target": a.Target,
						"last_used": a.LastUsed, "source": a.Source,
					},
					Fingerprint: FingerprintOf("sensitive_use",
						a.Kind+"|"+lapp+"|"+fmt.Sprint(int64(a.LastUsed/3600))),
				})
			}

		case KindPasswordManager:
			if !a.Live {
				continue
			}
			if isManagerProcess(a.App) || isNoiseProcess(a.App) || quiet(a.App) {
				continue // legitimate holder — snapshot lists it, no alert
			}
			f := Finding{
				Check: "sensitive", Severity: SevHigh,
				Title: fmt.Sprintf("%s is reading password-manager data", a.App),
				Detail: fmt.Sprintf("pid %d has %q open (%s). Only your password "+
					"manager (and its helpers) should touch these files — any other "+
					"process reading them is credential-theft behaviour.",
					a.Pid, a.Target, a.Source),
				Evidence: map[string]any{
					"app": a.App, "pid": a.Pid, "kind": a.Kind,
					"target": a.Target, "source": a.Source,
				},
				Fingerprint: FingerprintOf("pw_access",
					lapp+"|"+storeIdentity(a.Target)+"|"+fmt.Sprint(int64(now/3600))),
			}
			if len(cs) > 0 {
				c := cs[0]
				f.Detail += fmt.Sprintf(" The same app also holds an outbound "+
					"connection to %s%s.", c.RemoteIP, hostSuffix(c.Host))
			}
			findings = append(findings, f)

		case KindSensitiveFile:
			if !a.Live || quiet(a.App) || isNoiseProcess(a.App) {
				continue // listed in the Live Access tab, not alerted alone
			}
			if len(cs) > 0 {
				c := cs[0]
				lpath := strings.ToLower(a.Target)
				sev := SevHigh
				knownNote := ""
				if prov, known := intel.KnownRemote(c.RemoteIP); known {
					sev = SevMedium
					knownNote = fmt.Sprintf(" The peer is a known %s range "+
						"(IPolice) — downgraded, still worth a glance.", prov)
				}
				findings = append(findings, Finding{
					Check: "sensitive", Severity: sev,
					Title: fmt.Sprintf("Sensitive file open with live outbound: %s", a.App),
					Detail: fmt.Sprintf("%s (pid %d) holds %q open while talking to "+
						"%s%s. Credential/keychain readers behave exactly like "+
						"this.%s", a.App, a.Pid, a.Target, c.RemoteIP,
						hostSuffix(c.Host), knownNote),
					Evidence: map[string]any{
						"app": a.App, "pid": a.Pid, "path": a.Target,
						"remote": c.RemoteIP + ":" + fmt.Sprint(c.RemotePortInt()),
						"host":   c.Host,
					},
					// same identity scheme as exfil.go's monitor-event finding,
					// so one incident is one alert whichever path caught it
					Fingerprint: FingerprintOf("file_exfil",
						lapp+"|"+storeIdentity(lpath)+"|"+fmt.Sprint(int64(now/1800))),
				})
			}
		}
	}
	return findings
}

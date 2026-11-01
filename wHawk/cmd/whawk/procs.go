package main

// Process enumeration + process-based checks: zombies, orphans, known RAT
// / keylogger names, execution out of world-writable directories.
//
// Linux reads /proc directly (no external tools). macOS/BSD shell out to ps.
// Windows shells out to PowerShell CIM.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Proc struct {
	Pid           int    `json:"pid"`
	Ppid          int    `json:"ppid"`
	Name          string `json:"name"`
	State         string `json:"state"`
	User          string `json:"user,omitempty"`
	Path          string `json:"path,omitempty"`
	Zombie        bool   `json:"zombie"`
	ParentMissing bool   `json:"parent_missing,omitempty"`
}

func listProcs() ([]Proc, error) {
	switch runtime.GOOS {
	case "linux":
		return procsLinux()
	case "darwin", "freebsd", "openbsd", "netbsd":
		return procsPS()
	case "windows":
		return procsWin()
	}
	return nil, fmt.Errorf("process listing unavailable on %s", runtime.GOOS)
}

// ------------------------------------------------------------- linux ----

func procsLinux() ([]Proc, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	out := []Proc{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("/proc", e.Name(), "stat"))
		if err != nil {
			continue
		}
		s := string(raw)
		// comm is parenthesised and may contain spaces: split after last ')'
		closeIdx := strings.LastIndex(s, ")")
		if closeIdx < 0 {
			continue
		}
		name := strings.Trim(s[1:closeIdx], "()")
		rest := strings.Fields(s[closeIdx+2:])
		if len(rest) < 3 {
			continue
		}
		ppid, _ := strconv.Atoi(rest[1])
		state := rest[0]
		p := Proc{Pid: pid, Ppid: ppid, Name: filepath.Base(name), State: state}
		if strings.HasPrefix(name, "/") {
			p.Path = name
		} else if link, err := os.Readlink(filepath.Join("/proc", e.Name(), "exe")); err == nil {
			p.Path = link
		}
		p.Zombie = state == "Z"
		out = append(out, p)
	}
	return out, nil
}

// ------------------------------------------------------- darwin / BSD ----

func procsPS() ([]Proc, error) {
	// ucomm= reports the kernel's short command name, which survives into
	// the zombie state; comm= prints "<defunct>" for zombies (ps(1)), which
	// erases the one detail that identifies who the dead child was. Path
	// still uses comm= — the full path only exists for live processes.
	outStr, err := RunOut(10*time.Second, "ps", "-axo", "pid=,ppid=,stat=,ucomm=,comm=")
	if err != nil {
		return nil, err
	}
	out := []Proc{}
	for _, line := range strings.Split(outStr, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) < 5 {
			continue
		}
		pid, err1 := strconv.Atoi(f[0])
		ppid, err2 := strconv.Atoi(f[1])
		if err1 != nil || err2 != nil {
			continue
		}
		stat := f[2]
		ucomm := f[3]
		comm := strings.TrimSpace(strings.Join(f[4:], " "))
		p := Proc{Pid: pid, Ppid: ppid, State: stat, Name: ucomm, Path: comm}
		p.Zombie = strings.HasPrefix(stat, "Z")
		if p.Zombie {
			// dead processes have no path; keep a readable marker that
			// distinguishes "<defunct>" (the ps display name) from a name
			// that was never resolved.
			p.Path = ""
		}
		out = append(out, p)
	}
	return out, nil
}

// ---------------------------------------------------------- windows ----

func procsWin() ([]Proc, error) {
	ps := `$ErrorActionPreference='SilentlyContinue';` +
		`Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath |` +
		` ConvertTo-Json -Compress`
	outStr, err := RunOut(20*time.Second, "powershell", "-NoProfile", "-Command", ps)
	if err != nil {
		return nil, err
	}
	type row struct {
		ProcessID       int    `json:"ProcessId"`
		ParentProcessID int    `json:"ParentProcessId"`
		Name            string `json:"Name"`
		ExecutablePath  string `json:"ExecutablePath"`
	}
	var rows []row
	if err := json.Unmarshal([]byte(outStr), &rows); err != nil {
		// single object when only one process matches
		var one row
		if err2 := json.Unmarshal([]byte(outStr), &one); err2 != nil {
			return nil, err
		}
		rows = []row{one}
	}
	out := []Proc{}
	for _, r := range rows {
		p := Proc{Pid: r.ProcessID, Ppid: r.ParentProcessID,
			Name: r.Name, Path: r.ExecutablePath}
		// Windows has no true zombies; a process whose parent is gone shows
		// up once ParentProcessId no longer resolves — flagged below.
		out = append(out, p)
	}
	return out, nil
}

// ------------------------------------------------------------- checks ----

// parentName returns the process name for pid from a collected process
// list (used to attribute a zombie to the supervisor that failed to reap it).
func parentName(procs []Proc, pid int) (string, bool) {
	for _, p := range procs {
		if p.Pid == pid {
			name := p.Name
			if name == "" || name == "<defunct>" {
				return "", false
			}
			return name, true
		}
	}
	return "", false
}

// procFindings runs the shared process-based detections. zombieFirstSeen and
// orphans are persistent state kept by the engine.
func procFindings(rules *Rules, procs []Proc,
	zombieSeen map[int]float64, now float64) []Finding {

	findings := []Finding{}

	byPid := map[int]bool{}
	for _, p := range procs {
		byPid[p.Pid] = true
	}

	// ---- zombies: require persistence across two scans before alerting
	alive := map[int]bool{}
	for _, p := range procs {
		if !p.Zombie {
			continue
		}
		alive[p.Pid] = true
		first, known := zombieSeen[p.Pid]
		if !known {
			zombieSeen[p.Pid] = now
			continue
		}
		// A parent on the process allowlist (its own supervisor semantics —
		// the same list that legitimizes remote-control ports) is a known
		// reap-lazy manager: known-noise, keep tracking but stay quiet.
		if parent, ok := parentName(procs, p.Ppid); ok && StrHasAny(parent, rules.ProcessAllow) {
			continue
		}
		if now-first >= 25 { // seen on two consecutive scans
			// <defunct> is ps(1)'s display name for any zombie, not a program
			// name — replace it with the parent's identity so the alert says
			// WHO left the dead child behind (e.g. "orphaned sudo from monitor").
			name := p.Name
			if name == "" || name == "<defunct>" {
				if parent, ok := parentName(procs, p.Ppid); ok {
					name = fmt.Sprintf("orphaned child of %s (pid %d)", parent, p.Ppid)
				} else {
					name = "unidentified process"
				}
			}
			findings = append(findings, Finding{
				Check:    "zombie",
				Severity: SevLow,
				Title:    fmt.Sprintf("Zombie process %d (%s)", p.Pid, name),
				Detail: fmt.Sprintf("Defunct child of pid %d lingering since %s — "+
					"its parent is not reaping it (usually a stuck supervisor, "+
					"harmless alone; swarms of them hint at a crashed watchdog).",
					p.Ppid, time.Unix(int64(first), 0).Format("15:04:05")),
				Evidence: map[string]any{
					"pid": p.Pid, "ppid": p.Ppid, "name": p.Name,
					"age_s": int(now - first),
				},
				Fingerprint: FingerprintOf("zombie",
					fmt.Sprintf("%d:%s:%d", p.Pid, p.Name, p.Ppid)),
			})
		}
	}
	for pid := range zombieSeen {
		if !alive[pid] {
			delete(zombieSeen, pid)
		}
	}

	// ---- orphans: parent pid does not exist (possible reparenting abuse
	// indicator when the parent was not pid 1/launchd/init)
	for i := range procs {
		p := &procs[i]
		if p.Ppid == 0 || p.Ppid == 1 || p.Ppid == p.Pid {
			continue
		}
		if !byPid[p.Ppid] {
			p.ParentMissing = true
		}
	}

	// ---- known-bad / RAT / keylogger names
	for _, p := range procs {
		lname := strings.ToLower(p.Name)
		if lname == "" {
			continue
		}
		if MatchBadName(lname, rules.ProcessBad) {
			findings = append(findings, Finding{
				Check:    "proc_bad",
				Severity: SevCritical,
				Title:    fmt.Sprintf("Known attack tool process running: %s", p.Name),
				Detail: fmt.Sprintf("pid %d, path %q, parent %d. This name matches the "+
					"known RAT/keylogger/tunneller list — verify what launched it.",
					p.Pid, p.Path, p.Ppid),
				Evidence: map[string]any{
					"pid": p.Pid, "name": p.Name, "path": p.Path, "ppid": p.Ppid,
				},
				Fingerprint: FingerprintOf("proc_bad",
					p.Name+"|"+p.Path+"|"+strconv.Itoa(p.Ppid)),
			})
		}
		// execution out of world-writable dirs (stager behaviour) — independent
		// of the name match, both indicators can apply to one process
		if p.Path != "" && runsFromTemp(p.Path) {
			findings = append(findings, Finding{
				Check:    "proc_tmp",
				Severity: SevMedium,
				Title:    fmt.Sprintf("Process running from a temp directory: %s", p.Name),
				Detail: fmt.Sprintf("pid %d executing from %q — malware staging "+
					"frequently drops binaries in temp paths. Confirm it is yours "+
					"(installers, build tools) or investigate.", p.Pid, p.Path),
				Evidence: map[string]any{
					"pid": p.Pid, "name": p.Name, "path": p.Path,
				},
				Fingerprint: FingerprintOf("proc_tmp", p.Path+"|"+strconv.Itoa(p.Pid)),
			})
		}
	}

	// orphan swarm: many processes whose parent vanished at once
	orphans := []Proc{}
	for _, p := range procs {
		if p.ParentMissing {
			orphans = append(orphans, p)
		}
	}
	if len(orphans) >= 15 {
		names := map[string]int{}
		for _, o := range orphans {
			names[o.Name]++
		}
		top := []string{}
		for n, c := range names {
			top = append(top, fmt.Sprintf("%s×%d", n, c))
		}
		sort.Strings(top)
		findings = append(findings, Finding{
			Check:    "proc_orphan",
			Severity: SevMedium,
			Title:    fmt.Sprintf("%d processes lost their parent at once", len(orphans)),
			Detail: "A mass parent death can mean a crashed supervisor — or a " +
				"monitoring/AV process being killed by something. Top names: " +
				strings.Join(top[:min(5, len(top))], ", "),
			Evidence: map[string]any{"count": len(orphans)},
			Fingerprint: FingerprintOf("proc_orphan",
				fmt.Sprintf("%d", time.Now().Unix()/900)),
		})
	}
	return findings
}

// runsFromTemp matches every platform's world-writable staging patterns on
// every platform: the shapes are distinctive (backslashed Windows paths never
// collide with POSIX prefixes), and cross-matching keeps the logic testable
// and robust under Wine/SMB-mounted paths.
func runsFromTemp(path string) bool {
	ls := strings.ToLower(path)
	if strings.Contains(ls, "\\appdata\\local\\temp\\") ||
		strings.Contains(ls, "\\windows\\temp\\") ||
		strings.Contains(ls, "\\users\\public\\") ||
		strings.Contains(ls, "\\programdata\\temp\\") {
		return true
	}
	return strings.HasPrefix(ls, "/tmp/") ||
		strings.HasPrefix(ls, "/private/tmp/") ||
		strings.HasPrefix(ls, "/var/tmp/") ||
		strings.HasPrefix(ls, "/private/var/tmp/") ||
		strings.HasPrefix(ls, "/dev/shm/") ||
		strings.HasPrefix(ls, "/run/user/")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

package main

// Network checks: listening backdoors (RAT ports), rogue-remote detection,
// and periodic-beacon heuristics over AppScope Monitor's connection table.

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Sock struct {
	Proto    string `json:"proto"`
	LocalIP  string `json:"local_ip"`
	Port     int    `json:"port"`
	Pid      int    `json:"pid"`
	ProcName string `json:"proc"`
	Foreign  bool   `json:"foreign"` // listening on all/wildcard interfaces
}

func listeningSocks() ([]Sock, error) {
	switch runtime.GOOS {
	case "linux":
		return listenLinux()
	case "darwin", "freebsd", "openbsd", "netbsd":
		return listenLsof()
	case "windows":
		return listenWin()
	}
	return nil, fmt.Errorf("socket listing unavailable on %s", runtime.GOOS)
}

// ------------------------------------------------------------- linux ----

func listenLinux() ([]Sock, error) {
	type rawSock struct {
		proto, localIP string
		port, inode    int
	}
	var raws []rawSock
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		proto := "tcp"
		if strings.HasSuffix(f, "6") {
			proto = "tcp6"
		}
		lines := strings.Split(string(raw), "\n")
		for i, line := range lines {
			if i == 0 {
				continue
			}
			flds := strings.Fields(line)
			if len(flds) < 10 || flds[3] != "0A" { // ST_LISTEN
				continue
			}
			ipPort := strings.Split(flds[1], ":")
			if len(ipPort) != 2 {
				continue
			}
			port, _ := strconv.ParseInt(ipPort[1], 16, 32)
			inode, _ := strconv.Atoi(flds[9])
			ip := ipPort[0]
			if len(ip) == 8 { // little-endian ipv4 hex
				var b [4]byte
				for j := 0; j < 4; j++ {
					v, _ := strconv.ParseInt(ip[j*2:j*2+2], 16, 32)
					b[3-j] = byte(v)
				}
				ip = net.IP(b[:]).String()
			} else {
				var b [16]byte
				for j := 0; j < 16; j++ {
					v, _ := strconv.ParseInt(ip[j*2:j*2+2], 16, 32)
					b[j] = byte(v)
				}
				ip = net.IP(b[:]).String()
			}
			raws = append(raws, rawSock{proto: proto, localIP: ip, port: int(port), inode: inode})
		}
	}
	// inode -> pid
	inodePid := map[int]int{}
	pids := []string{}
	if ents, err := os.ReadDir("/proc"); err == nil {
		for _, e := range ents {
			if e.IsDir() {
				pids = append(pids, e.Name())
			}
		}
	}
	for _, pid := range pids {
		fddir := "/proc/" + pid + "/fd"
		fds, err := os.ReadDir(fddir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(fddir + "/" + fd.Name())
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			var ino int
			fmt.Sscanf(link, "socket:[%d]", &ino)
			if ino > 0 {
				inodePid[ino], _ = strconv.Atoi(pid)
			}
		}
	}
	out := []Sock{}
	for _, r := range raws {
		s := Sock{Proto: r.proto, LocalIP: r.localIP, Port: r.port,
			Pid: inodePid[r.inode], Foreign: isWildcard(r.localIP)}
		s.ProcName = procNameLinux(s.Pid)
		out = append(out, s)
	}
	return out, nil
}

func procNameLinux(pid int) string {
	if pid == 0 {
		return ""
	}
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

func isWildcard(ip string) bool {
	return ip == "0.0.0.0" || ip == "::" || strings.HasPrefix(ip, "::ffff:0.0.0.0")
}

// ------------------------------------------------------- darwin / BSD ----

func listenLsof() ([]Sock, error) {
	outStr, err := RunOut(10*time.Second, "lsof", "-nP", "-iTCP", "-sTCP:LISTEN")
	if err != nil {
		// lsof may be missing on minimal BSDs; netstat fallback (no pid)
		outStr, err = RunOut(10*time.Second, "netstat", "-an", "-p", "tcp")
		if err != nil {
			return nil, err
		}
		out := []Sock{}
		for _, line := range strings.Split(outStr, "\n") {
			f := strings.Fields(line)
			if len(f) < 4 || !strings.Contains(f[3], "*.") && !strings.Contains(f[3], ".") {
				continue
			}
			if strings.Contains(line, "LISTEN") || len(f) >= 6 && f[5] == "LISTEN" {
				addr := f[3]
				parts := strings.Split(addr, ":")
				if len(parts) < 2 {
					continue
				}
				port, _ := strconv.Atoi(parts[len(parts)-1])
				out = append(out, Sock{Proto: "tcp", Port: port,
					LocalIP: strings.TrimSuffix(addr, ":"+parts[len(parts)-1]),
					Foreign: strings.Contains(addr, "*")})
			}
		}
		return out, nil
	}
	out := []Sock{}
	for i, line := range strings.Split(outStr, "\n") {
		if i == 0 {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 9 {
			continue
		}
		pid, _ := strconv.Atoi(f[1])
		name := f[0]
		addr := f[8]
		if !strings.Contains(addr, ":") {
			continue
		}
		idx := strings.LastIndex(addr, ":")
		port, _ := strconv.Atoi(addr[idx+1:])
		out = append(out, Sock{Proto: "tcp", Port: port,
			LocalIP: addr[:idx], Pid: pid, ProcName: name,
			Foreign: isWildcard(addr[:idx])})
	}
	return out, nil
}

// ---------------------------------------------------------- windows ----

func listenWin() ([]Sock, error) {
	ps := `$ErrorActionPreference='SilentlyContinue';` +
		`$c=Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess;` +
		`$p=@{}; Get-CimInstance Win32_Process | ForEach-Object { $p[[int]$_.ProcessId]=$_.Name };` +
		`$c | ForEach-Object { [pscustomobject]@{LocalAddress=$_.LocalAddress;LocalPort=$_.LocalPort;OwningProcess=$_.OwningProcess;Name=$p[[int]$_.OwningProcess]} } | ConvertTo-Json -Compress`
	outStr, err := RunOut(25*time.Second, "powershell", "-NoProfile", "-Command", ps)
	if err != nil {
		return nil, err
	}
	type row struct {
		LocalAddress  string `json:"LocalAddress"`
		LocalPort     int    `json:"LocalPort"`
		OwningProcess int    `json:"OwningProcess"`
		Name          string `json:"Name"`
	}
	var rows []row
	if err := json.Unmarshal([]byte(outStr), &rows); err != nil {
		var one row
		if err2 := json.Unmarshal([]byte(outStr), &one); err2 != nil {
			return nil, err
		}
		rows = []row{one}
	}
	out := []Sock{}
	for _, r := range rows {
		out = append(out, Sock{Proto: "tcp", LocalIP: r.LocalAddress, Port: r.LocalPort,
			Pid: r.OwningProcess, ProcName: r.Name, Foreign: isWildcard(r.LocalAddress)})
	}
	return out, nil
}

// ------------------------------------------------------------ checks ----

// netFindings: listeners + live bad-port sessions. Endpoint learning &
// beacon math are event-driven — see beacon.go.
// processes so listener owners can be sanity-checked.
func netFindings(rules *Rules, socks []Sock, procs []Proc,
	monConns []MonitorConn, now float64) []Finding {

	findings := []Finding{}
	procName := func(pid int) string {
		for _, p := range procs {
			if p.Pid == pid {
				return p.Name
			}
		}
		return ""
	}

	// ---- listening backdoors / RAT listeners
	badPorts := map[int]bool{}
	for _, p := range rules.BadPorts {
		badPorts[p] = true
	}
	for _, s := range socks {
		owner := s.ProcName
		if owner == "" && s.Pid > 0 {
			owner = procName(s.Pid)
		}
		if !badPorts[s.Port] {
			continue
		}
		if StrHasAny(owner, rules.ProcessAllow) {
			continue
		}
		sev := SevHigh
		if owner == "" {
			sev = SevMedium
		}
		findings = append(findings, Finding{
			Check:    "listen_backdoor",
			Severity: sev,
			Title: fmt.Sprintf("Listener on known remote-control port %d (%s)",
				s.Port, ownerOrUnknown(owner)),
			Detail: fmt.Sprintf("%s listening on %s:%d%s. This port is on the "+
				"RAT/C2/tunnel list and the owner is not in the allowlist — "+
				"verify before dismissing (RDP/VNC users: allowlist the service).",
				ownerOrUnknown(owner), s.LocalIP, s.Port,
				ifForeign(s.Foreign)),
			Evidence: map[string]any{
				"port": s.Port, "local_ip": s.LocalIP, "pid": s.Pid,
				"proc": owner, "foreign": s.Foreign,
			},
			Fingerprint: FingerprintOf("listen_backdoor",
				fmt.Sprintf("%d:%s:%s", s.Port, owner, s.LocalIP)),
		})
	}

	// ---- bad-port remotes seen by the monitor (active sessions, not just listeners)
	for _, c := range monConns {
		if !badPorts[c.RemotePortInt()] {
			continue
		}
		if !IsExternal(c.RemoteIP, rules) {
			continue
		}
		if StrHasAny(c.App, rules.ProcessAllow) {
			continue
		}
		findings = append(findings, Finding{
			Check:    "conn_badport",
			Severity: SevHigh,
			Title: fmt.Sprintf("Active connection to remote-control port %d (%s)",
				c.RemotePortInt(), ownerOrUnknown(c.App)),
			Detail: fmt.Sprintf("%s has an established session to %s:%d%s. "+
				"Outbound traffic to a RAT/C2 port from a non-allowlisted app "+
				"is a compromise indicator — treat as urgent unless you run "+
				"this service yourself.", ownerOrUnknown(c.App), c.RemoteIP,
				c.RemotePortInt(), hostSuffix(c.Host)),
			Evidence: map[string]any{
				"app": c.App, "remote": c.RemoteIP, "port": c.RemotePortInt(),
				"host": c.Host, "pid": c.Pid,
			},
			Fingerprint: FingerprintOf("conn_badport",
				c.App+"|"+c.RemoteIP+":"+strconv.Itoa(c.RemotePortInt())),
		})
	}
	return findings
}

func ownerOrUnknown(owner string) string {
	if strings.TrimSpace(owner) == "" {
		return "unknown process"
	}
	return owner
}

func ifForeign(foreign bool) string {
	if foreign {
		return " on all interfaces"
	}
	return ""
}

func hostSuffix(host string) string {
	if strings.TrimSpace(host) != "" {
		return fmt.Sprintf(" (%s)", host)
	}
	return ""
}

func AnyFloat(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	}
	return 0
}

func sortSocks(s []Sock) {
	sort.Slice(s, func(i, j int) bool { return s[i].Port < s[j].Port })
}

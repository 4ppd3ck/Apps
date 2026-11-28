package main

// Network checks: listening backdoors (RAT ports), rogue-remote detection,
// and periodic-beacon heuristics over AppScope Monitor's connection table.
//
// Socket discovery is not duplicated here: listeningSocks derives its view
// from the ports check's scanLocalPorts (ports.go) — one /proc, lsof and
// PowerShell pass per fast tick serves both the ports inventory and the
// backdoor-listener matching.

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type Sock struct {
	Proto    string `json:"proto"`
	LocalIP  string `json:"local_ip"`
	Port     int    `json:"port"`
	Pid      int    `json:"pid"`
	ProcName string `json:"proc"`
	Foreign  bool   `json:"foreign"` // listening on all/wildcard interfaces
}

// listeningSocks returns the TCP listeners, reusing scanLocalPorts so the
// fast tick runs the platform scanner once, not twice.
func listeningSocks() ([]Sock, error) {
	scan := scanLocalPorts()
	if len(scan.Ports) == 0 && scan.Error != "" {
		return nil, fmt.Errorf("%s", scan.Error)
	}
	return socksFromPorts(scan), nil
}

// socksFromPorts converts the ports inventory into the listener view the
// backdoor check matches against (TCP "listening" rows only).
func socksFromPorts(scan PortScan) []Sock {
	out := make([]Sock, 0, len(scan.Ports))
	for _, p := range scan.Ports {
		// the backdoor check is about TCP listeners; UDP "bound" endpoints
		// and the remote-connection rows are not listeners
		if p.State != "listening" || strings.HasPrefix(p.Protocol, "udp") {
			continue
		}
		out = append(out, Sock{Proto: p.Protocol, LocalIP: p.LocalIP, Port: p.Port,
			Pid: p.Pid, ProcName: p.Process, Foreign: isWildcard(p.LocalIP)})
	}
	return out
}

func isWildcard(ip string) bool {
	ip = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(ip), "["), "]")
	return ip == "0.0.0.0" || ip == "::" || ip == "*" || strings.HasPrefix(ip, "::ffff:0.0.0.0")
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

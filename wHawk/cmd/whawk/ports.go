package main

// Local port inventory. Socket discovery stays on the machine and uses
// /proc on Linux, lsof on macOS, and PowerShell networking cmdlets on Windows.
// Active remote connections are added separately from the optional local wTower feed.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

type LocalPort struct {
	Protocol   string `json:"protocol"`
	LocalIP    string `json:"local_ip"`
	Port       int    `json:"port"`
	RemoteIP   string `json:"remote_ip,omitempty"`
	RemotePort int    `json:"remote_port,omitempty"`
	RemoteType string `json:"remote_type,omitempty"`
	State      string `json:"state"`
	Pid        int    `json:"pid,omitempty"`
	Process    string `json:"process,omitempty"`
	Exposure   string `json:"exposure"`
	Service    string `json:"service"`
	Purpose    string `json:"purpose"`
	Category   string `json:"category"`
	Risk       string `json:"risk"`
	Advice     string `json:"advice"`
}

type PortScan struct {
	Ports                []LocalPort      `json:"ports"`
	Connections          []PortConnection `json:"connections"`
	ConnectionsAvailable bool             `json:"connections_available"`
	Complete             bool             `json:"complete"`
	Error                string           `json:"error,omitempty"`
	Warnings             []string         `json:"warnings,omitempty"`
	Method               string           `json:"method"`
	ScannedAt            float64          `json:"scanned_at"`
}

type PortConnection struct {
	Protocol   string `json:"protocol"`
	LocalIP    string `json:"local_ip"`
	LocalPort  int    `json:"local_port"`
	RemoteIP   string `json:"remote_ip"`
	RemotePort int    `json:"remote_port"`
	App        string `json:"app"`
	Pid        string `json:"pid,omitempty"`
	State      string `json:"state"`
	RemoteType string `json:"remote_type"`
	Risk       string `json:"risk"`
	Source     string `json:"source"`
}

type rawLocalPort struct {
	protocol   string
	localIP    string
	port       int
	remoteIP   string
	remotePort int
	state      string
	pid        int
	process    string
}

func scanLocalPorts() PortScan {
	result := PortScan{
		Ports: []LocalPort{}, Warnings: []string{},
		Complete: true, ScannedAt: NowF(),
	}
	var raws []rawLocalPort
	switch runtime.GOOS {
	case "linux":
		result.Method = "/proc"
		raws, result.Error, result.Warnings = scanLinuxPorts()
	case "darwin":
		result.Method = "lsof"
		raws, result.Error, result.Warnings = scanDarwinPorts()
	case "windows":
		result.Method = "PowerShell Get-NetTCPConnection/Get-NetUDPEndpoint"
		raws, result.Error, result.Warnings = scanWindowsPorts()
	default:
		result.Method = runtime.GOOS
		result.Error = "local port inventory is supported on macOS, Windows, and Linux"
	}
	for _, port := range raws {
		if port.pid > 0 && port.process == "" {
			result.Warnings = append(result.Warnings, "Some process names are unavailable; the owner may have exited or may require elevated permissions.")
			break
		}
	}
	result.Complete = result.Error == "" && len(result.Warnings) == 0
	if result.Error == "" && !result.Complete {
		result.Error = strings.Join(result.Warnings, "; ")
	}
	result.Ports = enrichLocalPorts(raws)
	return result
}

// Linux /proc -------------------------------------------------------------

func scanLinuxPorts() ([]rawLocalPort, string, []string) {
	type procSocket struct {
		protocol, localIP, state string
		port, inode              int
	}
	var sockets []procSocket
	var sourceErrors []string
	readable := 0
	for _, source := range []struct {
		path, protocol string
		tcp            bool
	}{
		{"/proc/net/tcp", "tcp", true},
		{"/proc/net/tcp6", "tcp6", true},
		{"/proc/net/udp", "udp", false},
		{"/proc/net/udp6", "udp6", false},
	} {
		raw, err := os.ReadFile(source.path)
		if err != nil {
			sourceErrors = append(sourceErrors, source.path+": "+err.Error())
			continue
		}
		readable++
		for i, line := range strings.Split(string(raw), "\n") {
			if i == 0 || strings.TrimSpace(line) == "" {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 10 || source.tcp && fields[3] != "0A" {
				continue
			}
			host, port, ok := parseProcEndpoint(fields[1], strings.HasSuffix(source.path, "6"))
			if !ok || port == 0 {
				continue
			}
			inode, _ := strconv.Atoi(fields[9])
			state := "bound"
			if source.tcp {
				state = "listening"
			}
			sockets = append(sockets, procSocket{
				protocol: source.protocol, localIP: host, port: port,
				state: state, inode: inode,
			})
		}
	}
	if readable == 0 {
		return nil, strings.Join(sourceErrors, "; "), nil
	}
	var warnings []string
	if len(sourceErrors) > 0 {
		warnings = append(warnings, "Some /proc socket tables could not be read: "+strings.Join(sourceErrors, "; "))
	}

	inodeOwner := map[int]rawLocalPort{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		warnings = append(warnings, "Socket owners could not be enumerated from /proc: "+err.Error())
	} else {
		ownerScanLimited := false
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			pid, err := strconv.Atoi(entry.Name())
			if err != nil {
				continue
			}
			fdDir := "/proc/" + entry.Name() + "/fd"
			fds, err := os.ReadDir(fdDir)
			if err != nil {
				if os.IsPermission(err) {
					ownerScanLimited = true
				}
				continue
			}
			name := ""
			if raw, err := os.ReadFile("/proc/" + entry.Name() + "/comm"); err == nil {
				name = strings.TrimSpace(string(raw))
			}
			if executable, err := os.Readlink("/proc/" + entry.Name() + "/exe"); err == nil {
				if base := filepath.Base(strings.TrimSuffix(executable, " (deleted)")); base != "." && base != "/" {
					name = base
				}
			}
			for _, fd := range fds {
				link, err := os.Readlink(fdDir + "/" + fd.Name())
				if err != nil || !strings.HasPrefix(link, "socket:[") {
					continue
				}
				var inode int
				if _, err := fmt.Sscanf(link, "socket:[%d]", &inode); err == nil && inode > 0 {
					inodeOwner[inode] = rawLocalPort{pid: pid, process: name}
				}
			}
		}
		if ownerScanLimited {
			warnings = append(warnings, "Some process owners are hidden by OS permissions; run wHawk with elevated permissions for broader attribution.")
		}
	}
	raws := make([]rawLocalPort, 0, len(sockets))
	unattributed := 0
	for _, sock := range sockets {
		owner := inodeOwner[sock.inode]
		if sock.inode > 0 && owner.pid == 0 {
			unattributed++
		}
		raws = append(raws, rawLocalPort{
			protocol: sock.protocol, localIP: sock.localIP, port: sock.port,
			state: sock.state, pid: owner.pid, process: owner.process,
		})
	}
	if unattributed > 0 {
		warnings = append(warnings, "Some socket owners could not be attributed; they may have exited or may require elevated permissions.")
	}
	return raws, strings.Join(sourceErrors, "; "), warnings
}

func runPortCommand(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.Output()
	if ctx.Err() != nil {
		return "", fmt.Errorf("%s timed out after %s", name, timeout)
	}
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
			return strings.TrimSpace(string(output)), fmt.Errorf("%s: %s: %w",
				name, strings.TrimSpace(string(exitErr.Stderr)), err)
		}
		return strings.TrimSpace(string(output)), err
	}
	return strings.TrimSpace(string(output)), nil
}

func parseProcEndpoint(endpoint string, ipv6 bool) (string, int, bool) {
	parts := strings.Split(endpoint, ":")
	if len(parts) != 2 {
		return "", 0, false
	}
	rawIP, err := hex.DecodeString(parts[0])
	if err != nil || len(rawIP) != 4 && len(rawIP) != 16 {
		return "", 0, false
	}
	if !ipv6 {
		for i, j := 0, len(rawIP)-1; i < j; i, j = i+1, j-1 {
			rawIP[i], rawIP[j] = rawIP[j], rawIP[i]
		}
	} else {
		for base := 0; base < len(rawIP); base += 4 {
			for i, j := base, base+3; i < j; i, j = i+1, j-1 {
				rawIP[i], rawIP[j] = rawIP[j], rawIP[i]
			}
		}
	}
	port, err := strconv.ParseInt(parts[1], 16, 32)
	if err != nil {
		return "", 0, false
	}
	return net.IP(rawIP).String(), int(port), true
}

// macOS / lsof ------------------------------------------------------------

func scanDarwinPorts() ([]rawLocalPort, string, []string) {
	lsof, err := exec.LookPath("lsof")
	if err != nil {
		return nil, "lsof is required to scan local ports on macOS: " + err.Error(), nil
	}
	var raws []rawLocalPort
	var failures []string
	for _, query := range []struct {
		protocol string
		args     []string
		state    string
	}{
		{"tcp", []string{"-nP", "+c", "0", "-iTCP", "-sTCP:LISTEN"}, "listening"},
		{"udp", []string{"-nP", "+c", "0", "-iUDP"}, "bound"},
	} {
		output, err := runPortCommand(10*time.Second, lsof, query.args...)
		if err != nil {
			if lsofNoMatches(err) {
				continue
			}
			failures = append(failures, query.protocol+": "+err.Error())
			if output == "" {
				continue
			}
		}
		for i, line := range strings.Split(output, "\n") {
			if i == 0 {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 9 {
				continue
			}
			pid, _ := strconv.Atoi(fields[1])
			localIP, port, ok := parseLsofEndpoint(fields[8])
			if !ok || port == 0 {
				continue
			}
			remoteIP, remotePort := parseLsofRemoteEndpoint(fields[8])
			raws = append(raws, rawLocalPort{
				protocol: query.protocol, localIP: localIP, port: port,
				remoteIP: remoteIP, remotePort: remotePort,
				state: query.state, pid: pid, process: decodeLsofCommand(fields[0]),
			})
		}
	}
	processes, procErr := procsPS()
	names := make(map[int]string, len(processes))
	if procErr == nil {
		for _, process := range processes {
			names[process.Pid] = process.Name
		}
	}
	for i := range raws {
		if raws[i].process == "" {
			raws[i].process = names[raws[i].pid]
		}
	}
	var warnings []string
	for _, row := range raws {
		if row.process == "" {
			if procErr != nil {
				warnings = append(warnings, "Fallback process-name lookup failed: "+procErr.Error())
			} else {
				warnings = append(warnings, "Some socket owners are not visible to this user; process names may require elevated permissions.")
			}
			break
		}
	}
	return raws, strings.Join(failures, "; "), warnings
}

func decodeLsofCommand(command string) string {
	return strings.ReplaceAll(command, `\x20`, " ")
}

func lsofNoMatches(err error) bool {
	var exitErr *exec.ExitError
	return errors.As(err, &exitErr) && exitErr.ExitCode() == 1 && len(exitErr.Stderr) == 0
}

func parseLsofEndpoint(endpoint string) (string, int, bool) {
	endpoint = strings.TrimSpace(strings.SplitN(endpoint, "->", 2)[0])
	endpoint = strings.TrimSuffix(endpoint, "(LISTEN)")
	endpoint = strings.TrimSpace(endpoint)
	host, portText, err := net.SplitHostPort(endpoint)
	if err != nil {
		i := strings.LastIndex(endpoint, ":")
		if i < 0 {
			return "", 0, false
		}
		host, portText = strings.Trim(endpoint[:i], "[]"), endpoint[i+1:]
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, false
	}
	switch host {
	case "*":
		host = "0.0.0.0"
	case "":
		host = "0.0.0.0"
	}
	return host, port, true
}

func parseLsofRemoteEndpoint(endpoint string) (string, int) {
	parts := strings.SplitN(endpoint, "->", 2)
	if len(parts) != 2 {
		return "", 0
	}
	host, port, ok := parseLsofEndpoint(parts[1])
	if !ok {
		return "", 0
	}
	return host, port
}

func portConnectionsFromMonitor(conns []MonitorConn) []PortConnection {
	out := make([]PortConnection, 0, len(conns))
	for _, conn := range conns {
		localPort, remotePort := conn.LocalPortInt(), conn.RemotePortInt()
		if conn.LocalIP == "" && localPort == 0 && conn.RemoteIP == "" && remotePort == 0 {
			continue
		}
		remoteType := IPClass(conn.RemoteIP)
		risk := "unknown"
		switch remoteType {
		case "public":
			risk = "medium"
		case "loopback", "private", "linklocal", "cgnat":
			risk = "low"
		}
		out = append(out, PortConnection{
			Protocol: strings.ToLower(conn.Proto), LocalIP: conn.LocalIP, LocalPort: localPort,
			RemoteIP: conn.RemoteIP, RemotePort: remotePort,
			App: conn.App, Pid: FmtAny(conn.Pid), State: conn.State,
			RemoteType: remoteType, Risk: risk, Source: "wTower",
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].App != out[j].App {
			return out[i].App < out[j].App
		}
		if out[i].RemoteIP != out[j].RemoteIP {
			return out[i].RemoteIP < out[j].RemoteIP
		}
		return out[i].RemotePort < out[j].RemotePort
	})
	return out
}

// Windows / PowerShell ----------------------------------------------------

func scanWindowsPorts() ([]rawLocalPort, string, []string) {
	var raws []rawLocalPort
	var failures []string
	procs, procErr := procsWin()
	names := make(map[int]string, len(procs))
	if procErr == nil {
		for _, proc := range procs {
			names[proc.Pid] = proc.Name
		}
	}
	for _, query := range []struct {
		protocol, command, state string
	}{
		{"tcp", "Get-NetTCPConnection -State Listen", "listening"},
		{"udp", "Get-NetUDPEndpoint", "bound"},
	} {
		script := "$ErrorActionPreference='Stop'; $rows=@(" + query.command +
			" -ErrorAction Stop | ForEach-Object { [pscustomobject]@{LocalAddress=$_.LocalAddress;LocalPort=$_.LocalPort;OwningProcess=$_.OwningProcess;State='" +
			query.state + "'} })"
		output, err := runPortCommand(20*time.Second, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script+"; ConvertTo-Json -InputObject $rows -Compress")
		if err != nil {
			failures = append(failures, query.protocol+": "+err.Error())
			continue
		}
		type row struct {
			LocalAddress  string `json:"LocalAddress"`
			LocalPort     int    `json:"LocalPort"`
			OwningProcess int    `json:"OwningProcess"`
			State         string `json:"State"`
		}
		var rows []row
		if strings.TrimSpace(output) == "" || strings.TrimSpace(output) == "null" {
			continue
		}
		if err := json.Unmarshal([]byte(output), &rows); err != nil {
			var one row
			if singleErr := json.Unmarshal([]byte(output), &one); singleErr != nil {
				failures = append(failures, query.protocol+": invalid PowerShell output: "+err.Error())
				continue
			}
			rows = []row{one}
		}
		for _, item := range rows {
			state := item.State
			if state == "" {
				state = query.state
			}
			raws = append(raws, rawLocalPort{
				protocol: query.protocol, localIP: item.LocalAddress, port: item.LocalPort,
				state: state, pid: item.OwningProcess, process: names[item.OwningProcess],
			})
		}
	}
	var warnings []string
	if procErr != nil {
		warnings = append(warnings, "Socket owners were found, but process names could not be read: "+procErr.Error())
	}
	return raws, strings.Join(failures, "; "), warnings
}

// Service guidance and risk classification --------------------------------

type portService struct {
	name, purpose, category string
}

func describePort(proto string, port int) portService {
	switch {
	case port == 22:
		return portService{"SSH", "Secure remote shell and file transfer", "remote_access"}
	case port == 53:
		return portService{"DNS", "Name resolution service", "infrastructure"}
	case port == 80:
		return portService{"HTTP", "Web server or local web interface", "web"}
	case port == 135:
		return portService{"Windows RPC", "Windows remote procedure calls", "admin"}
	case port == 139 || port == 445:
		return portService{"SMB / NetBIOS", "Windows file and printer sharing", "admin"}
	case port == 161:
		return portService{"SNMP", "Network device management", "admin"}
	case port == 389 || port == 636:
		return portService{"LDAP", "Directory service", "database"}
	case port == 443:
		return portService{"HTTPS", "Secure web server or local web interface", "web"}
	case port == 631:
		return portService{"CUPS", "Printer service and administration", "admin"}
	case port == 1433:
		return portService{"Microsoft SQL Server", "Database service", "database"}
	case port == 1521:
		return portService{"Oracle Database", "Database service", "database"}
	case port == 2049:
		return portService{"NFS", "Network file sharing", "admin"}
	case port == 2375:
		return portService{"Docker API (unencrypted)", "Unauthenticated container management API", "admin"}
	case port == 2376:
		return portService{"Docker API (TLS)", "TLS-protected container management API", "admin"}
	case port == 3000 || port == 3001 || port == 4200 || port == 5173 || port == 8000 || port == 8080:
		return portService{"Development / web server", "Common development server or application web port", "development"}
	case port == 3306:
		return portService{"MySQL / MariaDB", "Database service", "database"}
	case port == 3389:
		return portService{"Remote Desktop (RDP)", "Windows remote desktop access", "remote_access"}
	case port == 5000:
		return portService{"Development server / registry", "Common development server or container registry port", "development"}
	case port == 5432:
		return portService{"PostgreSQL", "Database service", "database"}
	case port == 5900:
		return portService{"VNC", "Remote desktop access", "remote_access"}
	case port == 6443:
		return portService{"Kubernetes API", "Kubernetes cluster administration", "admin"}
	case port == 9090 || port == 8443:
		return portService{"Admin dashboard", "Common application or administration interface port", "admin"}
	case port == 9200:
		return portService{"Elasticsearch", "Search and data service API", "database"}
	case port == 27017:
		return portService{"MongoDB", "Database service", "database"}
	case proto == "udp" && port == 67 || proto == "udp" && port == 68:
		return portService{"DHCP", "Local network address configuration", "infrastructure"}
	case proto == "udp" && port == 123:
		return portService{"NTP", "Time synchronization service", "infrastructure"}
	case proto == "udp" && port == 5353:
		return portService{"mDNS", "Local network service discovery", "infrastructure"}
	case proto == "udp" && port == 5355:
		return portService{"LLMNR", "Local network name resolution", "infrastructure"}
	default:
		return portService{"Unknown service", "No common service is assigned to this port", "unknown"}
	}
}

func portExposure(ip string) string {
	ip = strings.Trim(strings.TrimSpace(ip), "[]")
	if ip == "*" || ip == "" {
		return "all_interfaces"
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		if strings.EqualFold(ip, "localhost") {
			return "loopback"
		}
		return "unknown"
	}
	if parsed.IsLoopback() {
		return "loopback"
	}
	if parsed.IsUnspecified() {
		return "all_interfaces"
	}
	return "network_interface"
}

func portRisk(category, exposure, process string) string {
	switch exposure {
	case "loopback":
		if category == "database" || category == "admin" || category == "remote_access" {
			return "medium"
		}
		return "low"
	case "network_interface", "all_interfaces":
		switch category {
		case "database", "admin", "remote_access":
			return "high"
		case "development":
			return "medium"
		case "unknown":
			if process == "" {
				return "high"
			}
			return "medium"
		default:
			return "low"
		}
	default:
		return "unknown"
	}
}

func portAdvice(category, exposure, process string) string {
	if exposure == "loopback" {
		if category == "database" || category == "admin" || category == "remote_access" {
			return "Only local programs can connect. Confirm you recognize the service and keep it bound to loopback unless other devices need it."
		}
		return "This is limited to this machine. Confirm the process is expected."
	}
	if exposure == "network_interface" || exposure == "all_interfaces" {
		if category == "unknown" && process == "" {
			return "The owner could not be identified and other devices may reach this port. Identify the process and verify whether it should be running; review your OS firewall before exposing it."
		}
		switch category {
		case "database":
			return "Other devices may reach this database. Confirm authentication and encryption are enabled; prefer loopback or a trusted interface and review firewall rules."
		case "admin":
			return "Other devices may reach this management service. Restrict it to trusted interfaces, require authentication, and review firewall rules."
		case "remote_access":
			return "Other devices may attempt remote access. Confirm you enabled it, require strong authentication, and restrict access to trusted networks."
		case "development":
			return "Development servers often lack production security. Stop exposing it when finished or bind it to loopback; check the app's network-binding setting."
		default:
			return "Confirm the process is expected and whether it needs network access; review your OS firewall and bind to loopback if remote access is unnecessary."
		}
	}
	return "The bind address could not be classified. Verify the process and local address before relying on its exposure status."
}

func enrichLocalPorts(raws []rawLocalPort) []LocalPort {
	ports := make([]LocalPort, 0, len(raws))
	for _, raw := range raws {
		service := describePort(raw.protocol, raw.port)
		exposure := portExposure(raw.localIP)
		remoteType := ""
		if raw.remoteIP != "" {
			remoteType = IPClass(raw.remoteIP)
		}
		ports = append(ports, LocalPort{
			Protocol: raw.protocol, LocalIP: raw.localIP, Port: raw.port,
			RemoteIP: raw.remoteIP, RemotePort: raw.remotePort,
			RemoteType: remoteType,
			State:      raw.state, Pid: raw.pid, Process: raw.process,
			Exposure: exposure, Service: service.name, Purpose: service.purpose,
			Category: service.category,
			Risk:     portRisk(service.category, exposure, raw.process),
			Advice:   portAdvice(service.category, exposure, raw.process),
		})
	}
	sort.Slice(ports, func(i, j int) bool {
		if ports[i].Port != ports[j].Port {
			return ports[i].Port < ports[j].Port
		}
		if ports[i].Protocol != ports[j].Protocol {
			return ports[i].Protocol < ports[j].Protocol
		}
		if ports[i].LocalIP != ports[j].LocalIP {
			return ports[i].LocalIP < ports[j].LocalIP
		}
		return ports[i].Pid < ports[j].Pid
	})
	return ports
}

func localPortFindings(scan PortScan) []Finding {
	var findings []Finding
	if !scan.Complete {
		title := "Local port scan incomplete"
		if len(scan.Ports) == 0 {
			title = "Local port scan unavailable"
		}
		detail := scan.Error
		if detail == "" {
			detail = "The platform scanner could not fully inventory sockets or attribute every process owner."
		}
		findings = append(findings, Finding{
			Check: "ports", Severity: SevInfo, Title: title,
			Detail: detail + " The displayed inventory may be partial; check the platform tool and permissions.",
		})
	}
	for _, port := range scan.Ports {
		if port.Exposure != "network_interface" && port.Exposure != "all_interfaces" {
			continue
		}
		if port.Category != "database" && port.Category != "admin" &&
			port.Category != "remote_access" && port.Category != "development" &&
			port.Process != "" {
			continue
		}
		severity := SevMedium
		if port.Risk == "high" {
			severity = SevHigh
		}
		name := port.Service
		if port.Process != "" {
			name = port.Process + " (" + port.Service + ")"
		} else if port.Category == "unknown" {
			name = "unidentified process"
		}
		findings = append(findings, Finding{
			Check: "ports", Severity: severity,
			Title: fmt.Sprintf("Network-reachable %s on %s/%d", name, port.Protocol, port.Port),
			Detail: fmt.Sprintf("%s:%d is %s (%s). %s",
				port.LocalIP, port.Port, port.State, port.Exposure, port.Advice),
			Evidence: map[string]any{
				"protocol": port.Protocol, "local_ip": port.LocalIP, "port": port.Port,
				"state": port.State, "pid": port.Pid, "proc": port.Process,
				"app":     port.Process,
				"service": port.Service, "category": port.Category,
				"exposure": port.Exposure, "risk": port.Risk,
			},
			Fingerprint: FingerprintOf("ports", fmt.Sprintf("%s|%s|%d|%d|%s",
				port.Protocol, port.LocalIP, port.Port, port.Pid, port.Process)),
		})
	}
	return findings
}

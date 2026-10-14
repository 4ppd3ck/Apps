//go:build windows

// Windows network collector.
//
// Runs one persistent PowerShell loop that emits a JSON snapshot of TCP/UDP
// endpoints (with owning process name and user), plus per-adapter byte
// counters, every few seconds. Emits a `connection` event for new remote
// endpoints.
//
// Failures are surfaced: if no valid snapshot arrives within 15s the
// collector degrades and shows PowerShell's own error output in the chip
// status.
//
// Mirrors collectors/network_windows.py.
package collectors

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"monitor"
)

const networkPS = `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$owners = @{}
while ($true) {
  $c = @()
  Get-NetTCPConnection -ErrorAction SilentlyContinue |
    Where-Object { $_.State -ne 'Listen' } | ForEach-Object {
      $c += @{proto='tcp'; state=[string]$_.State; la=[string]$_.LocalAddress;
              lp=$_.LocalPort; ra=[string]$_.RemoteAddress; rp=$_.RemotePort;
              pid=$_.OwningProcess}
    }
  Get-NetUDPEndpoint -ErrorAction SilentlyContinue | ForEach-Object {
    $c += @{proto='udp'; state=''; la=[string]$_.LocalAddress; lp=$_.LocalPort;
            ra=''; rp=''; pid=$_.OwningProcess}
  }
  $procs = @{}
  Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
    $procs[[string]$_.Id] = $_.ProcessName
  }
  $lookups = 0
  foreach ($p in ($c | ForEach-Object { $_.pid } | Sort-Object -Unique)) {
    if ($p -and -not $owners.ContainsKey([string]$p)) {
      if ($lookups -ge 15) { break }   # cap CIM calls/tick: first snapshot fast
      $lookups++
      $pci = Get-CimInstance Win32_Process -Filter "ProcessId=$p" ` + "`" + `
              -ErrorAction SilentlyContinue
      if ($pci) {
        $o = $pci.GetOwner()
        if ($o -and $o.User) { $owners[[string]$p] = "$($o.Domain)\$($o.User)" }
        else { $owners[[string]$p] = '' }
      }
    }
  }
  $adps = @()
  Get-NetAdapterStatistics -ErrorAction SilentlyContinue | ForEach-Object {
    $adps += @{name=$_.Name; rin=$_.ReceivedBytes; out=$_.SentBytes}
  }
  @{conns=$c; procs=$procs; owners=$owners; adps=$adps} |
    ConvertTo-Json -Depth 3 -Compress | Write-Output
  [Console]::Out.Flush()
  Start-Sleep -Seconds 3
}
`

type connKey struct {
	pid string
	rip string
	rp  int
}

// NetworkWindows collects connections + per-adapter rates via PowerShell.
type NetworkWindows struct {
	*BaseCollector
	seen    map[connKey]bool
	prevAdp map[string][2]int64
}

// NewNetworkWindows creates the collector.
func NewNetworkWindows(ctx *monitor.Ctx) *NetworkWindows {
	b := NewBase(ctx, "network-windows",
		"Connections + per-adapter rates via PowerShell", "network")
	c := &NetworkWindows{BaseCollector: b, seen: map[connKey]bool{},
		prevAdp: map[string][2]int64{}}
	b.setRun(c.run)
	return c
}

// newNetworkCollector is the registry hook for the "network" category on Windows.
func newNetworkCollector(ctx *monitor.Ctx) monitor.Collector {
	return NewNetworkWindows(ctx)
}

// Available probes that the Get-NetTCPConnection cmdlet exists -- the
// previous probe used a nonexistent parameter and failed on valid systems.
func (c *NetworkWindows) Available() (bool, string) {
	rc, _, errOut := monitor.Run([]string{"powershell.exe", "-NoProfile", "-Command",
		"if (Get-Command Get-NetTCPConnection -ErrorAction " +
			"SilentlyContinue) { exit 0 } else { exit 1 }"}, 25*time.Second)
	if rc == 127 && strings.Contains(errOut, "not found") {
		return false, "powershell.exe not found"
	}
	if rc == 0 {
		return true, ""
	}
	return false, "Get-NetTCPConnection unavailable"
}

// run starts the PowerShell snapshot loop and surfaces failures loudly:
// if no valid JSON arrives within 15s, the chip shows PowerShell's own error
// output instead of sitting silently on empty panels.
func (c *NetworkWindows) run() {
	scriptPath := c.writeScript()
	cmd := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy",
		"Bypass", "-File", scriptPath)
	cmd.WaitDelay = time.Second
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		c.SetStatus("error", err.Error())
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		c.SetStatus("error", err.Error())
		return
	}
	if err := cmd.Start(); err != nil {
		c.SetStatus("unavailable", "powershell.exe not found")
		return
	}
	proc := cmd
	c.registerProc(proc)
	reader := newLineReader(stdout)
	// drain stderr, keeping the last few lines to surface failures
	errbuf := &errRing{limit: 6}
	go func() {
		scanner := newLineReader(stderr)
		for {
			line, err := scanner.ReadString('\n')
			if t := strings.TrimSpace(line); t != "" {
				errbuf.push(truncateRunes(t, 200))
			}
			if err != nil {
				return
			}
		}
	}()

	outq := make(chan string, 64)
	go func() {
		defer close(outq)
		for {
			line, err := reader.ReadString('\n')
			if strings.TrimSpace(line) != "" {
				outq <- line
			}
			if err != nil {
				return
			}
		}
	}()

	handle := func(line string) bool {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			return false
		}
		var data map[string]any
		if json.Unmarshal([]byte(line), &data) != nil {
			return false
		}
		c.process(data)
		return true
	}

	// first snapshot must arrive within 15s, else degrade visibly
	deadline := time.After(15 * time.Second)
	gotFirst := false
	for !c.Stopped() && !gotFirst {
		select {
		case line, ok := <-outq:
			if !ok {
				goto drain
			}
			gotFirst = handle(line)
		case <-deadline:
			goto drain
		}
	}
drain:
	if !c.Stopped() && !gotFirst {
		tail := "PowerShell produced no output and no error"
		if last := errbuf.last(3); len(last) > 0 {
			tail = strings.Join(last, " | ")
		}
		c.SetStatus("degraded",
			truncateRunes("no data from the snapshot loop: "+tail, 180)+
				" (script: "+scriptPath+")")
		if proc.Process != nil {
			_ = proc.Process.Kill()
		}
		return
	}

	c.SetStatus("active", "PowerShell snapshot loop (3s)")
	for !c.Stopped() {
		select {
		case line, ok := <-outq:
			if !ok {
				return
			}
			handle(line)
		case <-time.After(1 * time.Second):
		}
	}
}

// errRing keeps the last N stderr lines (Python's errbuf list).
type errRing struct {
	mu    sync.Mutex
	lines []string
	limit int
}

func (r *errRing) push(line string) {
	r.mu.Lock()
	r.lines = append(r.lines, line)
	if len(r.lines) > r.limit {
		r.lines = r.lines[len(r.lines)-r.limit:]
	}
	r.mu.Unlock()
}

func (r *errRing) last(n int) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.lines) > n {
		return append([]string(nil), r.lines[len(r.lines)-n:]...)
	}
	return append([]string(nil), r.lines...)
}

func truncateRunes(s string, n int) string {
	runes := []rune(s)
	if len(runes) > n {
		return string(runes[:n])
	}
	return s
}

func (c *NetworkWindows) process(data map[string]any) {
	procs, _ := data["procs"].(map[string]any)
	owners, _ := data["owners"].(map[string]any)
	raw, _ := data["conns"].([]any)
	if raw == nil {
		if m, isMap := data["conns"].(map[string]any); isMap {
			raw = []any{m}
		}
	}
	var conns []map[string]any
	for _, item := range raw {
		cv, ok := item.(map[string]any)
		if !ok {
			continue
		}
		proto, _ := cv["proto"].(string)
		ra, _ := cv["ra"].(string)
		if proto != "tcp" || ra == "" {
			continue
		}
		pid := cv["pid"]
		user := ""
		if owners != nil {
			user, _ = owners[monitor.StrOf(pid)].(string)
		}
		if user == "" {
			user = monitor.GetPassUser()
		}
		state := strings.ToUpper(monitor.StrOf(cv["state"]))
		conns = append(conns, map[string]any{
			"proto":       "tcp",
			"state":       state,
			"local_ip":    monitor.StrOf(cv["la"]),
			"local_port":  intOrNil(cv["lp"]),
			"remote_ip":   ra,
			"remote_port": intOrNil(cv["rp"]),
			"pid":         pid,
			"app":         procs[monitor.StrOf(pid)],
			"user":        user,
		})
	}
	if c.Ctx.Cfg.GetBool("hide_loopback_connections", true) {
		filtered := conns[:0]
		for _, conn := range conns {
			rip, _ := conn["remote_ip"].(string)
			if strings.HasPrefix(rip, "127.") || strings.HasPrefix(rip, "::1") {
				continue
			}
			filtered = append(filtered, conn)
		}
		conns = filtered
	}
	c.Ctx.Net.UpdateConnections(conns)
	c.emitNew(conns)
	c.adapters(data["adps"])
}

func (c *NetworkWindows) emitNew(conns []map[string]any) {
	if len(c.seen) > 4096 {
		c.seen = map[connKey]bool{}
	}
	for _, conn := range conns {
		key := connKey{
			pid: monitor.StrOf(conn["pid"]),
			rip: monitor.StrOf(conn["remote_ip"]),
			rp:  monitor.IntOr(conn["remote_port"], 0),
		}
		if c.seen[key] {
			continue
		}
		c.seen[key] = true
		c.Emit(&monitor.Event{
			Category:  "network",
			Kind:      "connection",
			App:       conn["app"],
			Pid:       conn["pid"],
			User:      conn["user"],
			Remote:    pyJoinAddr(conn["remote_ip"], conn["remote_port"]),
			Local:     pyJoinAddr(conn["local_ip"], conn["local_port"]),
			Proto:     "tcp",
			Direction: monitor.DirectionOf(conn["local_port"], conn["remote_port"]),
			Detail:    conn["state"],
		})
	}
}

// pyJoinAddr and maxI64 live in popen.go (shared across platforms).

func (c *NetworkWindows) adapters(adpsAny any) {
	var adps []any
	switch v := adpsAny.(type) {
	case []any:
		adps = v
	case map[string]any:
		adps = []any{v}
	}
	const dt = 3.0
	totals := map[string][2]int64{}
	for _, item := range adps {
		a, ok := item.(map[string]any)
		if !ok {
			continue
		}
		rin := int64(monitor.IntOr(a["rin"], 0))
		out := int64(monitor.IntOr(a["out"], 0))
		totals[monitor.StrOf(a["name"])] = [2]int64{rin, out}
	}
	prev := c.prevAdp
	c.prevAdp = totals
	if len(prev) == 0 {
		return
	}
	ifaces := map[string]monitor.Rate{}
	var sumIn, sumOut float64
	for name, t := range totals {
		rin, out := t[0], t[1]
		prin, pout := rin, out // Python: prev.get(name, (rin, out))
		if p, ok := prev[name]; ok {
			prin, pout = p[0], p[1]
		}
		rate := monitor.Rate{
			In:       float64(maxI64(rin-prin, 0)) / dt,
			Out:      float64(maxI64(out-pout, 0)) / dt,
			TotalIn:  rin,
			TotalOut: out,
		}
		ifaces[name] = rate
		sumIn += rate.In
		sumOut += rate.Out
	}
	c.Ctx.Net.UpdateTraffic(map[string]monitor.Rate{}, ifaces, sumIn, sumOut)
}

func (c *NetworkWindows) writeScript() string {
	path := filepath.Join(os.TempDir(), "appscope_net.ps1")
	_ = os.WriteFile(path, []byte(networkPS), 0o644)
	return path
}

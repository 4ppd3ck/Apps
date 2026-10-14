//go:build linux

// Linux network collector.
//
//   - `ss -tunapep` -> per-connection table (pid, process, uid, local/remote)
//   - /proc/net/dev -> per-interface byte rates
//   - `nethogs`     -> optional per-process traffic rates (if installed)
//
// Emits a `connection` event when a (process, remote endpoint) pair is first
// seen.
//
// Mirrors collectors/network_linux.py.
package collectors

import (
	"bufio"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"monitor"
)

var (
	reUsers = regexp.MustCompile(`users:\(\("([^"]+)",pid=(\d+)`)
	reUIDSS = regexp.MustCompile(`uid=(\d+)`)
)

// NetworkLinux collects connections (ss) + per-interface rates.
type NetworkLinux struct {
	*BaseCollector
	seen      map[seenKey]bool
	prevIface map[string][2]int64
	nethogsRd *bufio.Reader
}

type seenKey struct {
	pid string
	rip string
	rp  int
}

// NewNetworkLinux creates the collector.
func NewNetworkLinux(ctx *monitor.Ctx) *NetworkLinux {
	b := NewBase(ctx, "network-linux",
		"Connections (ss) + per-interface rates, optional nethogs", "network")
	c := &NetworkLinux{BaseCollector: b, seen: map[seenKey]bool{},
		prevIface: map[string][2]int64{}}
	b.setRun(c.run)
	return c
}

// newNetworkCollector is the registry hook for the "network" category on Linux.
func newNetworkCollector(ctx *monitor.Ctx) monitor.Collector {
	return NewNetworkLinux(ctx)
}

// Available checks for iproute2's ss.
func (c *NetworkLinux) Available() (bool, string) {
	if rc, _, _ := monitor.Run([]string{"ss", "-V"}, 5*time.Second); rc != 0 {
		return false, "ss not found (iproute2 required)"
	}
	return true, ""
}

func (c *NetworkLinux) run() {
	interval := c.Ctx.Poll("network", 3.0)
	c.SetStatus("active", "")
	c.startNethogs()
	for !c.Stopped() {
		t0 := monitor.Now()
		func() {
			defer func() {
				if r := recover(); r != nil {
					c.SetStatus("degraded", panicString(r))
				}
			}()
			conns := c.ssConns()
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
			c.traffic(t0)
		}()
		c.Sleep(interval)
	}
}

// -- connections -----------------------------------------------------------

func (c *NetworkLinux) ssConns() []map[string]any {
	_, out, _ := monitor.Run([]string{"ss", "-tunapep"}, 10*time.Second)
	var conns []map[string]any
	lines := strings.Split(out, "\n")
	for _, line := range lines[1:] {
		toks := strings.Fields(line)
		if len(toks) < 6 {
			continue
		}
		proto, state := toks[0], toks[1]
		local, peer := toks[4], toks[5]
		if state == "LISTEN" || strings.HasPrefix(peer, "*") ||
			strings.HasPrefix(peer, "0.0.0.0") ||
			strings.HasPrefix(peer, "[::]") {
			continue
		}
		row := map[string]any{
			"proto": proto, "state": state, "app": nil, "pid": nil,
			"user": nil, "local_ip": nil, "local_port": nil,
			"remote_ip": nil, "remote_port": nil,
		}
		lip, lport := rpartition(local, ":")
		rip, rport := rpartition(peer, ":")
		row["local_ip"] = strings.Trim(lip, "[]")
		row["local_port"] = intOrNilSS(lport)
		row["remote_ip"] = strings.Trim(rip, "[]")
		row["remote_port"] = intOrNilSS(rport)
		if mu := reUsers.FindStringSubmatch(line); mu != nil {
			row["app"] = mu[1]
			if pid, err := strconv.Atoi(mu[2]); err == nil {
				row["pid"] = pid
			}
		}
		if mu := reUIDSS.FindStringSubmatch(line); mu != nil {
			if uid, err := strconv.Atoi(mu[1]); err == nil {
				row["user"] = monitor.UsernameForUID(uid)
			}
		} else if pid, ok := row["pid"].(int); ok {
			// unprivileged ss omits uid=; own processes are stat-able
			if st, err := os.Stat("/proc/" + strconv.Itoa(pid)); err == nil {
				if sys, sysOk := st.Sys().(*syscall.Stat_t); sysOk {
					row["user"] = monitor.UsernameForUID(int(sys.Uid))
				}
			}
		}
		if rip, ok := row["remote_ip"].(string); ok && rip != "" {
			conns = append(conns, row)
		}
	}
	return conns
}

func (c *NetworkLinux) emitNew(conns []map[string]any) {
	if len(c.seen) > 4096 {
		c.seen = map[seenKey]bool{}
	}
	for _, conn := range conns {
		key := seenKey{
			pid: pyStr(conn["pid"]),
			rip: pyStr(conn["remote_ip"]),
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
			Proto:     conn["proto"],
			Direction: monitor.DirectionOf(conn["local_port"], conn["remote_port"]),
			Detail:    conn["state"],
		})
	}
}

// -- traffic ---------------------------------------------------------------

func (c *NetworkLinux) traffic(t0 float64) {
	dt := monitor.Now() - t0
	if dt < 0.1 {
		dt = 0.1
	}
	ifaces, tin, tout := c.ifaceBytes(dt)
	appRates := c.nethogsRates()
	c.Ctx.Net.UpdateTraffic(appRates, ifaces, tin, tout)
}

func (c *NetworkLinux) ifaceBytes(dt float64) (map[string]monitor.Rate, float64, float64) {
	totals := map[string][2]int64{}
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return map[string]monitor.Rate{}, 0.0, 0.0
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) > 2 {
		lines = lines[2:]
	}
	for _, line := range lines {
		name, rest, found := strings.Cut(line, ":")
		name = strings.TrimSpace(name)
		if !found || strings.HasPrefix(name, "lo") || strings.TrimSpace(rest) == "" {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 9 {
			continue
		}
		ib, _ := strconv.ParseInt(f[0], 10, 64)
		ob, _ := strconv.ParseInt(f[8], 10, 64)
		totals[name] = [2]int64{ib, ob}
	}
	var tin, tout int64
	for _, v := range totals {
		tin += v[0]
		tout += v[1]
	}
	prev := c.prevIface
	c.prevIface = totals
	rate := map[string]monitor.Rate{}
	var tinRate, toutRate float64
	for name, v := range totals {
		ib, ob := v[0], v[1]
		pib, pob := ib, ob // Python: prev.get(name, (ib, ob))
		if p, ok := prev[name]; ok {
			pib, pob = p[0], p[1]
		}
		r := monitor.Rate{
			In:       float64(maxI64(ib-pib, 0)) / dt,
			Out:      float64(maxI64(ob-pob, 0)) / dt,
			TotalIn:  ib,
			TotalOut: ob,
		}
		rate[name] = r
		tinRate += r.In
		toutRate += r.Out
	}
	return rate, tinRate, toutRate
}

// -- per-process rates via nethogs (optional) -------------------------------

func (c *NetworkLinux) startNethogs() {
	if monitor.Which("nethogs") == "" {
		c.SetStatus("active", "ss + /proc/net/dev (install nethogs for "+
			"per-process traffic rates)")
		return
	}
	proc, reader, err := monitor.PopenStream([]string{"nethogs", "-t", "-v", "2"})
	if err != nil {
		return
	}
	c.registerProc(proc)
	c.nethogsRd = reader
}

func (c *NetworkLinux) nethogsRates() map[string]monitor.Rate {
	if c.nethogsRd == nil {
		return map[string]monitor.Rate{}
	}
	rates := map[string]monitor.Rate{}
	deadline := monitor.Now() + 0.05
	for monitor.Now() < deadline {
		line, err := c.nethogsRd.ReadString('\n')
		if line == "" || (err != nil && strings.TrimSpace(line) == "") {
			break
		}
		parts := strings.Split(strings.Trim(line, "\r\n"), "\t")
		if len(parts) != 3 || parts[0] == "Refreshing:" || parts[0] == "" {
			continue
		}
		sent, err1 := strconv.ParseFloat(parts[1], 64)
		recv, err2 := strconv.ParseFloat(parts[2], 64)
		if err1 != nil || err2 != nil {
			continue
		}
		app := strings.Split(strings.Split(parts[0], "/")[0], "?")[0]
		if app == "" {
			app = "unknown"
		}
		r := rates[app]
		r.In += recv * 1024
		r.Out += sent * 1024
		rates[app] = r
	}
	return rates
}

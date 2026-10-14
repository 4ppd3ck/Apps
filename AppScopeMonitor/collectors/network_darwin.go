//go:build darwin

// macOS network collector.
//
//   - `lsof -i -F` -> per-connection table (pid, process, uid, local/remote,
//     state)
//   - `nettop`     -> per-process TCP bytes in/out (rates)
//   - `netstat -ibn` -> per-interface totals (rates)
//
// Emits a `connection` event when a (process, remote endpoint) pair is first
// seen.
//
// Mirrors collectors/network_macos.py.
package collectors

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"monitor"
)

var reNettopLine = regexp.MustCompile(`^\S+\s+(\S+?)\.(\d+)\s+`)
var reNumbers = regexp.MustCompile(`\d+`)

// NetworkMacOS collects connections (lsof) + per-process traffic (nettop).
type NetworkMacOS struct {
	*BaseCollector
	seen      map[seenKeyDarwin]bool
	prevBytes map[string][2]int64
	prevIface map[string][2]int64
}

type seenKeyDarwin struct {
	pid string
	rip string
	rp  int
}

type darwinConn struct {
	pid        any
	app        any
	user       any
	proto      string
	state      string
	localIP    string
	localPort  any
	remoteIP   string
	remotePort any
}

// NewNetworkMacOS creates the collector.
func NewNetworkMacOS(ctx *monitor.Ctx) *NetworkMacOS {
	b := NewBase(ctx, "network-macos", "Connections (lsof) + per-process traffic (nettop)",
		"network")
	c := &NetworkMacOS{BaseCollector: b, seen: map[seenKeyDarwin]bool{},
		prevBytes: map[string][2]int64{}, prevIface: map[string][2]int64{}}
	b.setRun(c.run)
	return c
}

// newNetworkCollector is the registry hook for the "network" category on darwin.
func newNetworkCollector(ctx *monitor.Ctx) monitor.Collector {
	return NewNetworkMacOS(ctx)
}

// Available: always available on darwin.
func (c *NetworkMacOS) Available() (bool, string) { return true, "" }

func (c *NetworkMacOS) run() {
	interval := c.Ctx.Poll("network", 3.0)
	c.SetStatus("active", "")
	for !c.Stopped() {
		t0 := monitor.Now()
		func() {
			defer func() {
				if r := recover(); r != nil {
					c.SetStatus("degraded", panicString(r))
				}
			}()
			conns := c.lsofConns()
			if c.Ctx.Cfg.GetBool("hide_loopback_connections", true) {
				filtered := conns[:0]
				for _, conn := range conns {
					if !c.isLoopback(conn) {
						filtered = append(filtered, conn)
					}
				}
				conns = filtered
			}
			c.Ctx.Net.UpdateConnections(c.connRows(conns))
			c.emitNewConns(conns, interval)
			rates, ifaces, tin, tout := c.traffic(t0)
			c.Ctx.Net.UpdateTraffic(rates, ifaces, tin, tout)
		}()
		c.Sleep(interval)
	}
}

func (c *NetworkMacOS) connRows(conns []darwinConn) []map[string]any {
	rows := make([]map[string]any, 0, len(conns))
	for _, conn := range conns {
		rows = append(rows, map[string]any{
			"pid": conn.pid, "app": conn.app, "user": conn.user,
			"proto": conn.proto, "state": conn.state,
			"local_ip": conn.localIP, "local_port": conn.localPort,
			"remote_ip": conn.remoteIP, "remote_port": conn.remotePort,
		})
	}
	return rows
}

// -- connections ----------------------------------------------------------

// lsofConns parses `lsof -F0` output: NUL-terminated fields; each record's
// last field is followed by a newline. Parse as a flat token stream.
func (c *NetworkMacOS) lsofConns() []darwinConn {
	_, out, _ := monitor.Run([]string{"/usr/sbin/lsof", "-a", "-i", "-n", "-P",
		"-w", "-F0pcnuPnT"}, 12*time.Second)
	var conns []darwinConn
	var proc struct {
		pid  any
		app  any
		user any
	}
	var file *lsofFile

	flush := func() {
		if file != nil && file.proto == "tcp" && file.remoteIP != "" {
			conns = append(conns, darwinConn{
				pid: proc.pid, app: proc.app, user: proc.user,
				proto: file.proto, state: file.state,
				localIP: file.localIP, localPort: file.localPort,
				remoteIP: file.remoteIP, remotePort: file.remotePort,
			})
		}
		file = nil
	}

	for _, tok := range strings.Split(out, "\x00") {
		tok = strings.Trim(tok, "\n\r")
		if len(tok) < 2 {
			continue
		}
		tag, val := tok[0], tok[1:]
		switch tag {
		case 'p':
			flush()
			if pid, err := strconv.Atoi(val); err == nil {
				proc.pid = pid
			} else {
				proc.pid = nil
			}
			proc.app, proc.user = nil, nil
		case 'c':
			proc.app = val
		case 'u':
			if uid, err := strconv.Atoi(val); err == nil {
				proc.user = monitor.UsernameForUID(uid)
			} else {
				proc.user = val
			}
		case 'f':
			flush()
			file = &lsofFile{}
		default:
			if file == nil {
				continue
			}
			switch tag {
			case 'P':
				file.proto = strings.ToLower(val)
			case 'n':
				parseLsofAddr(file, val)
			case 'T':
				if strings.HasPrefix(val, "ST=") {
					file.state = val[3:]
				}
			}
		}
	}
	flush()
	return conns
}

type lsofFile struct {
	proto      string
	state      string
	localIP    string
	localPort  any
	remoteIP   string
	remotePort any
}

func (c *NetworkMacOS) isLoopback(conn darwinConn) bool {
	rip := strings.Trim(conn.remoteIP, "[]")
	return strings.HasPrefix(rip, "127.") || rip == "::1"
}

func parseLsofAddr(row *lsofFile, val string) {
	local, remote := val, ""
	if idx := strings.Index(val, "->"); idx >= 0 {
		local, remote = val[:idx], val[idx+2:]
	}
	lip, lport := rpartition(local, ":")
	row.localIP = strings.Trim(lip, "[]")
	if row.localIP == "" {
		row.localIP = "*"
	}
	row.localPort = intOrNilSS(lport)
	if remote != "" {
		rip, rport := rpartition(remote, ":")
		row.remoteIP = strings.Trim(rip, "[]")
		if row.remoteIP == "" {
			row.remoteIP = "*"
		}
		row.remotePort = intOrNilSS(rport)
	}
}

func (c *NetworkMacOS) emitNewConns(conns []darwinConn, interval float64) {
	if len(c.seen) > 4096 {
		c.seen = map[seenKeyDarwin]bool{}
	}
	for _, conn := range conns {
		key := seenKeyDarwin{
			pid: pyStr(conn.pid),
			rip: conn.remoteIP,
			rp:  monitor.IntOr(conn.remotePort, 0),
		}
		if c.seen[key] {
			continue
		}
		c.seen[key] = true
		c.Emit(&monitor.Event{
			Category:  "network",
			Kind:      "connection",
			App:       conn.app,
			Pid:       conn.pid,
			User:      conn.user,
			Remote:    pyJoinAddr(conn.remoteIP, conn.remotePort),
			Local:     pyJoinAddr(conn.localIP, conn.localPort),
			Proto:     conn.proto,
			Direction: monitor.DirectionOf(conn.localPort, conn.remotePort),
			Detail:    fmt.Sprintf("%s (new in last %.0fs)", pyStr(conn.state), interval),
		})
	}
}

// -- traffic --------------------------------------------------------------

func (c *NetworkMacOS) traffic(t0 float64) (map[string]monitor.Rate, map[string]monitor.Rate, float64, float64) {
	rates := map[string]monitor.Rate{}
	_, out, _ := monitor.Run([]string{"/usr/bin/nettop", "-P", "-x", "-l", "1",
		"-m", "tcp"}, 10*time.Second)
	perApp := map[string][2]int64{}
	lines := strings.Split(out, "\n")
	for _, line := range lines[1:] {
		m := reNettopLine.FindStringSubmatchIndex(line)
		if m == nil {
			continue
		}
		app := line[m[2]:m[3]]
		nums := reNumbers.FindAllString(line[m[1]:], -1)
		if len(nums) < 2 {
			continue
		}
		bin, _ := strconv.ParseInt(nums[0], 10, 64)
		bout, _ := strconv.ParseInt(nums[1], 10, 64)
		prevApp := perApp[app]
		perApp[app] = [2]int64{prevApp[0] + bin, prevApp[1] + bout}
	}

	first := len(c.prevBytes) == 0
	dt := 0.0
	if !first {
		dt = monitor.Now() - t0
		if dt < 0.1 {
			dt = 0.1
		}
	}
	for app, v := range perApp {
		tin, tout := v[0], v[1]
		if prev, ok := c.prevBytes[app]; ok && dt > 0 {
			rates[app] = monitor.Rate{
				In:       float64(maxI64(tin-prev[0], 0)) / dt,
				Out:      float64(maxI64(tout-prev[1], 0)) / dt,
				TotalIn:  tin,
				TotalOut: tout,
			}
		} else {
			rates[app] = monitor.Rate{TotalIn: tin, TotalOut: tout}
		}
	}
	c.prevBytes = map[string][2]int64{}
	for app, r := range rates {
		c.prevBytes[app] = [2]int64{r.TotalIn, r.TotalOut}
	}

	ifaces, tin, tout := c.ifaceRates(dt)
	return rates, ifaces, tin, tout
}

func (c *NetworkMacOS) ifaceRates(dt float64) (map[string]monitor.Rate, float64, float64) {
	_, out, _ := monitor.Run([]string{"/usr/sbin/netstat", "-ibn"}, 8*time.Second)
	totals := map[string][2]int64{}
	headerIdx := -1
	var iName, iIn, iOut int
	for _, line := range strings.Split(out, "\n") {
		toks := strings.Fields(line)
		if headerIdx < 0 {
			hasIn, hasOut := false, false
			for i, t := range toks {
				if t == "Name" {
					iName = i
				}
				if t == "Ibytes" {
					iIn, hasIn = i, true
				}
				if t == "Obytes" {
					iOut, hasOut = i, true
				}
			}
			if hasIn && hasOut {
				headerIdx = 1
			}
			continue
		}
		if len(toks) <= maxInt(iName, maxInt(iIn, iOut)) {
			continue
		}
		name := toks[iName]
		if strings.HasPrefix(name, "lo") || strings.HasPrefix(name, "bridge") {
			continue
		}
		ib, err1 := strconv.ParseInt(toks[iIn], 10, 64)
		ob, err2 := strconv.ParseInt(toks[iOut], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		totals[name] = [2]int64{ib, ob}
	}
	var tin, tout int64
	for _, v := range totals {
		tin += v[0]
		tout += v[1]
	}
	prev := c.prevIface
	rate := map[string]monitor.Rate{}
	if len(prev) > 0 {
		for name, v := range totals {
			ib, ob := v[0], v[1]
			pib, pob := ib, ob
			if p, ok := prev[name]; ok {
				pib, pob = p[0], p[1]
			}
			d := dt
			if d < 0.1 {
				d = 0.1
			}
			rate[name] = monitor.Rate{
				In:       float64(maxI64(ib-pib, 0)) / d,
				Out:      float64(maxI64(ob-pob, 0)) / d,
				TotalIn:  ib,
				TotalOut: ob,
			}
		}
	}
	c.prevIface = totals
	var tinRate, toutRate float64
	for _, r := range rate {
		tinRate += r.In
		toutRate += r.Out
	}
	return rate, tinRate, toutRate
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

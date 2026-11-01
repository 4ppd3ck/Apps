// DNS shield: a local filtering resolver that refuses to resolve blocked
// domains.
//
// Ads and trackers are best blocked at the domain layer, not the IP layer:
// the same CDN address hosts a thousand legitimate sites, and an IP list
// goes stale the moment an ad network moves hosting. The shield sits
// between this machine's resolver and the real upstream DNS servers and
// answers NXDOMAIN for any name on its blocklists — one small listener,
// no external software, no privilege:
//
//	listens   UDP+TCP 127.0.0.1:<dns_port> (default 5333)
//	allow     name (or a parent of it) on an allowlist -> forwarded
//	block     name (or a parent of it) on a blocklist -> NXDOMAIN
//	else      forwarded unmodified to the real resolvers
//
// Port 53 needs root, which the monitor deliberately never runs with. The
// pf helper the Grant button installs carries a `dns on|off` verb that
// redirects loopback port 53 into the shield — a hardcoded constant pair
// of rdr lines, nothing user-supplied (see scripts/appscope-block-helper.sh).
// Pointing the system DNS at 127.0.0.1 is a one-time manual step (the
// dashboard hint spells it out).
//
// Lists live in <data>/dnsblocklists/*.txt. HOSTS-format lines
// ("0.0.0.0 ads.example.com") and bare-domain lines both parse; files
// named allow-*.txt are allowlists and win over every blocklist. Lists
// reload at start, on demand, and whenever a file's mtime changes.
package wtower

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	dnsShieldBind   = "127.0.0.1"
	dnsShieldPort   = 5333 // the pf helper's rdr target — keep in sync
	dnsUpstreamPort = "53"
	dnsQueryMax     = 64 << 10 // largest DNS message accepted (TCP framing)
)

// DNSShield is the filtering resolver (Ctx.DNSShield; nil-safe API paths).
type DNSShield struct {
	ctx *Ctx

	mu      sync.RWMutex
	blocked map[string]bool
	allowed map[string]bool
	lists   []DNSListInfo

	udpConn *net.UDPConn
	tcpLn   net.Listener
	stop    chan struct{}
	wg      sync.WaitGroup
	running bool
	lastErr string
	port    int // the bound port after Start (0 until then)

	queries   atomic.Uint64
	blockedN  atomic.Uint64
	forwarded atomic.Uint64
	errorsN   atomic.Uint64

	upMu      sync.Mutex
	upstreams []string
	upIdx     atomic.Uint64

	routeMu    sync.Mutex
	routeKnown string // "on" | "off" | "unknown" — helper rdr state cache

	// rules overlay: dns_rules table rows applied on top of the *.txt lists
	// at every reload. Provider rules fetch their raw lines from IPolice
	// (CountrySource.ProviderRawLines) and cache them here — the cache
	// survives IPolice outages ("stale cache beats no data").
	providerDomains map[string][]string
	providerSyncAt  map[string]float64 // provider -> last successful sync
	providerErr     map[string]string  // provider -> last sync error
	ruleCounts      map[int64]int      // rule id -> parsed domains
	ruleErr         map[int64]string   // rule id -> load error (missing file…)

	// system-DNS routing: mode (auto-managed vs manual), the watchdog's
	// consecutive-failure count, and the auto-revert record the dashboard
	// banners until the next successful route.
	routeMode    string // "auto" (default) | "manual" — config dns_route_mode
	watchFails   int
	autoReverted *dnsAutoRevert

	// canaryProbe answers "does <addr> resolve DNS right now?"; overridable
	// in tests. Default: a real A query via udpRoundTrip.
	canaryProbe func(addr string) bool

	// opt-in query log (config "dns_log"): the names this machine asked
	// for and — parsed from the upstream answers — which IPs each name
	// resolved to. Memory-only: nothing about query names is written to
	// disk, and switching the log off wipes both structures. The answer
	// map is what names site-visit sessions precisely (the machine asked
	// for that domain, and that domain pointed at that IP).
	logEnabled atomic.Bool
	logMu      sync.Mutex
	queryLog   []DNSLogEntry             // newest last, capped
	answers    map[string]dnsAnswerEntry // resolved IP -> name
}

// DNSLogEntry is one logged DNS query (dashboard display).
type DNSLogEntry struct {
	Ts      float64 `json:"ts"`
	Name    string  `json:"name"`
	Blocked bool    `json:"blocked"`
}

type dnsAnswerEntry struct {
	domain string
	ts     float64
}

const (
	dnsLogCap    = 500  // recent queries kept in memory
	dnsAnswerCap = 8192 // resolved-IP -> name entries kept in memory

	dnsProviderTTL   = 5 * time.Minute // provider rule re-sync cadence
	dnsWatchdogFails = 3               // consecutive canary failures → auto-revert

	// dnsCanaryNames rotates per probe: any single fixed name can be
	// filtered or broken by a particular resolver (one ISP router here
	// blackholes example.com specifically), and a canary that only some
	// networks answer would trip the watchdog spuriously. Any response —
	// NXDOMAIN, SERVFAIL, anything — counts as "the path answers".
	dnsCanaryNames = "google.com,cloudflare.com,github.com,apple.com"
	// dnsCanaryDeadline outlives the shield's worst-case local answer: with
	// dead upstreams forward() tries each in turn (~3s apiece) before
	// answering SERVFAIL, and the canary must still be reading then.
	dnsCanaryDeadline = 10 * time.Second
)

// canaryName picks the next canary name round-robin (atomic index).
var canaryIdx atomic.Uint64

func canaryName() string {
	names := strings.Split(dnsCanaryNames, ",")
	return names[int(canaryIdx.Add(1)-1)%len(names)]
}

// dnsAutoRevert records one watchdog auto-unroute (dashboard banner).
type dnsAutoRevert struct {
	Ts     float64 `json:"ts"`
	Reason string  `json:"reason"`
}

// runDNSHelper invokes the privileged helper's dns verb; a var so tests can
// stub the sudo call.
var runDNSHelper = func(helper, verb string, args ...string) (int, string) {
	cmd := append([]string{"sudo", "-n", helper, "dns", verb}, args...)
	return runCombined(cmd, 15*time.Second)
}

// DNSListInfo describes one loaded domain list (dashboard display).
type DNSListInfo struct {
	Name    string `json:"name"`
	Domains int    `json:"domains"`
	Allow   bool   `json:"allow"`
}

// NewDNSShield creates the shield (not started).
func NewDNSShield(ctx *Ctx) *DNSShield {
	d := &DNSShield{
		ctx:             ctx,
		blocked:         map[string]bool{},
		allowed:         map[string]bool{},
		providerDomains: map[string][]string{},
		providerSyncAt:  map[string]float64{},
		providerErr:     map[string]string{},
		ruleCounts:      map[int64]int{},
		ruleErr:         map[int64]string{},
	}
	d.canaryProbe = defaultCanaryProbe
	if ctx != nil && ctx.Cfg != nil {
		d.logEnabled.Store(ctx.Cfg.GetBool("dns_log", false))
		if m := ctx.Cfg.GetString("dns_route_mode", ""); m == "manual" {
			d.routeMode = "manual"
		} else {
			d.routeMode = "auto"
		}
	}
	d.migrateCustomList()
	return d
}

// migrateCustomList imports the legacy custom.txt one-click blocklist into
// the dns_rules table once, then retires the file (renamed, out of the
// loader's *.txt glob): with rules as the source of truth, a leftover file
// would keep blocking domains the user removed. The config flag makes the
// import idempotent across restarts.
func (d *DNSShield) migrateCustomList() {
	if d.ctx == nil || d.ctx.Store == nil || d.ctx.Cfg == nil {
		return
	}
	if d.ctx.Cfg.GetBool("dns_custom_imported", false) {
		return
	}
	d.ctx.Cfg.Data["dns_custom_imported"] = true
	d.ctx.Cfg.Save()
	imported := 0
	for _, dom := range readCustomListFile(d.listsDir()) {
		if _, err := d.ctx.Store.AddDNSRule("domain", "block", dom, nil); err == nil {
			imported++
		}
	}
	if imported > 0 {
		fmt.Printf("[dns] imported %d custom blocklist entries into dns_rules\n",
			imported)
	}
	_ = os.Rename(filepath.Join(d.listsDir(), customListName+".txt"),
		filepath.Join(d.listsDir(), customListName+".txt.imported"))
}

// LogEnabled reports whether the opt-in query log is recording.
func (d *DNSShield) LogEnabled() bool { return d.logEnabled.Load() }

// SetLogEnabled toggles the query log (config "dns_log", persisted).
// Disabling wipes the in-memory log and answer map: log off means no
// retained query history.
func (d *DNSShield) SetLogEnabled(enabled bool) {
	d.logEnabled.Store(enabled)
	d.logMu.Lock()
	d.queryLog = nil
	d.answers = nil
	d.logMu.Unlock()
	if d.ctx != nil && d.ctx.Cfg != nil {
		d.ctx.Cfg.Data["dns_log"] = enabled
		d.ctx.Cfg.Save()
	}
}

// recordQuery appends one query to the capped in-memory log.
func (d *DNSShield) recordQuery(name string, blocked bool) {
	d.logMu.Lock()
	defer d.logMu.Unlock()
	d.queryLog = append(d.queryLog, DNSLogEntry{Ts: Now(), Name: name, Blocked: blocked})
	if len(d.queryLog) > dnsLogCap {
		d.queryLog = d.queryLog[len(d.queryLog)-dnsLogCap:]
	}
}

// recordAnswers merges parsed upstream answers (IP -> queried name) into
// the bounded answer map, evicting the oldest half when it grows past the
// cap.
func (d *DNSShield) recordAnswers(resolved map[string]string) {
	if len(resolved) == 0 {
		return
	}
	d.logMu.Lock()
	defer d.logMu.Unlock()
	if d.answers == nil {
		d.answers = map[string]dnsAnswerEntry{}
	}
	now := Now()
	for ip, domain := range resolved {
		d.answers[ip] = dnsAnswerEntry{domain: domain, ts: now}
	}
	if len(d.answers) > dnsAnswerCap {
		type kv struct {
			ip string
			e  dnsAnswerEntry
		}
		all := make([]kv, 0, len(d.answers))
		for ip, e := range d.answers {
			all = append(all, kv{ip, e})
		}
		sort.Slice(all, func(i, j int) bool { return all[i].e.ts > all[j].e.ts })
		kept := make(map[string]dnsAnswerEntry, dnsAnswerCap/2)
		for _, item := range all[:dnsAnswerCap/2] {
			kept[item.ip] = item.e
		}
		d.answers = kept
	}
}

// AnswerDomain returns the domain an IP most recently resolved from an
// upstream answer (log enabled only). This is the machine's own naming:
// the exact name an app asked for, not a reverse-DNS guess.
func (d *DNSShield) AnswerDomain(ip string) (string, bool) {
	if !d.logEnabled.Load() {
		return "", false
	}
	d.logMu.Lock()
	defer d.logMu.Unlock()
	if e, ok := d.answers[ip]; ok {
		return e.domain, true
	}
	return "", false
}

// RecentQueries returns a copy of the newest log entries (newest first).
func (d *DNSShield) RecentQueries(max int) []DNSLogEntry {
	d.logMu.Lock()
	defer d.logMu.Unlock()
	if max <= 0 || max > len(d.queryLog) {
		max = len(d.queryLog)
	}
	out := make([]DNSLogEntry, 0, max)
	for i := len(d.queryLog) - 1; i >= len(d.queryLog)-max && i >= 0; i-- {
		out = append(out, d.queryLog[i])
	}
	return out
}

// AnswerCount reports how many resolved-IP names are currently remembered.
func (d *DNSShield) AnswerCount() int {
	d.logMu.Lock()
	defer d.logMu.Unlock()
	return len(d.answers)
}

func (d *DNSShield) listsDir() string {
	return filepath.Join(d.ctx.Cfg.DataDir(), "dnsblocklists")
}

func (d *DNSShield) configuredPort() int {
	return IntOr(d.ctx.Cfg.Data["dns_port"], dnsShieldPort)
}

// Start binds the UDP+TCP listeners, loads the domain lists and begins
// serving. An already-running shield is a no-op.
func (d *DNSShield) Start() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.running {
		return nil
	}
	d.reloadLocked()
	addr := net.JoinHostPort(dnsShieldBind, strconv.Itoa(d.configuredPort()))
	// TCP first: an ephemeral port must be picked once, then shared by both
	// listeners (two independent :0 binds would land on different ports).
	tl, err := net.Listen("tcp4", addr)
	if err != nil {
		return d.failLocked("bind tcp " + addr + ": " + err.Error())
	}
	tcpPort := tl.Addr().(*net.TCPAddr).Port
	uc, err := net.ListenPacket("udp4", net.JoinHostPort(dnsShieldBind, strconv.Itoa(tcpPort)))
	if err != nil {
		tl.Close()
		return d.failLocked("bind udp " + addr + ": " + err.Error())
	}
	d.udpConn = uc.(*net.UDPConn)
	d.tcpLn = tl
	d.port = tcpPort
	d.lastErr = ""
	d.running = true
	d.stop = make(chan struct{})
	d.refreshUpstreams()
	d.wg.Add(3)
	go d.serveUDP()
	go d.serveTCP()
	go d.housekeeping()
	return nil
}

// Port returns the bound shield port (0 before Start).
func (d *DNSShield) Port() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.port
}

// Stop shuts the listeners down (idempotent). While the system DNS route
// is on, the redirect is lifted FIRST and best-effort: a stopped shield
// behind a live rdr blackholes every system lookup — the exact outage the
// watchdog guards between ticks.
func (d *DNSShield) Stop() {
	d.mu.RLock()
	wasRunning := d.running
	d.mu.RUnlock()
	if !wasRunning {
		return
	}
	if d.routeState() == "on" {
		if err := d.routeOff(); err != nil {
			fmt.Printf("[dns] lifting system DNS route on stop failed: %v\n", err)
		}
	}
	d.mu.Lock()
	if !d.running { // a concurrent Stop won the race
		d.mu.Unlock()
		return
	}
	d.running = false
	close(d.stop)
	d.mu.Unlock()
	if d.udpConn != nil {
		d.udpConn.Close()
	}
	if d.tcpLn != nil {
		d.tcpLn.Close()
	}
	d.wg.Wait()
	d.mu.Lock()
	d.udpConn, d.tcpLn = nil, nil
	d.mu.Unlock()
}

func (d *DNSShield) failLocked(msg string) error {
	d.lastErr = truncate(msg, 300)
	return fmt.Errorf("%s", d.lastErr)
}

// Reload re-reads every domain list (used after list edits and by the
// housekeeping tick when mtimes change).
func (d *DNSShield) Reload() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.reloadLocked()
}

// reloadLocked parses data/dnsblocklists/*.txt. HOSTS lines ("0.0.0.0 name")
// and bare domains both work; allow-*.txt files are allowlists. Parse
// failures never keep previously loaded entries or the relay from running.
// The dns_rules table overlays on top: domain/list/provider rules with the
// same allow-wins precedence the classify walk already applies.
func (d *DNSShield) reloadLocked() {
	blocked := map[string]bool{}
	allowed := map[string]bool{}
	lists := []DNSListInfo{}
	entries, err := os.ReadDir(d.listsDir())
	if err == nil {
		for _, e := range entries {
			if e.IsDir() || !strings.EqualFold(filepath.Ext(e.Name()), ".txt") {
				continue
			}
			allow := strings.HasPrefix(strings.ToLower(e.Name()), "allow-")
			data, err := os.ReadFile(filepath.Join(d.listsDir(), e.Name()))
			if err != nil {
				continue
			}
			n := 0
			for _, line := range strings.Split(string(data), "\n") {
				if dom, ok := parseDomainLine(line); ok {
					if allow {
						allowed[dom] = true
					} else {
						blocked[dom] = true
					}
					n++
				}
			}
			lists = append(lists, DNSListInfo{
				Name:    strings.TrimSuffix(e.Name(), filepath.Ext(e.Name())),
				Domains: n,
				Allow:   allow,
			})
		}
	}
	// rule overlay (dns_rules): same two maps, so precedence stays uniform
	if d.ctx != nil && d.ctx.Store != nil {
		if rules, err := d.ctx.Store.ListDNSRules(); err == nil {
			counts, errs := map[int64]int{}, map[int64]string{}
			for _, r := range rules {
				var doms []string
				switch r.Type {
				case "domain":
					if dom, ok := parseDomainLine(r.Value); ok {
						doms = []string{dom}
					} else {
						errs[r.ID] = "not a blockable domain"
					}
				case "list":
					raw, err := os.ReadFile(r.Value)
					if err != nil {
						errs[r.ID] = "cannot read " + r.Value
						break
					}
					for _, line := range strings.Split(string(raw), "\n") {
						if dom, ok := parseDomainLine(line); ok {
							doms = append(doms, dom)
						}
					}
				case "provider":
					doms = d.providerDomains[r.Value]
				}
				counts[r.ID] = len(doms)
				for _, dom := range doms {
					if r.Action == "allow" {
						allowed[dom] = true
					} else {
						blocked[dom] = true
					}
				}
			}
			d.ruleCounts, d.ruleErr = counts, errs
		}
	}
	d.blocked, d.allowed, d.lists = blocked, allowed, lists
}

// localNames are names the shield must never swallow: the dashboard and the
// host's own loopback names ride on them.
var localNames = map[string]bool{
	"localhost": true, "localhost.localdomain": true, "broadcasthost": true,
	"ip6-localhost": true, "ip6-loopback": true,
}

// parseDomainLine extracts one blockable domain from a list line: bare
// domains ("ads.example.com") and HOSTS-style lines ("0.0.0.0 ads.example.com")
// both work; comments, blank lines, local names, wildcards and IP literals
// are skipped.
func parseDomainLine(line string) (string, bool) {
	line = strings.TrimSpace(line)
	if i := strings.IndexAny(line, "#;"); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", false
	}
	tok := fields[0]
	if len(fields) >= 2 { // HOSTS format: "<ip> <domain>" — take the domain
		tok = fields[1]
	}
	tok = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(tok, "*."), "."))
	if tok == "" || !strings.Contains(tok, ".") || localNames[tok] ||
		strings.HasSuffix(tok, ".local") || net.ParseIP(tok) != nil {
		return "", false
	}
	for _, label := range strings.Split(tok, ".") {
		if label == "" || len(label) > 63 {
			return "", false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_' {
				return "", false
			}
		}
	}
	return tok, true
}

// classify walks the query name from the whole domain toward the TLD: the
// first allowlist hit wins, the first blocklist hit blocks — so an
// allow-* list can carve exceptions out of a broad block.
func (d *DNSShield) classify(name string) (allowed, blocked bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	n := name
	for {
		if d.allowed[n] {
			return true, false
		}
		if d.blocked[n] {
			return false, true
		}
		i := strings.Index(n, ".")
		if i < 0 {
			return false, false
		}
		n = n[i+1:]
	}
}

// ------------------------------------------------------------- serving ----

// serveUDP reads datagrams until stopped; each query is answered from its
// own goroutine (a slow upstream must never stall the read loop).
func (d *DNSShield) serveUDP() {
	defer d.wg.Done()
	buf := make([]byte, dnsQueryMax)
	for {
		n, addr, err := d.udpConn.ReadFromUDP(buf)
		if err != nil {
			d.mu.RLock()
			running := d.running
			d.mu.RUnlock()
			if !running {
				return
			}
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go d.handleUDP(pkt, addr)
	}
}

func (d *DNSShield) handleUDP(pkt []byte, addr *net.UDPAddr) {
	resp := d.handleMessage(pkt, false)
	if resp == nil {
		return
	}
	if _, err := d.udpConn.WriteToUDP(resp, addr); err != nil {
		d.errorsN.Add(1)
	}
}

// serveTCP answers DNS-over-TCP clients (length-prefixed messages); some
// stub resolvers fall back to TCP when a UDP reply is truncated.
func (d *DNSShield) serveTCP() {
	defer d.wg.Done()
	for {
		conn, err := d.tcpLn.Accept()
		if err != nil {
			d.mu.RLock()
			running := d.running
			d.mu.RUnlock()
			if !running {
				return
			}
			continue
		}
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			defer conn.Close()
			d.handleTCPConn(conn)
		}()
	}
}

func (d *DNSShield) handleTCPConn(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(conn)
	lenBuf := make([]byte, 2)
	for {
		if _, err := readFull(r, lenBuf); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(lenBuf))
		if n == 0 || n > dnsQueryMax {
			return
		}
		msg := make([]byte, n)
		if _, err := readFull(r, msg); err != nil {
			return
		}
		resp := d.handleMessage(msg, true)
		if resp == nil || len(resp) > dnsQueryMax {
			return
		}
		out := make([]byte, 2+len(resp))
		binary.BigEndian.PutUint16(out, uint16(len(resp)))
		copy(out[2:], resp)
		if _, err := conn.Write(out); err != nil {
			return
		}
	}
}

func readFull(r *bufio.Reader, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// dnsQuery is a parsed query: everything the shield needs to decide and to
// answer in place.
type dnsQuery struct {
	pkt  []byte
	id   uint16
	rd   bool
	name string
	// qStart/qEnd span the question section (header included in qStart=12),
	// copied verbatim into a locally generated reply.
	qStart, qEnd int
}

// handleMessage is the one decision point shared by UDP and TCP: blocked
// names get a locally built NXDOMAIN, everything else (including packets
// too unusual to parse — fail open) is relayed to the real resolvers.
func (d *DNSShield) handleMessage(pkt []byte, viaTCP bool) []byte {
	d.queries.Add(1)
	if len(pkt) < 12 {
		d.errorsN.Add(1)
		return nil
	}
	q, ok := parseQuestion(pkt)
	if !ok {
		// Unparseable question: relay untouched (a filter must not break
		// exotic but legitimate queries it cannot read).
		d.forwarded.Add(1)
		return d.forward(pkt, viaTCP)
	}
	if _, blocked := d.classify(q.name); blocked {
		d.blockedN.Add(1)
		if d.LogEnabled() {
			d.recordQuery(q.name, true)
		}
		return nxdomainResponse(q)
	}
	d.forwarded.Add(1)
	if d.LogEnabled() {
		d.recordQuery(q.name, false)
	}
	return d.forward(pkt, viaTCP)
}

// parseQuestion reads the header and the first question section. It fails
// on anything non-standard (compression pointers in the question section,
// trailing label bytes, zero questions) so the caller relays instead of
// guessing.
func parseQuestion(pkt []byte) (dnsQuery, bool) {
	q := dnsQuery{pkt: pkt}
	q.id = binary.BigEndian.Uint16(pkt[0:2])
	q.rd = pkt[2]&0x01 != 0 // RD is 0x0100: the low bit of the flags' high byte
	qdcount := binary.BigEndian.Uint16(pkt[4:6])
	if qdcount != 1 {
		return q, false
	}
	q.qStart = 12
	off := 12
	for {
		if off >= len(pkt) {
			return q, false
		}
		l := int(pkt[off])
		off++
		if l == 0 {
			break
		}
		if l&0xC0 != 0 { // compression pointer in the question: non-standard
			return q, false
		}
		if off+l > len(pkt) {
			return q, false
		}
		q.name += string(pkt[off:off+l]) + "."
		off += l
	}
	if off+4 > len(pkt) { // QTYPE + QCLASS
		return q, false
	}
	off += 4
	q.qEnd = off
	q.name = strings.TrimSuffix(strings.ToLower(q.name), ".")
	if q.name == "" {
		return q, false
	}
	return q, true
}

// nxdomainResponse builds the "refused to resolve" reply: the query's own
// id, RD and question section, QR|RA set, RCODE=3 (NXDOMAIN).
func nxdomainResponse(q dnsQuery) []byte {
	return localResponse(q, 3)
}

// servfailResponse is the all-upstreams-failed answer (RCODE=2).
func servfailResponse(q dnsQuery) []byte {
	return localResponse(q, 2)
}

func localResponse(q dnsQuery, rcode int) []byte {
	flags := uint16(0x8000) | 0x0080 | uint16(rcode&0xF) // QR | RA | rcode
	if q.rd {
		flags |= 0x0100
	}
	out := make([]byte, 12, 12+(q.qEnd-q.qStart))
	binary.BigEndian.PutUint16(out[0:2], q.id)
	binary.BigEndian.PutUint16(out[2:4], flags)
	binary.BigEndian.PutUint16(out[4:6], 1) // QDCOUNT
	return append(out, q.pkt[q.qStart:q.qEnd]...)
}

// ----------------------------------------------------------- upstreams ----

// refreshUpstreams picks the real resolvers to relay to: the dns_upstreams
// config key wins (comma-separated IP[:port]), else the platform's own
// resolver list (systemUpstreams). Auto-discovered loopback entries are
// always dropped — once the system DNS points at 127.0.0.1, relaying to
// ourselves would be a loop — and explicitly configured ones may target a
// local resolver on another port (a second filter, a dnsmasq…) but never
// the shield's own socket, which is the one loop that must not happen.
// Public resolvers are the last resort.
func (d *DNSShield) refreshUpstreams() {
	var ups []string
	if v := strings.TrimSpace(d.ctx.GetString("dns_upstreams", "")); v != "" {
		for _, part := range strings.Split(v, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			host := part
			port := dnsUpstreamPort
			if h, p, err := net.SplitHostPort(part); err == nil {
				host, port = h, p
			}
			ip := net.ParseIP(strings.Trim(host, "[]"))
			if ip == nil || ip.IsUnspecified() {
				continue
			}
			if ip.IsLoopback() && port == strconv.Itoa(d.selfPort()) {
				continue // relaying to ourselves: an infinite loop
			}
			ups = append(ups, net.JoinHostPort(host, port))
		}
	}
	if len(ups) == 0 {
		for _, ns := range systemUpstreams() {
			ip := net.ParseIP(ns)
			if ip == nil || ip.To4() == nil || ip.IsLoopback() || ip.IsUnspecified() {
				continue
			}
			ups = append(ups, net.JoinHostPort(ns, dnsUpstreamPort))
		}
	}
	if len(ups) == 0 {
		ups = []string{"1.1.1.1:53", "8.8.8.8:53"}
	}
	d.upMu.Lock()
	d.upstreams = ups
	d.upMu.Unlock()
}

// selfPort is the bound shield port (the configured default before Start).
func (d *DNSShield) selfPort() int {
	if d.port != 0 {
		return d.port
	}
	return d.configuredPort()
}

func (d *DNSShield) currentUpstreams() []string {
	d.upMu.Lock()
	defer d.upMu.Unlock()
	out := make([]string, len(d.upstreams))
	copy(out, d.upstreams)
	return out
}

// forward relays a query to the upstream resolvers, trying the next one
// after a failure, and upgrades to TCP when a UDP reply is truncated.
func (d *DNSShield) forward(pkt []byte, viaTCP bool) []byte {
	ups := d.currentUpstreams()
	start := int(d.upIdx.Add(1))
	for i := 0; i < len(ups); i++ {
		up := ups[(start+i)%len(ups)]
		if viaTCP {
			if resp, ok := tcpRoundTrip(up, pkt); ok {
				d.noteUpstreamAnswers(resp)
				return resp
			}
			continue
		}
		resp, truncated := udpRoundTrip(up, pkt)
		if resp == nil {
			continue
		}
		if truncated {
			if full, ok := tcpRoundTrip(up, pkt); ok {
				d.noteUpstreamAnswers(full)
				return full
			}
		}
		d.noteUpstreamAnswers(resp)
		return resp
	}
	var q dnsQuery
	if parsed, ok := parseQuestion(pkt); ok {
		q = parsed
		return servfailResponse(q)
	}
	return nil
}

// noteUpstreamAnswers feeds the opt-in query log's answer map: which IPs
// the upstream said a queried name resolves to.
func (d *DNSShield) noteUpstreamAnswers(resp []byte) {
	if resp == nil || !d.LogEnabled() {
		return
	}
	if resolved := parseDNSAnswers(resp); len(resolved) > 0 {
		d.recordAnswers(resolved)
	}
}

func udpRoundTrip(up string, query []byte) (resp []byte, truncated bool) {
	c, err := net.DialTimeout("udp4", up, 2*time.Second)
	if err != nil {
		return nil, false
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write(query); err != nil {
		return nil, false
	}
	buf := make([]byte, dnsQueryMax)
	n, err := c.Read(buf)
	if err != nil || n < 3 {
		return nil, false
	}
	return buf[:n], buf[2]&0x02 != 0
}

func tcpRoundTrip(up string, query []byte) ([]byte, bool) {
	c, err := net.DialTimeout("tcp4", up, 2*time.Second)
	if err != nil {
		return nil, false
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	msg := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(msg, uint16(len(query)))
	copy(msg[2:], query)
	if _, err := c.Write(msg); err != nil {
		return nil, false
	}
	// one buffered reader for both reads — a second one would drop whatever
	// the first buffered past the length prefix
	r := bufio.NewReader(c)
	lenBuf := make([]byte, 2)
	if _, err := readFull(r, lenBuf); err != nil {
		return nil, false
	}
	n := int(binary.BigEndian.Uint16(lenBuf))
	if n == 0 || n > dnsQueryMax {
		return nil, false
	}
	buf := make([]byte, n)
	if _, err := readFull(r, buf); err != nil {
		return nil, false
	}
	return buf, true
}

// housekeeping refreshes the upstream list (network changes rewrite
// resolv.conf), re-loads the lists when files change on disk, re-syncs
// provider rules from IPolice on their TTL, and runs the routed-health
// watchdog.
func (d *DNSShield) housekeeping() {
	defer d.wg.Done()
	dir := d.listsDir()
	last := dirMtime(dir)
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-d.stop:
			return
		case <-tick.C:
			d.refreshUpstreams()
			now := dirMtime(dir)
			if now != last {
				last = now
				d.Reload()
			}
			if d.syncProviderRules() {
				d.Reload()
			}
			d.watchdogTick()
		}
	}
}

// watchdogTick guards the routed state: while system DNS rides the loopback
// redirect, a wedged shield or broken rdr blackholes every lookup. After
// dnsWatchdogFails consecutive canary failures the route is lifted
// automatically — auto mode also restores the previous system DNS servers
// (the helper recorded them) — and the revert is surfaced in the status
// payload for the dashboard banner.
func (d *DNSShield) watchdogTick() {
	d.routeMu.Lock()
	known := d.routeKnown
	d.routeMu.Unlock()
	if known != "on" {
		d.mu.Lock()
		d.watchFails = 0
		d.mu.Unlock()
		return
	}
	if d.canaryProbe(dnsSystemAddr) {
		d.mu.Lock()
		d.watchFails = 0
		d.mu.Unlock()
		return
	}
	d.mu.Lock()
	d.watchFails++
	fails := d.watchFails
	d.mu.Unlock()
	if fails < dnsWatchdogFails {
		return
	}
	mode := d.RouteMode()
	reason := fmt.Sprintf("system DNS (127.0.0.1:53) failed %d health "+
		"checks in a row — the route was lifted automatically", fails)
	if mode == "auto" {
		reason += " and the previous DNS servers were restored"
	}
	if err := d.routeOff(); err != nil {
		fmt.Printf("[dns] watchdog: %s, but lifting the route failed: %v\n",
			reason, err)
		return
	}
	d.mu.Lock()
	d.watchFails = 0
	d.autoReverted = &dnsAutoRevert{Ts: Now(), Reason: reason}
	d.mu.Unlock()
	fmt.Printf("[dns] watchdog: %s\n", reason)
}

func dirMtime(dir string) time.Time {
	info, err := os.Stat(dir)
	if err != nil {
		return time.Time{}
	}
	return info.ModTime()
}

// parseDNSAnswers extracts A/AAAA records from an upstream response:
// resolved IP -> the name the machine asked for. Compression pointers in
// both names and rdata are handled; anything unusual is skipped (this is a
// naming aid, never a correctness path). Returns nil for non-answer
// packets.
func parseDNSAnswers(pkt []byte) map[string]string {
	if len(pkt) < 12 {
		return nil
	}
	qdcount := int(binary.BigEndian.Uint16(pkt[4:6]))
	ancount := int(binary.BigEndian.Uint16(pkt[6:8]))
	if qdcount > 16 || ancount == 0 || ancount > 64 {
		return nil
	}

	// readName decodes one (possibly compressed) name; the second return is
	// the offset just past it in the ORIGINAL stream (pointers don't move
	// the record cursor on first pass).
	readName := func(off int) (string, int, bool) {
		var labels []string
		end, jumped, steps := 0, false, 0
		for {
			if off >= len(pkt) || steps > len(pkt) {
				return "", 0, false
			}
			steps++
			l := int(pkt[off])
			off++
			if l == 0 {
				if !jumped {
					end = off
				}
				break
			}
			if l&0xC0 != 0 { // compression pointer: 0b11 followed by 14 bits
				if off >= len(pkt) {
					return "", 0, false
				}
				ptr := (l&0x3F)<<8 | int(pkt[off])
				off++
				if !jumped {
					end = off
					jumped = true
				}
				off = ptr
				continue
			}
			if off+l > len(pkt) {
				return "", 0, false
			}
			labels = append(labels, string(pkt[off:off+l]))
			off += l
		}
		return strings.ToLower(strings.Join(labels, ".")), end, true
	}

	off := 12
	for i := 0; i < qdcount; i++ { // skip the question section
		if _, next, ok := readName(off); !ok {
			return nil
		} else {
			off = next
		}
		if off+4 > len(pkt) {
			return nil
		}
		off += 4 // QTYPE + QCLASS
	}
	out := map[string]string{}
	for i := 0; i < ancount && off < len(pkt); i++ {
		name, next, ok := readName(off)
		if !ok {
			break
		}
		off = next
		if off+10 > len(pkt) { // TYPE(2) CLASS(2) TTL(4) RDLENGTH(2)
			break
		}
		rtype := binary.BigEndian.Uint16(pkt[off : off+2])
		off += 8
		rdlen := int(binary.BigEndian.Uint16(pkt[off : off+2]))
		off += 2
		if off+rdlen > len(pkt) {
			break
		}
		switch {
		case rtype == 1 && rdlen == net.IPv4len: // A
			out[net.IP(pkt[off:off+rdlen]).String()] = name
		case rtype == 28 && rdlen == net.IPv6len: // AAAA
			out[net.IP(pkt[off:off+rdlen]).String()] = name
		}
		off += rdlen
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// ------------------------------------------------------------- routing ----

// RouteSystem wires (or unwires) the system's DNS through the shield:
//
//	auto   "dns on manage" — the helper records the current DNS servers per
//	       network service, points them at 127.0.0.1, and restores them on
//	       "dns off". The dashboard never asks the user to edit System
//	       Settings.
//	manual "dns on" — only the loopback :53 redirect installs; the user
//	       points system DNS at 127.0.0.1 themselves.
//
// Enabling is gated: the shield must pass Preflight first (never point the
// system at a resolver that cannot answer), and verified after (a canary
// through 127.0.0.1:53) — a failed post-verify reverts immediately so no
// half-routed state survives. Carrying the same hardcoded 127.0.0.1:5333
// constants as the helper. Loopback-only callers; a helper that predates a
// verb asks for a re-grant in its output. Windows has no UDP port redirect —
// the error points at the elevated-bind alternative instead.
func (d *DNSShield) RouteSystem(enable bool) error {
	var helper string
	switch runtime.GOOS {
	case "darwin":
		helper = HelperMac
	case "linux":
		helper = HelperLinux
	default:
		return fmt.Errorf("system DNS routing is not supported on %s — set "+
			"\"dns_port\": 53 in the config and run the monitor elevated so "+
			"the shield binds port 53 directly, then point the system DNS at "+
			"127.0.0.1", PlatformString())
	}
	if d.port != 0 && d.port != dnsShieldPort {
		return fmt.Errorf("the pf redirect targets the default port %d, but the "+
			"shield is listening on %d — set dns_port back to %d first",
			dnsShieldPort, d.port, dnsShieldPort)
	}
	if !enable {
		return d.routeOff()
	}
	if err := d.Preflight(); err != nil {
		return err
	}
	manage := d.RouteMode() != "manual"
	if manage {
		// helperDnsManageMinVersion: `dns on manage` (record + restore
		// system DNS) arrived with helper protocol 3; an older helper would
		// silently treat it as a plain redirect — manual mode with the
		// system DNS untouched, the exact half-routed surprise to avoid
		const helperDnsManageMinVersion = 3
		if d.ctx == nil || d.ctx.Enforcer == nil ||
			d.ctx.Enforcer.HelperVersion() < helperDnsManageMinVersion {
			return fmt.Errorf("the installed helper predates managed DNS " +
				"routing — click Grant once more to update it, or switch the " +
				"route mode to manual")
		}
	}
	var args []string
	if manage {
		args = []string{"manage"}
	}
	rc, out := runDNSHelper(helper, "on", args...)
	d.routeMu.Lock()
	if rc == 0 {
		d.routeKnown = "on"
	}
	d.routeMu.Unlock()
	if rc != 0 {
		lower := strings.ToLower(out)
		if strings.Contains(lower, "usage") || strings.Contains(lower, "unknown") ||
			strings.Contains(lower, "unrecognized") {
			d.routeMu.Lock()
			d.routeKnown = "unknown"
			d.routeMu.Unlock()
		}
		hint := truncate(out, 300)
		if hint == "" {
			hint = fmt.Sprintf("exit %d", rc)
		}
		if strings.Contains(lower, "usage") {
			hint += " — the installed helper predates managed DNS routing: " +
				"click Grant once more to refresh it (or switch the route " +
				"mode to manual)"
		}
		return fmt.Errorf("%s", hint)
	}
	// post-verify through the real system path; anything less than a
	// working :53 is rolled back so the machine is never left dark
	if !d.canaryProbe(dnsSystemAddr) {
		_ = d.routeOff()
		return fmt.Errorf("the route installed but 127.0.0.1:53 did not " +
			"answer a test query afterwards — everything was reverted " +
			"automatically; check the shield's last error")
	}
	d.mu.Lock()
	d.watchFails = 0
	d.autoReverted = nil // a later successful route clears the banner
	d.mu.Unlock()
	return nil
}

// routeOff lifts the route (helper dns off) — in auto mode the helper also
// restores the DNS servers it recorded per network service. Shared by the
// unroute button, Stop, and the watchdog.
func (d *DNSShield) routeOff() error {
	helper := HelperMac
	if runtime.GOOS == "linux" {
		helper = HelperLinux
	}
	rc, out := runDNSHelper(helper, "off")
	d.routeMu.Lock()
	if rc == 0 {
		d.routeKnown = "off"
	}
	d.routeMu.Unlock()
	if rc != 0 {
		return fmt.Errorf("%s", truncate(out, 300))
	}
	return nil
}

// RouteMode is the cutover mode: "auto" (helper manages system DNS and
// restores it on unroute) or "manual" (user points DNS at 127.0.0.1).
func (d *DNSShield) RouteMode() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.routeMode == "manual" {
		return "manual"
	}
	return "auto"
}

// SetRouteMode persists the cutover mode (config dns_route_mode).
func (d *DNSShield) SetRouteMode(mode string) {
	if mode != "manual" {
		mode = "auto"
	}
	d.mu.Lock()
	d.routeMode = mode
	d.mu.Unlock()
	if d.ctx != nil && d.ctx.Cfg != nil {
		d.ctx.Cfg.Data["dns_route_mode"] = mode
		d.ctx.Cfg.Save()
	}
}

// dnsRoutingSupported reports whether the platform's firewall can carry
// the fixed port-53 redirect (the dashboard shows the route button on it).
func dnsRoutingSupported() bool {
	return runtime.GOOS == "darwin" || runtime.GOOS == "linux"
}

func (d *DNSShield) routeState() string {
	if !dnsRoutingSupported() {
		return ""
	}
	helper := HelperMac
	if runtime.GOOS == "linux" {
		helper = HelperLinux
	}
	d.routeMu.Lock()
	defer d.routeMu.Unlock()
	if d.routeKnown == "" {
		d.routeKnown = "unknown"
		if _, err := os.Stat(helper); err == nil {
			if rc, out := runCombined([]string{"sudo", "-n", helper, "status"}, 10*time.Second); rc == 0 {
				if strings.Contains(strings.ToLower(out), "dns rdr: on") {
					d.routeKnown = "on"
				} else if strings.Contains(strings.ToLower(out), "dns rdr:") {
					d.routeKnown = "off"
				}
			}
		}
	}
	return d.routeKnown
}

// ---------------------------------------------------------------- API ----

// Status is the /api/dns payload.
func (d *DNSShield) Status() map[string]any {
	d.mu.RLock()
	lists := make([]DNSListInfo, len(d.lists))
	copy(lists, d.lists)
	domains := len(d.blocked)
	running := d.running
	port := d.port
	lastErr := d.lastErr
	d.mu.RUnlock()
	payload := map[string]any{
		"running":   running,
		"port":      port,
		"listen":    net.JoinHostPort(dnsShieldBind, strconv.Itoa(port)),
		"supported": dnsRoutingSupported(),
		"routed":    d.routeState(),
		"lists":     lists,
		"domains":   domains,
		"stats": map[string]uint64{
			"queries":   d.queries.Load(),
			"blocked":   d.blockedN.Load(),
			"forwarded": d.forwarded.Load(),
			"errors":    d.errorsN.Load(),
		},
		"rules":      d.RulesStatus(),
		"route_mode": d.RouteMode(),
	}
	d.mu.RLock()
	payload["watch_fails"] = d.watchFails
	if d.autoReverted != nil {
		payload["auto_reverted"] = map[string]any{
			"ts": d.autoReverted.Ts, "reason": d.autoReverted.Reason,
		}
	}
	d.mu.RUnlock()
	if d.RouteMode() == "manual" {
		payload["hint"] = "route installs the loopback port-53 redirect; you " +
			"point system DNS at 127.0.0.1 yourself (System Settings → your " +
			"network → DNS servers) — the shield health-checks the path and " +
			"lifts the redirect for you if it breaks"
	} else {
		payload["hint"] = "click 'route system DNS' — the helper points the " +
			"system resolver at the shield and restores the previous DNS " +
			"servers on unroute (never edit System Settings yourself)"
	}
	if lastErr != "" {
		payload["error"] = lastErr
	}
	if running {
		payload["upstreams"] = d.currentUpstreams()
	}
	payload["log_enabled"] = d.LogEnabled()
	if d.LogEnabled() {
		d.logMu.Lock()
		payload["log_entries"] = len(d.queryLog)
		d.logMu.Unlock()
		payload["answers"] = d.AnswerCount()
	}
	return payload
}

// AddList persists a pasted domain list (data/dnsblocklists/<name>.txt) and
// reloads. The reply carries the parsed domain count so the dashboard can
// show exactly what was accepted.
func (d *DNSShield) AddList(name, text string) (int, error) {
	label := SanitizeLabel(name)
	if label == "" {
		return 0, fmt.Errorf("list name must contain letters, digits or dashes")
	}
	n := 0
	for _, line := range strings.Split(text, "\n") {
		if _, ok := parseDomainLine(line); ok {
			n++
		}
	}
	if n == 0 {
		return 0, fmt.Errorf("no parseable domains in the pasted text — " +
			"one domain per line, or a HOSTS file (0.0.0.0 ads.example.com)")
	}
	dir := d.listsDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, err
	}
	if err := os.WriteFile(filepath.Join(dir, label+".txt"), []byte(strings.TrimRight(text, "\n")+"\n"), 0o600); err != nil {
		return 0, err
	}
	d.Reload()
	return n, nil
}

// RemoveList deletes a pasted list file and reloads.
func (d *DNSShield) RemoveList(name string) error {
	label := SanitizeLabel(name)
	if label == "" {
		return fmt.Errorf("unknown list name")
	}
	if err := os.Remove(filepath.Join(d.listsDir(), label+".txt")); err != nil {
		return err
	}
	d.Reload()
	return nil
}

// -------------------------------------------------------- rule overlay ----

// allowCoversLocked reports whether an allowlist entry (file or pasted
// list) covers dom at or above it in the suffix walk — such a block would
// be a silent no-op, since classify checks allow first at every level.
// Caller holds d.mu.
func (d *DNSShield) allowCoversLocked(dom string) bool {
	for t := dom; ; {
		if d.allowed[t] {
			return true
		}
		i := strings.Index(t, ".")
		if i < 0 {
			return false
		}
		t = t[i+1:]
	}
}

// AddRule validates and stores one dns_rules row, reloads, and for provider
// rules kicks an immediate sync so the first reload is not empty. Domain
// rules covered by an allowlist are refused up front (the same contract the
// one-click block button has: allow always wins, so the entry would be a
// silent no-op).
func (d *DNSShield) AddRule(rtype, action, value string) (int64, error) {
	value = strings.TrimSpace(value)
	if action != "allow" {
		action = "block"
	}
	var detail string
	switch rtype {
	case "domain":
		dom, ok := parseDomainLine(value)
		if !ok {
			return 0, fmt.Errorf("not a blockable domain: %q — one name like "+
				"ads.example.com", value)
		}
		value = dom
		if action == "block" {
			d.mu.RLock()
			covered := d.allowCoversLocked(dom)
			d.mu.RUnlock()
			if covered {
				return 0, fmt.Errorf("%s is covered by an allowlist (allow-* "+
					"entries win) — remove the allow entry instead", dom)
			}
			if d.ctx != nil && d.ctx.Store != nil {
				if rules, err := d.ctx.Store.ListDNSRules(); err == nil {
					allowRules := map[string]bool{}
					for _, r := range rules {
						if r.Action != "allow" || r.Type != "domain" {
							continue
						}
						if v, ok := parseDomainLine(r.Value); ok {
							allowRules[v] = true
						}
					}
					for t := dom; ; {
						if allowRules[t] {
							return 0, fmt.Errorf("%s already has an allow rule "+
								"(allow wins) — remove it instead", dom)
						}
						i := strings.Index(t, ".")
						if i < 0 {
							break
						}
						t = t[i+1:]
					}
				}
			}
		}
		detail = "domain rule"
	case "list":
		if !filepath.IsAbs(value) {
			return 0, fmt.Errorf("list path must be absolute")
		}
		raw, err := os.ReadFile(value)
		if err != nil {
			return 0, fmt.Errorf("cannot read %s", value)
		}
		n := 0
		for _, line := range strings.Split(string(raw), "\n") {
			if _, ok := parseDomainLine(line); ok {
				n++
			}
		}
		if n == 0 {
			return 0, fmt.Errorf("no parseable domains in %s — one domain per "+
				"line, or a HOSTS file (0.0.0.0 ads.example.com)", value)
		}
		detail = fmt.Sprintf("%d domains in %s", n, filepath.Base(value))
	case "provider":
		if SanitizeLabel(value) == "" {
			return 0, fmt.Errorf("empty WGrid provider name")
		}
		detail = "WGrid list — domains synced every " +
			dnsProviderTTL.String() + " (offline IPolice keeps the last set)"
	default:
		return 0, fmt.Errorf("type must be domain, list or provider")
	}
	if d.ctx == nil || d.ctx.Store == nil {
		return 0, fmt.Errorf("rule store unavailable")
	}
	id, err := d.ctx.Store.AddDNSRule(rtype, action, value, &detail)
	if err != nil {
		return 0, err
	}
	if rtype == "provider" {
		d.syncOneProvider(value)
	}
	d.Reload()
	return id, nil
}

// RemoveRule deletes a dns_rules row and reloads.
func (d *DNSShield) RemoveRule(id int64) error {
	if d.ctx == nil || d.ctx.Store == nil {
		return fmt.Errorf("rule store unavailable")
	}
	return d.ctx.Store.RemoveDNSRule(id)
}

// RulesStatus merges the stored rows with their live load state (parsed
// domain counts, provider sync info, per-rule errors) for the dashboard.
func (d *DNSShield) RulesStatus() []map[string]any {
	if d.ctx == nil || d.ctx.Store == nil {
		return []map[string]any{}
	}
	rules, err := d.ctx.Store.ListDNSRules()
	if err != nil {
		return []map[string]any{}
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]map[string]any, 0, len(rules))
	for _, r := range rules {
		row := map[string]any{
			"id": r.ID, "ts": r.Ts, "type": r.Type, "action": r.Action,
			"value": r.Value, "detail": r.Detail, "domains": d.ruleCounts[r.ID],
		}
		if e := d.ruleErr[r.ID]; e != "" {
			row["error"] = e
		}
		if r.Type == "provider" {
			row["synced_at"] = d.providerSyncAt[r.Value]
			if e := d.providerErr[r.Value]; e != "" {
				row["error"] = e
			}
		}
		out = append(out, row)
	}
	return out
}

// syncProviderRules refreshes every provider rule from IPolice when its
// cached copy is older than dnsProviderTTL; reports whether any cached set
// changed (the caller reloads then). Network I/O happens without the shield
// lock; only the cache swap takes it. A failed sync keeps the cached
// domains and records the error for the rules table.
func (d *DNSShield) syncProviderRules() bool {
	if d.ctx == nil || d.ctx.Store == nil || d.ctx.Country == nil {
		return false
	}
	rules, err := d.ctx.Store.ListDNSRules()
	if err != nil {
		return false
	}
	changed := false
	now := Now()
	for _, r := range rules {
		if r.Type != "provider" {
			continue
		}
		d.mu.RLock()
		syncedAt := d.providerSyncAt[r.Value]
		d.mu.RUnlock()
		if now-syncedAt < dnsProviderTTL.Seconds() {
			continue
		}
		if d.syncOneProvider(r.Value) {
			changed = true
		}
	}
	return changed
}

// syncOneProvider pulls one provider's raw lines from IPolice and parses
// them into domains (CIDR/IP lines are skipped by parseDomainLine — a mixed
// list feeds both the firewall's CIDR half and this DNS half). Reports
// whether the cached set changed.
func (d *DNSShield) syncOneProvider(name string) bool {
	if d.ctx == nil || d.ctx.Country == nil {
		return false
	}
	lines, found, err := d.ctx.Country.ProviderRawLines(name)
	var doms []string
	if err == nil && found {
		for _, line := range lines {
			if dom, ok := parseDomainLine(line); ok {
				doms = append(doms, dom)
			}
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	old := d.providerDomains[name]
	switch {
	case err != nil:
		d.providerErr[name] = truncate("IPolice unreachable: "+err.Error(), 200)
		if len(old) > 0 && Now()-d.providerSyncAt[name] < 24*3600 {
			return false // keep serving the last good set; error still surfaced
		}
		delete(d.providerDomains, name)
		return len(old) > 0
	case !found:
		d.providerErr[name] = "IPolice has no provider " + name
		delete(d.providerDomains, name)
		return len(old) > 0
	default:
		delete(d.providerErr, name)
		same := len(old) == len(doms)
		if same {
			for i := range doms {
				if old[i] != doms[i] {
					same = false
					break
				}
			}
		}
		if same && d.providerSyncAt[name] > 0 {
			d.providerSyncAt[name] = Now() // fresh, unchanged: no reload needed
			return false
		}
		d.providerDomains[name] = doms
		d.providerSyncAt[name] = Now()
		return true
	}
}

// ------------------------------------------------- route preflight/watch ----

// buildDNSQuery makes a minimal A query packet for one name.
func buildDNSQuery(name string) []byte {
	pkt := make([]byte, 12)
	binary.BigEndian.PutUint16(pkt[0:2], 0x4a53) // "JS"
	binary.BigEndian.PutUint16(pkt[2:4], 0x0100) // RD
	binary.BigEndian.PutUint16(pkt[4:6], 1)      // QDCOUNT
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			continue
		}
		pkt = append(pkt, byte(len(label)))
		pkt = append(pkt, label...)
	}
	pkt = append(pkt, 0)
	return append(pkt, 0, 1, 0, 1) // QTYPE=A, QCLASS=IN
}

// defaultCanaryProbe sends one A query to host:port and reports whether any
// DNS response came back — NXDOMAIN and SERVFAIL both count: they prove the
// listener and its answer path work even when a rule blocks the name or
// every upstream is down. The read deadline outlives the shield's own
// worst-case answer (sequential upstream timeouts then SERVFAIL), which the
// shared udpRoundTrip's 3 s does not.
func defaultCanaryProbe(addr string) bool {
	c, err := net.DialTimeout("udp4", addr, 2*time.Second)
	if err != nil {
		return false
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(dnsCanaryDeadline))
	if _, err := c.Write(buildDNSQuery(canaryName())); err != nil {
		return false
	}
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	return err == nil && n >= 12
}

// dnsSystemAddr is the address the routed-health watchdog probes: loopback
// :53, the pf rdr target — the exact path system lookups take once routed.
const dnsSystemAddr = "127.0.0.1:53"

// Preflight verifies the shield can answer before system DNS is pointed at
// it: running, then a canary query against the bound port (the rdr does not
// exist yet, so :53 would prove nothing here).
func (d *DNSShield) Preflight() error {
	d.mu.RLock()
	running, port := d.running, d.port
	d.mu.RUnlock()
	if !running {
		return fmt.Errorf("the DNS shield is not running — start it first")
	}
	if !d.canaryProbe(net.JoinHostPort(dnsShieldBind, strconv.Itoa(port))) {
		return fmt.Errorf("the shield did not answer a test query on port %d — "+
			"check the last error in the panel", port)
	}
	return nil
}

// customListName is the legacy one-click "block this domain" file. It is
// imported into dns_rules once at startup and then retired — rules are the
// source of truth for the 🌐 buttons now (see migrateCustomList).
const customListName = "custom"

// BlockDomain adds one domain block rule — the live-connections 🌐 button.
// A domain covered by an allowlist is refused: allow-* always wins, so the
// entry would be a silent no-op and the user should carve the exception out
// of the allow rule instead.
func (d *DNSShield) BlockDomain(domain string) error {
	_, err := d.AddRule("domain", "block", domain)
	return err
}

// UnblockDomain removes the domain's block rule and reloads.
func (d *DNSShield) UnblockDomain(domain string) error {
	dom, ok := parseDomainLine(domain)
	if !ok {
		return fmt.Errorf("not a domain: %q", domain)
	}
	if d.ctx == nil || d.ctx.Store == nil {
		return fmt.Errorf("rule store unavailable")
	}
	rules, err := d.ctx.Store.ListDNSRules()
	if err != nil {
		return err
	}
	for _, r := range rules {
		if r.Type != "domain" || r.Action == "allow" {
			continue
		}
		if v, ok := parseDomainLine(r.Value); ok && v == dom {
			if err := d.ctx.Store.RemoveDNSRule(r.ID); err != nil {
				return err
			}
			d.Reload()
			return nil
		}
	}
	return fmt.Errorf("%s is not on the custom blocklist", dom)
}

// CustomDomains lists the domains currently blocked by a domain rule (the
// dashboard greps it for the per-row 🌐 button state).
func (d *DNSShield) CustomDomains() []string {
	if d.ctx == nil || d.ctx.Store == nil {
		return nil
	}
	rules, err := d.ctx.Store.ListDNSRules()
	if err != nil {
		return nil
	}
	var out []string
	for _, r := range rules {
		if r.Type != "domain" || r.Action == "allow" {
			continue
		}
		if dom, ok := parseDomainLine(r.Value); ok {
			out = append(out, dom)
		}
	}
	return out
}

// readCustomListFile reads the legacy custom.txt's domains (migration input).
func readCustomListFile(dir string) []string {
	data, err := os.ReadFile(filepath.Join(dir, customListName+".txt"))
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		if dom, ok := parseDomainLine(line); ok {
			out = append(out, dom)
		}
	}
	return out
}

// appendCustomLine appends one domain to custom.txt, creating the file with
// a small header on first use. (Legacy path, kept for downgrades.)
func (d *DNSShield) appendCustomLine(dom string) error {
	dir := d.listsDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, customListName+".txt")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if info, err := f.Stat(); err == nil && info.Size() == 0 {
		f.WriteString("# one domain per line — added by the dashboard's " +
			"block-domain button\n")
	}
	_, err = f.WriteString(dom + "\n")
	return err
}

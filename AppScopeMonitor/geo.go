// External-IP geo enrichment: async batched lookups against ip-api.com's
// free batch endpoint (HTTP-only, 45 req/min) with a persistent on-disk
// cache. Lookups never block the SSE stream or the connections snapshot —
// callers only ever read the cache and serve "…" until the worker resolves
// an IP on a later poll. Only external IPs are looked up;
// private/loopback/multicast addresses never leave the box.
package monitor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	geoTTL            = 30 * 24 * time.Hour     // cached lookups expire after 30 days
	geoBatchMax       = 100                     // ip-api batch limit
	geoMinInterval    = 1600 * time.Millisecond // ~37 req/min, under the 45/min cap
	geoRetryDelay     = 10 * time.Minute        // failed-lookup backoff (in-memory only)
	geoRequestTimeout = 10 * time.Second
)

// geoBatchURL is the free-tier batch endpoint (HTTPS is paid-only). The
// fields list keeps replies minimal while still carrying the reverse-DNS
// hostname and the owning org/AS — many content hosts have no rDNS at all,
// and the org is often the only human-readable name an IP will ever have.
const geoBatchURL = "http://ip-api.com/batch/?fields=status,country,countryCode,city,reverse,org,as,query"

// GeoEntry is one cached ip-api result.
type GeoEntry struct {
	CC      string  `json:"cc"`
	Country string  `json:"country,omitempty"`
	City    string  `json:"city,omitempty"`
	Reverse string  `json:"reverse,omitempty"` // reverse-DNS hostname, when the IP has one
	Org     string  `json:"org,omitempty"`     // owning org/ISP, e.g. "Google LLC"
	AS      string  `json:"as,omitempty"`      // e.g. "AS15169 Google LLC"
	At      float64 `json:"at"`
}

type geoFile struct {
	Entries map[string]GeoEntry `json:"entries"`
	// V marks the field set the cache was written with. v2 added
	// reverse/org/as; caches without it predate names, so their entries
	// are aged out on load and refresh with names (rate-limited as usual).
	V int `json:"v,omitempty"`
}

// GeoCache resolves external IPs to country codes asynchronously, batching
// pending IPs into single ip-api.com /batch POSTs from one worker goroutine.
type GeoCache struct {
	endpoint string
	path     string
	client   *http.Client

	mu         sync.Mutex
	entries    map[string]GeoEntry
	pending    map[string]bool
	retryAfter map[string]float64
	nextAt     time.Time
	queue      chan string
}

// NewGeoCache opens (or creates) the persistent cache at path and starts the
// lookup worker. The cache file is data-only and written with 0600 perms.
func NewGeoCache(path string) *GeoCache { return newGeoCache(path, geoBatchURL) }

func newGeoCache(path, endpoint string) *GeoCache {
	g := &GeoCache{
		endpoint:   endpoint,
		path:       path,
		client:     &http.Client{Timeout: geoRequestTimeout},
		entries:    map[string]GeoEntry{},
		pending:    map[string]bool{},
		retryAfter: map[string]float64{},
		queue:      make(chan string, 1024),
	}
	g.load()
	go g.worker()
	return g
}

func (g *GeoCache) load() {
	data, err := os.ReadFile(g.path)
	if err != nil {
		return // absent cache is normal on first run
	}
	var file geoFile
	if err := json.Unmarshal(data, &file); err != nil {
		fmt.Printf("[geo] ignoring bad cache %s: %v\n", g.path, err)
		return
	}
	cutoff := Now() - geoTTL.Seconds()
	for ip, entry := range file.Entries {
		if entry.At >= cutoff {
			if file.V < 2 && entry.Org == "" && entry.Reverse == "" {
				entry.At = 0 // pre-name cache: age out so lookups refresh
			}
			g.entries[ip] = entry
		}
	}
}

// saveLocked persists the cache (caller holds g.mu); expired entries are
// pruned so the file stays bounded.
func (g *GeoCache) saveLocked() {
	cutoff := Now() - geoTTL.Seconds()
	for ip, entry := range g.entries {
		if entry.At < cutoff {
			delete(g.entries, ip)
		}
	}
	data, err := json.Marshal(geoFile{Entries: g.entries, V: 2})
	if err != nil {
		return
	}
	if err := os.WriteFile(g.path, data, 0o600); err != nil {
		if os.MkdirAll(filepath.Dir(g.path), 0o755) == nil {
			err = os.WriteFile(g.path, data, 0o600)
		}
	}
	if err != nil {
		fmt.Printf("[geo] cache write error: %v\n", err)
	}
}

// Get returns the cached entry for ip, scheduling an async lookup on a miss.
// Non-external IPs are never looked up. It never blocks: unresolved IPs
// report ok=false until a later call finds the worker's result.
func (g *GeoCache) Get(ip string) (GeoEntry, bool) {
	if g == nil || !geoLookupable(ip) {
		return GeoEntry{}, false
	}
	g.mu.Lock()
	if entry, ok := g.entries[ip]; ok {
		if Now()-entry.At < geoTTL.Seconds() {
			g.mu.Unlock()
			return entry, true
		}
		delete(g.entries, ip) // expired -> resolve again
	}
	if now := Now(); !g.pending[ip] && now >= g.retryAfter[ip] {
		g.pending[ip] = true
		select {
		case g.queue <- ip:
		default:
			delete(g.pending, ip) // queue full: retried on a later look
		}
	}
	g.mu.Unlock()
	return GeoEntry{}, false
}

// geoLookupable reports whether an IP is external (the only scope worth a
// geo lookup); private/lan/loopback/multicast addresses never leave the box.
func geoLookupable(ip string) bool {
	if ip == "" || ip == "*" {
		return false
	}
	return ClassifyIP(ip) == "external"
}

func (g *GeoCache) worker() {
	for ip := range g.queue {
		batch := []string{ip}
	drain:
		for len(batch) < geoBatchMax {
			select {
			case more := <-g.queue:
				batch = append(batch, more)
			default:
				break drain
			}
		}
		g.lookup(batch)
	}
}

// throttle sleeps until the next request slot so we stay well under the free
// tier's 45 req/min cap.
func (g *GeoCache) throttle() {
	g.mu.Lock()
	wait := time.Until(g.nextAt)
	if wait < 0 {
		wait = 0
	}
	g.nextAt = time.Now().Add(wait).Add(geoMinInterval)
	g.mu.Unlock()
	if wait > 0 {
		time.Sleep(wait)
	}
}

func (g *GeoCache) lookup(ips []string) {
	g.throttle()
	body, err := json.Marshal(ips)
	if err != nil {
		g.fail(ips, err)
		return
	}
	resp, err := g.client.Post(g.endpoint, "application/json", bytes.NewReader(body))
	if err != nil {
		g.fail(ips, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		g.fail(ips, fmt.Errorf("batch endpoint returned %s", resp.Status))
		return
	}
	var results []struct {
		Status      string `json:"status"`
		Country     string `json:"country"`
		CountryCode string `json:"countryCode"`
		City        string `json:"city"`
		Reverse     string `json:"reverse"`
		Org         string `json:"org"`
		AS          string `json:"as"`
		Query       string `json:"query"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&results); err != nil {
		g.fail(ips, err)
		return
	}
	now := Now()
	g.mu.Lock()
	for _, r := range results {
		if r.Query == "" {
			continue
		}
		if r.Status == "success" && len(r.CountryCode) == 2 {
			g.entries[r.Query] = GeoEntry{
				CC: strings.ToUpper(r.CountryCode), Country: r.Country,
				City: r.City, Reverse: r.Reverse, Org: r.Org, AS: r.AS,
				At: now,
			}
		} else {
			g.retryAfter[r.Query] = now + geoRetryDelay.Seconds()
		}
	}
	for _, ip := range ips {
		delete(g.pending, ip) // IPs missing from the reply retry later
	}
	g.saveLocked()
	g.mu.Unlock()
}

func (g *GeoCache) fail(ips []string, err error) {
	now := Now()
	g.mu.Lock()
	for _, ip := range ips {
		delete(g.pending, ip)
		g.retryAfter[ip] = now + geoRetryDelay.Seconds()
	}
	g.mu.Unlock()
	fmt.Printf("[geo] lookup error: %v\n", err)
}

// ccToFlag renders an ISO 3166-1 alpha-2 code as its emoji flag (regional
// indicator symbol pair). Anything but exactly two ASCII letters yields ""
// (Windows renders the pair as plain letters — the dashboard shows the code
// next to the flag anyway).
func ccToFlag(cc string) string {
	if len(cc) != 2 {
		return ""
	}
	out := make([]rune, 0, 2)
	for i := 0; i < 2; i++ {
		ch := cc[i]
		switch {
		case ch >= 'a' && ch <= 'z':
			ch = ch - 'a' + 'A'
		case ch >= 'A' && ch <= 'Z':
		default:
			return ""
		}
		out = append(out, rune(0x1F1E6+int(ch-'A')))
	}
	return string(out)
}

// ------------------------------------------------------- enrichment ----

// enrichConnections adds geo fields (cache-only, async) and first_seen (from
// the connection history) to live snapshot rows. It never touches the
// network: unresolved external IPs get geo_pending=true and resolve on a
// later poll once the geo worker fills the cache.
func enrichConnections(ctx *Ctx, conns []map[string]any) {
	if len(conns) == 0 {
		return
	}
	var starts map[string]float64
	if ctx != nil && ctx.Store != nil {
		starts, _ = ctx.Store.OpenConnectionStarts()
	}
	for _, row := range conns {
		if ctx != nil && ctx.Geo != nil {
			if remoteIP, _ := row["remote_ip"].(string); ClassifyIP(remoteIP) == "external" {
				if entry, ok := ctx.Geo.Get(remoteIP); ok {
					row["geo_cc"] = entry.CC
					row["geo_country"] = entry.Country
					if entry.City != "" {
						row["geo_city"] = entry.City
					}
					if entry.Reverse != "" {
						row["geo_reverse"] = entry.Reverse
					}
					if entry.Org != "" {
						row["geo_org"] = entry.Org
					}
				} else {
					row["geo_pending"] = true
				}
			}
		}
		if starts != nil {
			if key := connectionIdentityKey(row); key != "" {
				if started, ok := starts[key]; ok {
					row["first_seen"] = started
				}
			}
		}
	}
}

// connectionIdentityKey rebuilds the exact identity string the connection
// history uses (Store.RecordConnectionSnapshot), so live rows can join their
// history record for the first-seen timestamp.
func connectionIdentityKey(row map[string]any) string {
	identity, err := json.Marshal(connectionIdentity{
		PID:      nullableText(row["pid"]),
		App:      nullableText(row["app"]),
		Protocol: strings.ToUpper(nullableText(row["proto"])),
		Local:    formatConnectionEndpoint(row["local_ip"], row["local_port"]),
		Remote:   formatConnectionEndpoint(row["remote_ip"], row["remote_port"]),
	})
	if err != nil {
		return ""
	}
	return string(identity)
}

// enrichConnectionRecords adds cached geo fields to connection-history
// records (cache-only; misses just schedule the async lookup for later).
func enrichConnectionRecords(ctx *Ctx, records []*ConnectionRecord) {
	if ctx == nil || ctx.Geo == nil {
		return
	}
	for _, rec := range records {
		if rec == nil || rec.Scope != "external" {
			continue
		}
		host := rec.Remote
		if h, _, err := net.SplitHostPort(rec.Remote); err == nil {
			host = h
		}
		if entry, ok := ctx.Geo.Get(strings.Trim(host, "[]")); ok {
			rec.GeoCC = entry.CC
			rec.GeoCountry = entry.Country
			rec.GeoCity = entry.City
			rec.GeoReverse = entry.Reverse
			rec.GeoOrg = entry.Org
		}
	}
}

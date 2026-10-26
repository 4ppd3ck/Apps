// Country-level (CIDR) block data: per-country IPv4 ranges consumed from
// IPolice, the internet-facing companion app, over loopback — exactly the
// Sentinel pattern (Sentinel/cmd/sentinel/intel.go): the monitor itself
// never fetches feeds from the internet, IPolice does, and an offline
// IPolice degrades to the last cached table ("queued" rules, never errors
// that break the dashboard).
//
// The monitor auto-configures one IPolice source per blocked country on
// first use: firehol's per-country netset (raw.githubusercontent.com, HTTPS)
// — IPolice's `text` format parses those files natively. Ranges are cached
// on disk under data/country-cidrs/ so restarts and IPolice outages keep
// the last good table enforceable.
//
// Safety: loopback, RFC1918, link-local, multicast, bogon and broadcast
// ranges are filtered out before anything reaches the firewall (again in
// the privileged helpers), and the loopback API is never affected.
package monitor

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// IPoliceDefaultURL is the loopback base URL of the IPolice companion
	// app; override with the IPOLICE_URL env (the Sentinel contract).
	IPoliceDefaultURL = "http://127.0.0.1:8770"

	countryProviderPrefix = "country/"
	countryCacheTTL       = 7 * 24 * time.Hour
	countryFetchTimeout   = 10 * time.Second
	countryRefreshTimeout = 120 * time.Second // git-based feeds can be slow
	ownCountryTTL         = time.Hour
	// maxRemoteIPChars is the conservative netsh command-line budget for one
	// rule's remoteip= list (Windows CL size is ~32k; 400 IPv4 CIDRs land
	// far below both that and the firewall's per-rule entry limit).
	maxRemoteIPChars = 8000
	maxRemoteIPRules = 400 // hard cap of ranges per firewall rule
)

var (
	ccRe    = regexp.MustCompile(`^[A-Za-z]{2}$`)
	cidrRe  = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$`)
	ownCCRe = regexp.MustCompile(`"countryCode"\s*:\s*"([A-Za-z]{2})"`)
)

// ValidCC checks an ISO-3166-1 alpha-2 country code.
func ValidCC(cc string) bool { return ccRe.MatchString(cc) }

// NormalizeCC upper-cases and trims a country code ("" when invalid).
func NormalizeCC(cc string) string {
	cc = strings.ToUpper(strings.TrimSpace(cc))
	if !ValidCC(cc) {
		return ""
	}
	return cc
}

// ParseCIDRLine validates one IPv4 CIDR ("203.0.113.0/24"); "" when invalid.
func ParseCIDRLine(line string) string {
	line = strings.TrimSpace(line)
	if !cidrRe.MatchString(line) {
		return ""
	}
	if _, _, err := net.ParseCIDR(line); err != nil {
		return ""
	}
	prefix, err := strconv.Atoi(line[strings.LastIndex(line, "/")+1:])
	if err != nil || prefix < 1 || prefix > 32 {
		return ""
	}
	return line
}

// isProtectedCIDR reports ranges that must never be blocked: loopback,
// RFC1918, link-local, 0/8, 240/4 (reserved), multicast, broadcast — the
// machine's own subnets and the dashboard's loopback API live there.
func isProtectedCIDR(cidr string) bool {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return true // unparsable: fail closed
	}
	if network.IP.To4() == nil {
		return true // IPv4-only feature
	}
	return network.IP.IsLoopback() || network.IP.IsPrivate() ||
		network.IP.IsLinkLocalUnicast() || network.IP.IsLinkLocalMulticast() ||
		network.IP.IsUnspecified() || network.IP.IsMulticast() ||
		network.Contains(net.IPv4bcast) ||
		// CGNAT (100.64.0.0/10) is not IsPrivate but is carrier-owned
		(network.IP[0] == 100 && network.IP[1] >= 64 && network.IP[1] <= 127)
}

// FilterSafeCIDRs keeps valid, non-protected IPv4 CIDRs, deduplicated and
// sorted (stable output for tests and for firewall file diffs).
func FilterSafeCIDRs(cidrs []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(cidrs))
	for _, c := range cidrs {
		c = ParseCIDRLine(c)
		if c == "" || seen[c] || isProtectedCIDR(c) {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// SanitizeLabel reduces a user-supplied name to the charset the firewall
// helpers accept (lowercase alphanumerics, dash, underscore; max 32).
func SanitizeLabel(label string) string {
	var sb strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(label)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			sb.WriteRune(r)
		default:
			sb.WriteRune('-')
		}
	}
	out := strings.Trim(sb.String(), "-")
	if len(out) > 32 {
		out = out[:32]
	}
	return out
}

// ParseIPFile reads a user blocklist: one IPv4 CIDR or bare IP per line
// (bare IPs become /32), `#` comments — full-line and inline — skipped,
// protected ranges filtered. This is the `list` rule's data source; the
// same file shape ships as scripts/sample-blocklist.txt.
func ParseIPFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw []string
	for _, line := range strings.Split(string(data), "\n") {
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.Contains(line, "/") {
			line += "/32" // bare IP: a single host
		}
		raw = append(raw, line)
	}
	return FilterSafeCIDRs(raw), nil
}

// EnsureListSource registers a user blocklist file as an IPolice `file`
// source (IPolice re-reads it on every refresh), so the same ranges are
// visible to IPolice's dashboard and to Sentinel — the "both" wiring:
// the monitor enforces the file directly, IPolice mirrors it. Existing
// registration is success.
func (cs *CountrySource) EnsureListSource(label, path string) error {
	if cs == nil {
		return nil // no IPolice wiring without the client; direct still works
	}
	src := map[string]any{
		"name":   "list/" + label,
		"type":   "file",
		"path":   path,
		"format": "text",
	}
	if err := cs.postJSON("/api/sources/add", src); err != nil {
		if strings.Contains(err.Error(), "already configured") {
			return nil
		}
		return err
	}
	return cs.postJSON("/api/refresh", map[string]any{})
}

// ChunkCIDRs splits a CIDR list into groups whose joined remoteip= string
// stays under maxChars and maxRules entries (netsh command-line budget).
func ChunkCIDRs(cidrs []string, maxChars, maxRules int) [][]string {
	var chunks [][]string
	var cur []string
	chars := 0
	for _, c := range cidrs {
		if len(cur) >= maxRules || (len(cur) > 0 && chars+len(c)+1 > maxChars) {
			chunks = append(chunks, cur)
			cur, chars = nil, 0
		}
		cur = append(cur, c)
		chars += len(c) + 1
	}
	if len(cur) > 0 {
		chunks = append(chunks, cur)
	}
	return chunks
}

type countryCacheFile struct {
	Countries map[string]countryEntry `json:"countries"`
}

type countryEntry struct {
	CC        string   `json:"cc"`
	CIDRs     []string `json:"cidrs"`
	FetchedAt float64  `json:"fetched_at"`
}

// CountrySource serves per-country CIDR lists from IPolice with a disk
// cache. Nil-safe: a nil *CountrySource behaves like an absent IPolice.
type CountrySource struct {
	base string
	hc   *http.Client
	dir  string // data dir; cache lives in country-cidrs/

	mu          sync.Mutex
	cache       map[string]countryEntry
	lastAttempt map[string]float64 // cc -> last fetch attempt (Now())
	up          bool
	lastErr     string

	ownCountry   string
	ownCountryAt time.Time
	ownCountryFn func() (string, error) // overridable in tests
}

// NewCountrySource opens (or creates) the disk cache under dir/country-cidrs.
func NewCountrySource(dir string) *CountrySource {
	cs := &CountrySource{
		base:        ipoliceBaseURL(),
		hc:          &http.Client{Timeout: countryFetchTimeout},
		dir:         filepath.Join(dir, "country-cidrs"),
		cache:       map[string]countryEntry{},
		lastAttempt: map[string]float64{},
	}
	cs.ownCountryFn = cs.fetchOwnCountry
	cs.load()
	return cs
}

func ipoliceBaseURL() string {
	if v := os.Getenv("IPOLICE_URL"); v != "" {
		return strings.TrimRight(v, "/")
	}
	return IPoliceDefaultURL
}

func (cs *CountrySource) cachePath(cc string) string {
	return filepath.Join(cs.dir, cc+".json")
}

func (cs *CountrySource) load() {
	raw, err := os.ReadFile(filepath.Join(cs.dir, "index.json"))
	if err != nil {
		return
	}
	var file countryCacheFile
	if json.Unmarshal(raw, &file) != nil || file.Countries == nil {
		return
	}
	cutoff := Now() - countryCacheTTL.Seconds()
	for cc, e := range file.Countries {
		if e.FetchedAt >= cutoff {
			cs.cache[cc] = e
		}
	}
}

func (cs *CountrySource) saveLocked() {
	if err := os.MkdirAll(cs.dir, 0o755); err != nil {
		return
	}
	raw, err := json.Marshal(countryCacheFile{Countries: cs.cache})
	if err != nil {
		return
	}
	if err := os.WriteFile(filepath.Join(cs.dir, "index.json"), raw, 0o600); err != nil {
		fmt.Printf("[country] cache write error: %v\n", err)
	}
}

// Cached returns the currently cached ranges for a cache key (a country
// code, or an IPolice provider name for provider rules) — no I/O to
// IPolice. ok=false when nothing is cached. Used by the dashboard and by
// enforcer rebuild paths.
func (cs *CountrySource) Cached(key string) ([]string, bool) {
	if cs == nil {
		return nil, false
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return nil, false
	}
	cs.mu.Lock()
	defer cs.mu.Unlock()
	e, ok := cs.cache[key]
	if !ok {
		return nil, false
	}
	// filtered: the count and any rebuild path should reflect what would
	// actually be enforced
	return FilterSafeCIDRs(e.CIDRs), true
}

// CachedCount returns the cached CIDR count for a country (0 when absent).
func (cs *CountrySource) CachedCount(cc string) int {
	cidrs, ok := cs.Cached(cc)
	if !ok {
		return 0
	}
	return len(cidrs)
}

// EnsureBackground is Ensure for cache-warming paths (block add, reconcile,
// dashboard polls): one attempt per country per minute, failures silent —
// IPolice's feed refresh runs concurrently and the next attempt catches it.
func (cs *CountrySource) EnsureBackground(cc string) {
	if cs == nil {
		return
	}
	cc = NormalizeCC(cc)
	if cc == "" {
		return
	}
	cs.mu.Lock()
	if Now()-cs.lastAttempt[cc] < 60 {
		cs.mu.Unlock()
		return
	}
	cs.mu.Unlock()
	_, _ = cs.Ensure(cc)
}

// EnsureProvider fetches a user-managed IPolice provider's CIDRs — the
// "upload a list in IPolice, block it in the monitor" path. Cache-first
// with the same TTL as countries; the user manages the source in IPolice
// (Databases UI or API), the monitor only consumes it.
func (cs *CountrySource) EnsureProvider(name string) ([]string, error) {
	if cs == nil {
		return nil, fmt.Errorf("country data source unavailable")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("empty IPolice provider name")
	}
	cs.mu.Lock()
	e, ok := cs.cache[name]
	fresh := ok && Now()-e.FetchedAt < countryCacheTTL.Seconds()
	cs.lastAttempt["provider:"+name] = Now()
	cs.mu.Unlock()
	if fresh {
		return FilterSafeCIDRs(e.CIDRs), nil
	}
	cidrs, found, err := cs.providerCIDRs(name)
	if err != nil {
		if ok { // stale cache beats no data
			return FilterSafeCIDRs(e.CIDRs), nil
		}
		return nil, fmt.Errorf("IPolice (%s) unreachable: %w", cs.base, err)
	}
	if !found {
		if ok {
			return FilterSafeCIDRs(e.CIDRs), nil
		}
		return nil, fmt.Errorf("IPolice has no provider %q — add it in "+
			"IPolice first (Databases → add source)", name)
	}
	if len(cidrs) == 0 {
		if ok {
			return FilterSafeCIDRs(e.CIDRs), nil
		}
		return nil, fmt.Errorf("IPolice provider %q has no ranges", name)
	}
	cs.mu.Lock()
	cs.cache[name] = countryEntry{CC: name, CIDRs: cidrs, FetchedAt: Now()}
	cs.saveLocked()
	cs.mu.Unlock()
	return cidrs, nil
}

// EnsureProviderBackground is the debounced cache-warmer for provider rules.
func (cs *CountrySource) EnsureProviderBackground(name string) {
	if cs == nil {
		return
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return
	}
	cs.mu.Lock()
	if Now()-cs.lastAttempt["provider:"+name] < 60 {
		cs.mu.Unlock()
		return
	}
	cs.mu.Unlock()
	_, _ = cs.EnsureProvider(name)
}

// ProviderNames lists the IPolice providers the user manages themselves —
// everything except the monitor-managed country/* and list/* feeds.
func (cs *CountrySource) ProviderNames() ([]string, error) {
	if cs == nil {
		return nil, fmt.Errorf("country data source unavailable")
	}
	var payload struct {
		Providers []struct {
			Name string `json:"name"`
		} `json:"providers"`
	}
	if err := cs.getJSON("/api/networks", &payload); err != nil {
		return nil, err
	}
	var out []string
	for _, p := range payload.Providers {
		if p.Name == "" ||
			strings.HasPrefix(p.Name, countryProviderPrefix) ||
			strings.HasPrefix(p.Name, "list/") {
			continue
		}
		out = append(out, p.Name)
	}
	sort.Strings(out)
	return out, nil
}

// Ensure returns the safe CIDR list for cc, refreshing from IPolice when
// the cache is missing or stale. Errors carry a dashboard-ready reason.
func (cs *CountrySource) Ensure(cc string) ([]string, error) {
	if cs == nil {
		return nil, fmt.Errorf("country data source unavailable")
	}
	cc = NormalizeCC(cc)
	if cc == "" {
		return nil, fmt.Errorf("invalid country code")
	}
	cs.mu.Lock()
	cs.lastAttempt[cc] = Now()
	cs.mu.Unlock()
	cs.mu.Lock()
	e, ok := cs.cache[cc]
	fresh := ok && Now()-e.FetchedAt < countryCacheTTL.Seconds()
	cs.mu.Unlock()
	if fresh {
		// cached entries are filtered too: defense in depth against a
		// poisoned or hand-edited cache file
		return FilterSafeCIDRs(e.CIDRs), nil
	}

	cidrs, err := cs.fetchFromIPolice(cc)
	if err != nil {
		if ok { // stale cache beats no data
			return FilterSafeCIDRs(e.CIDRs), nil
		}
		return nil, err
	}
	if len(cidrs) == 0 {
		if ok {
			return append([]string(nil), e.CIDRs...), nil
		}
		return nil, fmt.Errorf("IPolice returned no ranges for country %s", cc)
	}
	cs.mu.Lock()
	cs.cache[cc] = countryEntry{CC: cc, CIDRs: cidrs, FetchedAt: Now()}
	cs.saveLocked()
	cs.mu.Unlock()
	return cidrs, nil
}

// countryRetryGap paces the post-registration polls: IPolice's feed refresh
// runs concurrently with this function, so the provider may appear only
// after a few seconds. Var so tests can shrink it.
var countryRetryGap = 2500 * time.Millisecond

// fetchFromIPolice pulls provider "country/<CC>" from IPolice, registering
// the country feed as a source first when the provider is missing.
func (cs *CountrySource) fetchFromIPolice(cc string) ([]string, error) {
	cidrs, ok, err := cs.providerCIDRs(countryProviderPrefix + cc)
	if err != nil {
		return nil, fmt.Errorf("IPolice (%s) unreachable: %w", cs.base, err)
	}
	if ok {
		return cidrs, nil
	}
	// The provider does not exist yet: register its feed in IPolice
	// (persisted to sources.json there), refresh, and poll briefly — the
	// feed fetch runs concurrently with these checks.
	if err := cs.ensureIPoliceSource(cc); err != nil {
		return nil, fmt.Errorf("IPolice has no country/%s feed and registering "+
			"it failed: %w", cc, err)
	}
	for attempt := 0; attempt < 5; attempt++ {
		time.Sleep(countryRetryGap)
		cidrs, ok, err = cs.providerCIDRs(countryProviderPrefix + cc)
		if err != nil {
			return nil, fmt.Errorf("IPolice (%s) unreachable after source add: %w",
				cs.base, err)
		}
		if ok {
			return cidrs, nil
		}
	}
	return nil, fmt.Errorf("IPolice has no ranges for country/%s yet — "+
		"its feed is still refreshing; try again shortly", cc)
}

// providerCIDRs GETs /api/networks and extracts one provider's CIDRs.
func (cs *CountrySource) providerCIDRs(provider string) ([]string, bool, error) {
	var payload struct {
		Providers []struct {
			Name  string   `json:"name"`
			Cidrs []string `json:"cidrs"`
		} `json:"providers"`
	}
	if err := cs.getJSON("/api/networks", &payload); err != nil {
		return nil, false, err
	}
	cs.mu.Lock()
	cs.up = true
	cs.lastErr = ""
	cs.mu.Unlock()
	for _, p := range payload.Providers {
		if p.Name == provider {
			return FilterSafeCIDRs(p.Cidrs), true, nil
		}
	}
	return nil, false, nil
}

// ensureIPoliceSource registers a per-country zone as an IPolice source
// (ipdeny.com's published country ranges, fetched by IPolice over HTTPS —
// it is the internet-facing half of the pair). "already configured" is
// success.
func (cs *CountrySource) ensureIPoliceSource(cc string) error {
	lcc := strings.ToLower(cc)
	src := map[string]any{
		"name":   countryProviderPrefix + cc,
		"type":   "http",
		"url":    "https://www.ipdeny.com/ipblocks/data/countries/" + lcc + ".zone",
		"format": "text",
	}
	if err := cs.postJSON("/api/sources/add", src); err != nil {
		if strings.Contains(err.Error(), "already configured") {
			return nil
		}
		return err
	}
	// sources/add activates the source; refresh pulls the feed now.
	if err := cs.postJSON("/api/refresh", map[string]any{}); err != nil {
		return fmt.Errorf("IPolice refresh failed: %w", err)
	}
	return nil
}

func (cs *CountrySource) getJSON(path string, out any) error {
	resp, err := cs.hc.Get(cs.base + path)
	if err != nil {
		cs.markDown(err)
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		cs.markDown(fmt.Errorf("%s -> %d", path, resp.StatusCode))
		return fmt.Errorf("IPolice %s -> %d", path, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		cs.markDown(err)
		return err
	}
	return nil
}

func (cs *CountrySource) postJSON(path string, body any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	hc := &http.Client{Timeout: countryRefreshTimeout}
	resp, err := hc.Post(cs.base+path, "application/json", strings.NewReader(string(raw)))
	if err != nil {
		cs.markDown(err)
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		var payload struct {
			Error string `json:"error"`
		}
		msg := fmt.Sprintf("%s -> %d", path, resp.StatusCode)
		if json.NewDecoder(resp.Body).Decode(&payload) == nil && payload.Error != "" {
			msg = payload.Error
		}
		cs.markDown(fmt.Errorf("%s", msg))
		return fmt.Errorf("IPolice %s", msg)
	}
	return nil
}

func (cs *CountrySource) markDown(err error) {
	cs.mu.Lock()
	cs.up = false
	cs.lastErr = err.Error()
	cs.mu.Unlock()
}

// Status summarizes the IPolice link for the dashboard. Read-only: it must
// never trigger a fetch (only blockAdd resolves the own country on demand).
func (cs *CountrySource) Status() map[string]any {
	if cs == nil {
		return map[string]any{"available": false, "reason": "country source unavailable"}
	}
	cs.mu.Lock()
	defer cs.mu.Unlock()
	out := map[string]any{
		"url":       cs.base,
		"up":        cs.up,
		"available": cs.up,
	}
	if cs.lastErr != "" {
		out["last_error"] = cs.lastErr
		out["reason"] = cs.lastErr
	}
	if cs.ownCountry != "" && time.Since(cs.ownCountryAt) < ownCountryTTL {
		out["own_country"] = cs.ownCountry
	}
	return out
}

// OwnCountry best-effort resolves the machine's own country (via ip-api,
// the same plain-HTTP posture as the geo enrichment) and caches it for an
// hour. "" when unknown — the own-country guardrail then degrades to the
// UI confirmation only.
func (cs *CountrySource) OwnCountry() string {
	if cs == nil {
		return ""
	}
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.ownCountryLocked()
}

func (cs *CountrySource) ownCountryLocked() string {
	if cs.ownCountry != "" && time.Since(cs.ownCountryAt) < ownCountryTTL {
		return cs.ownCountry
	}
	if cs.ownCountryFn == nil {
		return ""
	}
	cc, err := cs.ownCountryFn()
	if err != nil || cc == "" {
		return ""
	}
	cs.ownCountry = cc
	cs.ownCountryAt = time.Now()
	return cc
}

// fetchOwnCountry asks ip-api for this machine's public-IP country. Plain
// HTTP on purpose: identical posture to geo.go's ip-api batch calls (the
// app.json network flag documents the posture; see README).
func (cs *CountrySource) fetchOwnCountry() (string, error) {
	client := &http.Client{Timeout: 6 * time.Second}
	resp, err := client.Get("http://ip-api.com/json/?fields=status,countryCode")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("ip-api -> %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	m := ownCCRe.FindSubmatch(raw)
	if m == nil {
		return "", fmt.Errorf("ip-api: no countryCode in response")
	}
	return strings.ToUpper(string(m[1])), nil
}

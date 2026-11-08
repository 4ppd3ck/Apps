package main

// IntelFeed — the known-IP intelligence feed. This is the original wGrid
// engine, standalone again: it spent a while merged into wHawk and then
// wTower, and this split restores its own app.
//
// Fetches published network ranges of well-known providers (Google/YouTube,
// Cloudflare, GitHub, …) plus a bundled static seed for providers without
// stable feeds (Apple, Meta), and serves them over the /api/* surface so
// the peers find it: wHawk's net checks and wTower's country-block source
// label known endpoints from here (WGRID_URL / the launcher registry point
// them at this server).
//
// Sources come from http(s) feeds, local files, or git repos (see Source) in
// formats parsed by ParseFeedColumn. Sources sharing a Name merge into one
// provider (union of their networks); a provider whose every source fails
// keeps its previous networks and records the errors.

import (
	"bytes"
	"crypto/rand"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Provider is one named set of known networks.
type Provider struct {
	Name      string   `json:"name"`
	Cidrs     []string `json:"cidrs"`
	UpdatedAt float64  `json:"updated_at"`
	Origin    string   `json:"origin"` // "fetch" (live source) | "seed" (bundled snapshot)
	Source    string   `json:"source,omitempty"`
	Error     string   `json:"error,omitempty"`
}

// Source is one dynamic database. Formats (see ParseFeedColumn):
//
//	goog         — Google's ipranges JSON ({"prefixes":[{"ipv4Prefix":…}]})
//	text         — one CIDR per line (Cloudflare ips-v4 / Telegram cidr.txt)
//	aws          — AWS ip-ranges.json ({"prefixes":[{"ip_prefix":…}], …})
//	csv          — CSV with a network column (see CSVColumn)
//	ms365        — Microsoft 365 endpoints JSON ([{"ips":[…]}, …])
//	github-meta  — api.github.com/meta ({"git":[…], "web":[…], …})
//	fastly       — api.fastly.com/public-ip-list ({"addresses":[…], "ipv6":[…]})
//
// Types: "" / "http" fetches URL; "git" shallow-clones URL into
// data/repos/<slug> and reads Path inside it; "file" reads the local Path.
type Source struct {
	Name      string `json:"name"`
	URL       string `json:"url,omitempty"`
	Format    string `json:"format"`
	Type      string `json:"type,omitempty"` // "" / "http" | "git" | "file"
	Path      string `json:"path,omitempty"` // git: file inside the repo · file: local path
	Branch    string `json:"branch,omitempty"`
	CSVColumn string `json:"csv_column,omitempty"` // csv: header name or 1-based index
}

func (s Source) kind() string {
	switch s.Type {
	case "git", "file":
		return s.Type
	default:
		return "http"
	}
}

// displayURL is the human-readable location used in errors and the UI.
func (s Source) displayURL() string {
	switch s.kind() {
	case "file":
		if s.Path != "" {
			return s.Path
		}
		return s.URL
	case "git":
		if s.Path != "" {
			return s.URL + " · " + s.Path
		}
		return s.URL
	default:
		return s.URL
	}
}

func sameSource(a, b Source) bool {
	return a.Name == b.Name && a.URL == b.URL && a.Path == b.Path && a.kind() == b.kind()
}

func dedupeSources(list []Source) []Source {
	out := make([]Source, 0, len(list))
	for _, s := range list {
		dup := false
		for _, e := range out {
			if sameSource(e, s) {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, s)
		}
	}
	return out
}

// Cond carries the validator headers of the last successful http fetch so the
// next one can be conditional (ETag / If-Modified-Since → 304).
type Cond struct {
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
}

type Cache struct {
	Providers []Provider        `json:"providers"`
	Errors    map[string]string `json:"errors,omitempty"`
	UpdatedAt float64           `json:"updated_at"`
	ETags     map[string]Cond   `json:"etags,omitempty"`
}

func DefaultSources() []Source {
	// Deliberately limited to providers whose ranges are THEIR OWN services.
	// Cloud-hosting feeds (AWS/Azure/GCP customer space) are intentionally
	// not defaults: arbitrary customer workloads — including malware C2 —
	// live there, so "known AWS" must never mean "known good". See README
	// for how to add such a feed anyway.
	return []Source{
		{Name: "Google & YouTube", URL: "https://www.gstatic.com/ipranges/goog.json", Format: "goog"},
		{Name: "Cloudflare", URL: "https://www.cloudflare.com/ips-v4", Format: "text"},
		{Name: "Cloudflare", URL: "https://www.cloudflare.com/ips-v6", Format: "text"},
		{Name: "GitHub", URL: "https://api.github.com/meta", Format: "github-meta"},
	}
}

// seedProviders are bundled snapshots for providers without a stable public
// feed. They only apply when no fetched provider of the same name exists —
// a live source named "Meta" replaces the Meta seed, and if that source
// fails the seed still serves while the error is reported.
func seedProviders() []Provider {
	at := float64(1730000000) // snapshot taken 2025-10
	seed := func(name string, cidrs ...string) Provider {
		return Provider{Name: name, Cidrs: cidrs, UpdatedAt: at, Origin: "seed"}
	}
	return []Provider{
		// Apple owns all of 17/8 (ASN information, stable for decades).
		seed("Apple", "17.0.0.0/8"),
		// Meta/Facebook published ranges.
		seed("Meta",
			"31.13.24.0/21", "31.13.64.0/18", "31.13.80.0/24", "45.64.40.0/22",
			"57.144.110.0/24", "66.220.144.0/20", "69.63.176.0/20",
			"69.171.224.0/19", "102.132.96.0/20", "129.134.0.0/17",
			"157.240.0.0/17", "173.252.64.0/18", "179.60.192.0/22",
			"185.60.216.0/22", "204.15.20.0/22", "2a03:2880::/29"),
		// GitHub published service ranges (backup for the live meta feed).
		seed("GitHub",
			"140.82.112.0/20", "143.55.64.0/20", "185.199.108.0/22",
			"192.30.252.0/22", "20.201.28.151/32", "20.205.243.166/32",
			"20.248.137.48/32", "20.26.104.152/32", "4.160.170.144/32",
			"102.133.202.161/32", "20.26.156.212/32", "20.87.245.216/32",
			"20.87.245.6/32", "20.102.85.16/32", "20.27.70.102/32",
			"20.200.245.247/32", "20.233.83.145/32", "20.201.29.67/32"),
	}
}

// IntelFeed fetches, caches and serves the provider tables.
type IntelFeed struct {
	mu      sync.Mutex
	sources []Source
	cache   Cache
	nets    map[string][]*net.IPNet // provider -> parsed networks
	hc      *http.Client
	dataDir string
	refresh time.Duration
	lastTry float64
}

func NewIntelFeed(dataDir string, refresh time.Duration) *IntelFeed {
	return &IntelFeed{
		sources: DefaultSources(),
		nets:    map[string][]*net.IPNet{},
		hc:      &http.Client{Timeout: 30 * time.Second},
		dataDir: dataDir,
		refresh: refresh,
	}
}

// Load reads sources.json (if the user wrote one) and the cache, then
// refreshes in the background when the cache is empty or stale.
func (it *IntelFeed) Load() {
	it.loadSources()
	if it.loadCache() {
		it.rebuildNets()
	}
	if it.needRefresh() {
		go it.Refresh()
	}
}

func (it *IntelFeed) needRefresh() bool {
	it.mu.Lock()
	defer it.mu.Unlock()
	fetched := 0
	for _, p := range it.cache.Providers {
		if p.Origin == "fetch" && len(p.Cidrs) > 0 {
			fetched++
		}
	}
	return fetched == 0 || Now()-it.cache.UpdatedAt > it.refresh.Seconds()
}

// Refresh fetches every source, merges results per provider name, unions
// them with seeds, and persists the cache. A failing source never wipes the
// data of healthy sources sharing its name; a provider whose sources all
// fail keeps its previous networks. Sources reporting 304 Not Modified
// count as healthy (their data is unchanged).
func (it *IntelFeed) Refresh() {
	it.mu.Lock()
	it.lastTry = Now()
	sources := append([]Source(nil), it.sources...)
	prev := make(map[string]Provider, len(it.cache.Providers))
	for _, p := range it.cache.Providers {
		prev[p.Name] = p
	}
	it.mu.Unlock()

	type result struct {
		src   Source
		cidrs []string
		err   error
	}
	results := make(chan result, len(sources))
	for _, s := range sources {
		go func(s Source) {
			cidrs, err := it.fetchOne(s)
			results <- result{s, cidrs, err}
		}(s)
	}

	type agg struct {
		ok                [][]string
		okUrls            []string
		failed, notMod, n int
	}
	aggs := map[string]*agg{}
	errs := map[string]string{}
	for range sources {
		r := <-results
		a := aggs[r.src.Name]
		if a == nil {
			a = &agg{}
			aggs[r.src.Name] = a
		}
		a.n++
		skey := r.src.Name + " " + r.src.displayURL()
		switch {
		case r.err == nil:
			a.ok = append(a.ok, r.cidrs)
			a.okUrls = append(a.okUrls, r.src.displayURL())
		case errors.Is(r.err, errNotModified):
			a.notMod++
		default:
			a.failed++
			errs[skey] = FmtErr(r.err)
		}
	}

	seedNames := map[string]bool{}
	for _, sp := range seedProviders() {
		seedNames[sp.Name] = true
	}

	providers := make([]Provider, 0, len(aggs))
	for name, a := range aggs {
		p, had := prev[name]
		switch {
		case len(a.ok) > 0:
			lists := a.ok
			if had && a.n > len(a.ok) { // some source kept old data — merge it in
				lists = append(append([][]string{}, a.ok...), p.Cidrs)
			}
			sort.Strings(a.okUrls)
			providers = append(providers, Provider{
				Name: name, Cidrs: unionCidrs(lists), UpdatedAt: Now(),
				Origin: "fetch", Source: strings.Join(a.okUrls, ", "),
			})
		case had:
			// 304s and/or failures with previous data: keep the old networks.
			p.Origin = "fetch"
			if a.failed == a.n {
				p.Error = errText(name, sources, errs)
			} else {
				p.Error = ""
			}
			providers = append(providers, p)
		default:
			// Everything failed on first fetch. Don't shadow a bundled seed
			// with an empty error stub — the seed serves and errs has the detail.
			if !seedNames[name] {
				providers = append(providers, Provider{Name: name, Origin: "fetch", Error: errText(name, sources, errs)})
			}
		}
	}
	sort.Slice(providers, func(i, j int) bool { return providers[i].Name < providers[j].Name })
	have := map[string]bool{}
	for _, p := range providers {
		have[p.Name] = true
	}
	for _, sp := range seedProviders() {
		if !have[sp.Name] {
			providers = append(providers, sp)
		}
	}

	// All fetches have returned, so it.cache.ETags now carries any validators
	// they stored — carry it into the replacement cache.
	it.mu.Lock()
	it.cache = Cache{Providers: providers, Errors: errs, UpdatedAt: Now(), ETags: it.cache.ETags}
	it.rebuildNetsLocked()
	it.mu.Unlock()
	it.saveCache()
}

func errText(name string, sources []Source, errs map[string]string) string {
	parts := []string{}
	for _, s := range sources {
		if s.Name != name {
			continue
		}
		if e, ok := errs[name+" "+s.displayURL()]; ok {
			parts = append(parts, s.displayURL()+": "+e)
		}
	}
	return strings.Join(parts, " · ")
}

func unionCidrs(lists [][]string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, 64)
	for _, l := range lists {
		for _, c := range l {
			c = strings.TrimSpace(c)
			if c == "" || seen[c] {
				continue
			}
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

func (it *IntelFeed) rebuildNets() {
	it.mu.Lock()
	defer it.mu.Unlock()
	it.rebuildNetsLocked()
}

func (it *IntelFeed) rebuildNetsLocked() {
	nets := map[string][]*net.IPNet{}
	for _, p := range it.cache.Providers {
		for _, c := range p.Cidrs {
			if _, n, err := net.ParseCIDR(c); err == nil {
				nets[p.Name] = append(nets[p.Name], n)
			}
		}
	}
	it.nets = nets
}

// Lookup reports the provider whose range contains ip, if any.
func (it *IntelFeed) Lookup(ipStr string) (string, bool) {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return "", false
	}
	it.mu.Lock()
	defer it.mu.Unlock()
	for name, nets := range it.nets {
		for _, n := range nets {
			if n.Contains(ip) {
				return name, true
			}
		}
	}
	return "", false
}

func (it *IntelFeed) Cache() Cache {
	it.mu.Lock()
	defer it.mu.Unlock()
	// Providers is always a non-nil slice (never marshals as JSON null): a
	// consumer probing {"providers":[…]} — wTower's blocklist probe — must
	// see a valid array even before the first refresh populates it.
	provs := make([]Provider, 0, len(it.cache.Providers))
	provs = append(provs, it.cache.Providers...)
	c := Cache{Providers: provs, UpdatedAt: it.cache.UpdatedAt}
	if len(it.cache.Errors) > 0 {
		c.Errors = map[string]string{}
		for k, v := range it.cache.Errors {
			c.Errors[k] = v
		}
	}
	return c
}

func (it *IntelFeed) hasProvider(name string) bool {
	it.mu.Lock()
	defer it.mu.Unlock()
	for _, p := range it.cache.Providers {
		if p.Name == name {
			return true
		}
	}
	return false
}

func (it *IntelFeed) sourceConfigured(s Source) bool {
	it.mu.Lock()
	defer it.mu.Unlock()
	for _, e := range it.sources {
		if sameSource(e, s) {
			return true
		}
	}
	return false
}

func (it *IntelFeed) Status() map[string]any {
	c := it.Cache()
	networks := 0
	providers := map[string]int{}
	for _, p := range c.Providers {
		providers[p.Name] += len(p.Cidrs)
		networks += len(p.Cidrs)
	}
	return map[string]any{
		"providers":  providers,
		"networks":   networks,
		"updated_at": c.UpdatedAt,
		"errors":     c.Errors,
		"sources":    it.sourceList(),
	}
}

func (it *IntelFeed) sourceList() []Source {
	it.mu.Lock()
	defer it.mu.Unlock()
	return append([]Source(nil), it.sources...)
}

// RefreshLoop refreshes on the configured cadence until stop is closed.
func (it *IntelFeed) RefreshLoop(stop <-chan struct{}) {
	t := time.NewTicker(it.refresh)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			it.Refresh()
		}
	}
}

// ------------------------------------------------------------- fetching ----

var errNotModified = errors.New("not modified")

// fetchOne reads one source over http, from a local file, or out of a git repo.
func (it *IntelFeed) fetchOne(s Source) ([]string, error) {
	switch s.kind() {
	case "file":
		if strings.TrimSpace(s.Path) == "" {
			return nil, fmt.Errorf("file source %q: path required", s.Name)
		}
		raw, err := os.ReadFile(s.Path)
		if err != nil {
			return nil, err
		}
		return parseSource(s, raw)
	case "git":
		raw, err := gitRepoFile(s, filepath.Join(it.dataDir, "repos"))
		if err != nil {
			return nil, err
		}
		return parseSource(s, raw)
	default:
		return it.fetchHTTP(s)
	}
}

func parseSource(s Source, raw []byte) ([]string, error) {
	cidrs, err := ParseFeedColumn(s.Format, raw, s.CSVColumn)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", s.displayURL(), err)
	}
	if len(cidrs) == 0 {
		return nil, fmt.Errorf("%s: feed contained no networks", s.displayURL())
	}
	return cidrs, nil
}

func (it *IntelFeed) fetchHTTP(s Source) ([]string, error) {
	url := s.URL
	if s.Format == "ms365" {
		url = withRequestGUID(url)
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "wgrid-intelfeed/"+appVersion)
	key := s.kind() + "|" + s.URL + "|" + s.Path
	it.mu.Lock()
	cond := it.cache.ETags[key]
	it.mu.Unlock()
	if cond.ETag != "" {
		req.Header.Set("If-None-Match", cond.ETag)
	}
	if cond.LastModified != "" {
		req.Header.Set("If-Modified-Since", cond.LastModified)
	}

	resp, err := it.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotModified:
		return nil, errNotModified
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("%s -> HTTP %d", s.URL, resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	cidrs, err := ParseFeedColumn(s.Format, raw, s.CSVColumn)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", s.URL, err)
	}
	if len(cidrs) == 0 {
		return nil, fmt.Errorf("%s: feed contained no networks", s.URL)
	}

	nc := Cond{ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified")}
	it.mu.Lock()
	if it.cache.ETags == nil {
		it.cache.ETags = map[string]Cond{}
	}
	if nc.ETag == "" && nc.LastModified == "" {
		delete(it.cache.ETags, key)
	} else {
		it.cache.ETags[key] = nc
	}
	it.mu.Unlock()
	return cidrs, nil
}

// withRequestGUID appends the fresh clientrequestid GUID that Microsoft's
// endpoints service expects on every request.
func withRequestGUID(u string) string {
	if strings.Contains(u, "clientrequestid=") {
		return u
	}
	sep := "?"
	if strings.Contains(u, "?") {
		sep = "&"
	}
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	guid := fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
	return u + sep + "clientrequestid=" + guid
}

// ParseFeed extracts CIDR strings from a supported feed format.
func ParseFeed(format string, raw []byte) ([]string, error) {
	return ParseFeedColumn(format, raw, "")
}

// ParseFeedColumn is ParseFeed with an optional csv column selector
// (header name or 1-based index).
func ParseFeedColumn(format string, raw []byte, column string) ([]string, error) {
	switch format {
	case "goog":
		var feed struct {
			Prefixes []struct {
				IPv4Prefix string `json:"ipv4Prefix"`
				IPv6Prefix string `json:"ipv6Prefix"`
			} `json:"prefixes"`
		}
		if err := json.Unmarshal(raw, &feed); err != nil {
			return nil, err
		}
		out := []string{}
		for _, p := range feed.Prefixes {
			if p.IPv4Prefix != "" {
				out = append(out, p.IPv4Prefix)
			}
			if p.IPv6Prefix != "" {
				out = append(out, p.IPv6Prefix)
			}
		}
		return out, nil
	case "aws":
		var feed struct {
			Prefixes []struct {
				Prefix string `json:"ip_prefix"`
			} `json:"prefixes"`
			IPv6 []struct {
				Prefix string `json:"ipv6_prefix"`
			} `json:"ipv6_prefixes"`
		}
		if err := json.Unmarshal(raw, &feed); err != nil {
			return nil, err
		}
		out := []string{}
		for _, p := range feed.Prefixes {
			if p.Prefix != "" {
				out = append(out, p.Prefix)
			}
		}
		for _, p := range feed.IPv6 {
			if p.Prefix != "" {
				out = append(out, p.Prefix)
			}
		}
		return out, nil
	case "text":
		raw = bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf"))
		out := []string{}
		for _, line := range strings.Split(string(raw), "\n") {
			if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
				out = append(out, line)
			}
		}
		return out, nil
	case "csv":
		return parseCSV(raw, column)
	case "ms365":
		var feed []struct {
			IPS []string `json:"ips"`
		}
		if err := json.Unmarshal(raw, &feed); err != nil {
			return nil, err
		}
		out := []string{}
		for _, e := range feed {
			for _, v := range e.IPS {
				if n, ok := normalizeNet(v); ok {
					out = append(out, n)
				}
			}
		}
		return out, nil
	case "github-meta":
		// api.github.com/meta mixes CIDR arrays ("git", "web", "hooks", …)
		// with objects and bools, so decode per-key and keep only the
		// string arrays.
		var feed map[string]json.RawMessage
		if err := json.Unmarshal(raw, &feed); err != nil {
			return nil, err
		}
		keys := make([]string, 0, len(feed))
		for k := range feed {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := []string{}
		for _, k := range keys {
			var arr []string
			if json.Unmarshal(feed[k], &arr) != nil {
				continue
			}
			for _, v := range arr {
				if n, ok := normalizeNet(v); ok {
					out = append(out, n)
				}
			}
		}
		return out, nil
	case "fastly":
		var feed struct {
			Addresses []string `json:"addresses"`
			IPv6      []string `json:"ipv6"`
		}
		if err := json.Unmarshal(raw, &feed); err != nil {
			return nil, err
		}
		out := []string{}
		for _, v := range append(append([]string{}, feed.Addresses...), feed.IPv6...) {
			if n, ok := normalizeNet(v); ok {
				out = append(out, n)
			}
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unknown feed format %q (supported: goog, text, aws, csv, ms365, github-meta, fastly)", format)
	}
}

// normalizeNet accepts a CIDR or a bare IP (→ /32, //128) and reports whether
// it is a usable network.
func normalizeNet(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", false
	}
	if strings.Contains(v, "/") {
		if _, _, err := net.ParseCIDR(v); err == nil {
			return v, true
		}
		return "", false
	}
	ip := net.ParseIP(v)
	if ip == nil {
		return "", false
	}
	if ip.To4() != nil {
		return v + "/32", true
	}
	return v + "/128", true
}

func looksLikeNetwork(v string) bool {
	_, ok := normalizeNet(v)
	return ok
}

// parseCSV reads the network column of a CSV feed. Comment rows whose first
// cell starts with '#' are skipped. The column is resolved from column
// (header name, or 1-based index); without it, a header row is auto-detected
// and a column named network/cidr/prefix/ip/range/… preferred, else column 1.
func parseCSV(raw []byte, column string) ([]string, error) {
	raw = bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf"))
	rd := csv.NewReader(bytes.NewReader(raw))
	rd.FieldsPerRecord = -1
	records, err := rd.ReadAll()
	if err != nil {
		return nil, err
	}
	rows := make([][]string, 0, len(records))
	for _, rec := range records {
		if len(rec) > 0 && strings.HasPrefix(strings.TrimSpace(rec[0]), "#") {
			continue
		}
		rows = append(rows, rec)
	}
	if len(rows) == 0 {
		return nil, nil
	}

	col, start := 0, 0
	header := rows[0]
	headerish := true
	for _, cell := range header {
		if looksLikeNetwork(cell) {
			headerish = false
			break
		}
	}
	if spec := strings.TrimSpace(column); spec != "" {
		if n, err := strconv.Atoi(spec); err == nil && n >= 1 {
			if n > len(header) {
				return nil, fmt.Errorf("csv: column %d out of range (%d columns)", n, len(header))
			}
			col = n - 1
		} else {
			found := false
			for i, h := range header {
				if strings.EqualFold(strings.TrimSpace(h), spec) {
					col, found = i, true
					break
				}
			}
			if !found {
				return nil, fmt.Errorf("csv: column %q not found in header %v", spec, header)
			}
			start = 1
		}
	} else if headerish {
		start = 1
		for i, h := range header {
			switch strings.ToLower(strings.TrimSpace(h)) {
			case "network", "cidr", "prefix", "ip", "range", "ip_range", "iprange", "net", "ip_prefix":
				col = i
			}
		}
		if col >= len(header) {
			col = 0
		}
	}

	out := []string{}
	for _, row := range rows[start:] {
		if col >= len(row) {
			continue
		}
		if n, ok := normalizeNet(row[col]); ok {
			out = append(out, n)
		}
	}
	return out, nil
}

// ------------------------------------------------------- cache persistence --
// JSON cache persistence (stdlib only) — mirrors wHawk's store.go style.

// writeFileAtomic writes dir/name via a .tmp + rename so readers never see a
// torn file.
func writeFileAtomic(dir, name string, raw []byte) {
	_ = os.MkdirAll(dir, 0o755)
	tmp := filepath.Join(dir, name+".tmp")
	if os.WriteFile(tmp, raw, 0o644) == nil {
		_ = os.Rename(tmp, filepath.Join(dir, name))
	}
}

// loadCache reads data/cache.json; true when a usable cache existed.
func (it *IntelFeed) loadCache() bool {
	raw, err := os.ReadFile(filepath.Join(it.dataDir, "cache.json"))
	if err != nil {
		return false
	}
	var c Cache
	if json.Unmarshal(raw, &c) != nil || len(c.Providers) == 0 {
		return false
	}
	it.mu.Lock()
	it.cache = c
	it.mu.Unlock()
	return true
}

func (it *IntelFeed) saveCache() {
	it.mu.Lock()
	c := it.cache
	it.mu.Unlock()
	raw, err := json.MarshalIndent(c, "", " ")
	if err != nil {
		return
	}
	writeFileAtomic(it.dataDir, "cache.json", raw)
}

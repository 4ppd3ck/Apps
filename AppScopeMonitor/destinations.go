// Destination summary views for the dashboard's "Connections by country"
// and "Sites & apps" tables. All three views (per-IP, per-site, per-app)
// aggregate the same detail cube: connection-history lifecycles (no byte
// counts) joined with the persisted byte totals — per-socket (TCP, macOS
// nettop) for IPs/sites and per-process (TCP+UDP) for apps, which is the
// only source that captures QUIC/UDP traffic.
package monitor

import (
	"net"
	"sort"
	"strings"
)

// IPCountryRow is one remote IP's rollup: which apps used it, how many
// connection lifecycles, total connected time, and accumulated bytes.
// Unresolved geo leaves CC empty (the row shows as pending). It doubles as
// the per-IP detail row inside site groups.
type IPCountryRow struct {
	CC          string   `json:"cc,omitempty"`
	Country     string   `json:"country,omitempty"`
	IP          string   `json:"ip"`
	Reverse     string   `json:"reverse,omitempty"` // rDNS or geo hostname (display name)
	Org         string   `json:"org,omitempty"`     // owning org/ISP
	Apps        []string `json:"apps"`
	Connections int64    `json:"connections"`
	Open        int64    `json:"open"`
	Seconds     float64  `json:"seconds"`
	BytesIn     int64    `json:"bytes_in,omitempty"`
	BytesOut    int64    `json:"bytes_out,omitempty"`
	LastSeen    float64  `json:"last_seen"`
}

// SiteGroup groups every app's traffic to one registrable domain (YouTube's
// video servers all live under 1e100.net / googlevideo.com, so grouping by
// full hostname would scatter one site over dozens of rows). Label carries
// a friendly name for well-known domains.
type SiteGroup struct {
	Host        string         `json:"host"`
	Label       string         `json:"label,omitempty"`
	Apps        []string       `json:"apps"`
	IPs         int            `json:"ips"`
	Connections int64          `json:"connections"`
	Open        int64          `json:"open"`
	Seconds     float64        `json:"seconds"`
	BytesIn     int64          `json:"bytes_in,omitempty"`
	BytesOut    int64          `json:"bytes_out,omitempty"`
	LastSeen    float64        `json:"last_seen"`
	IPRows      []IPCountryRow `json:"ip_rows,omitempty"`
}

// AppSiteRow is one site (domain) inside an app's expanded view. Bytes are
// socket-attributed (TCP); the app-level row totals include UDP.
type AppSiteRow struct {
	Host        string  `json:"host"`
	Label       string  `json:"label,omitempty"`
	IPs         int     `json:"ips"`
	Connections int64   `json:"connections"`
	Open        int64   `json:"open"`
	Seconds     float64 `json:"seconds"`
	BytesIn     int64   `json:"bytes_in,omitempty"`
	BytesOut    int64   `json:"bytes_out,omitempty"`
	LastSeen    float64 `json:"last_seen"`
}

// AppGroup is one app's rollup. Bytes prefer the per-process totals
// (TCP+UDP); per-socket bytes only cover TCP and sockets that were seen
// live, so the site subrows can sum to less than the app total.
type AppGroup struct {
	App         string       `json:"app"`
	Connections int64        `json:"connections"`
	Open        int64        `json:"open"`
	Seconds     float64      `json:"seconds"`
	BytesIn     int64        `json:"bytes_in,omitempty"`
	BytesOut    int64        `json:"bytes_out,omitempty"`
	LastSeen    float64      `json:"last_seen"`
	Sites       []AppSiteRow `json:"sites,omitempty"`
}

// siteLabels maps well-known domains to friendly names — rdns of content
// servers is opaque (YouTube video lives on *.1e100.net), and the point of
// the sites table is recognising who you are talking to.
var siteLabels = map[string]string{
	"1e100.net":              "Google / YouTube",
	"googlevideo.com":        "YouTube video",
	"youtube.com":            "YouTube",
	"ytimg.com":              "YouTube images",
	"ggpht.com":              "Google / YouTube images",
	"googleusercontent.com":  "Google",
	"google.com":             "Google",
	"gstatic.com":            "Google",
	"googleapis.com":         "Google APIs",
	"googletagservices.com":  "Google Ads",
	"doubleclick.net":        "Google Ads",
	"apple.com":              "Apple",
	"icloud.com":             "Apple iCloud",
	"cdn-apple.com":          "Apple",
	"mzstatic.com":           "Apple",
	"akamaitechnologies.com": "Akamai CDN",
	"akamaihd.net":           "Akamai CDN",
	"cloudfront.net":         "Amazon CloudFront",
	"amazonaws.com":          "Amazon AWS",
	"fastly.net":             "Fastly CDN",
	"cloudflare.com":         "Cloudflare",
	"github.com":             "GitHub",
	"githubusercontent.com":  "GitHub",
	"facebook.com":           "Facebook",
	"instagram.com":          "Instagram",
	"cdninstagram.com":       "Instagram",
	"tiktokv.com":            "TikTok",
	"tiktokcdn.com":          "TikTok",
	"netflix.com":            "Netflix",
	"nflxvideo.net":          "Netflix video",
	"twimg.com":              "X (Twitter)",
	"x.com":                  "X (Twitter)",
	"openai.com":             "OpenAI",
	"anthropic.com":          "Anthropic",
	"cloudflare-dns.com":     "Cloudflare DNS",
	"quad9.net":              "Quad9 DNS",
	"opendns.com":            "OpenDNS",
}

// twoPartSuffixes are country-code second-level zones where the registrable
// domain needs three labels (example.co.uk).
var twoPartSuffixes = map[string]bool{
	"co.uk": true, "org.uk": true, "ac.uk": true, "gov.uk": true,
	"co.jp": true, "co.in": true, "co.kr": true, "co.nz": true,
	"co.za": true, "co.id": true, "com.au": true, "net.au": true,
	"org.au": true, "com.br": true, "com.mx": true, "com.tr": true,
	"com.sg": true, "com.hk": true, "com.tw": true, "com.ar": true,
}

// domainOf reduces a hostname to its registrable domain ("pnmaaa-bc-in-f1.1e100.net"
// -> "1e100.net"); IP-literal hosts are their own domain.
func domainOf(host string) string {
	if net.ParseIP(strings.Trim(host, "[]")) != nil {
		return host
	}
	labels := strings.Split(strings.TrimSuffix(host, "."), ".")
	if len(labels) >= 3 &&
		twoPartSuffixes[strings.Join(labels[len(labels)-2:], ".")] {
		return strings.Join(labels[len(labels)-3:], ".")
	}
	if len(labels) >= 2 {
		return strings.Join(labels[len(labels)-2:], ".")
	}
	return host
}

// siteLabelOf returns the friendly name for a domain (suffix-aware, longest
// match wins via the two-label key space).
func siteLabelOf(domain string) string {
	if label, ok := siteLabels[domain]; ok {
		return label
	}
	for suffix, label := range siteLabels {
		if strings.HasSuffix(domain, "."+suffix) {
			return label
		}
	}
	return ""
}

// destinationSummary builds all three views for /api/destinations. Geo and
// rdns lookups are cache-only; misses schedule async resolution for later.
func destinationSummary(ctx *Ctx, since float64) ([]IPCountryRow, []SiteGroup, []AppGroup, error) {
	spans, err := ctx.Store.DestinationSpans(since)
	if err != nil {
		return nil, nil, nil, err
	}
	traffic, err := ctx.Store.DestinationBytes(since)
	if err != nil {
		return nil, nil, nil, err
	}
	appTraffic, err := ctx.Store.AppTraffic(since)
	if err != nil {
		return nil, nil, nil, err
	}

	// socket-attributed bytes + last-seen per "app\x00ip"; entries the spans
	// don't cover have no history row anymore (history aged out sooner)
	type destKey struct{ app, ip string }
	bytesOf := map[destKey][2]int64{}
	seenAt := map[destKey]float64{}
	for _, t := range traffic {
		key := destKey{t.App, t.RemoteIP}
		b := bytesOf[key]
		b[0] += t.BytesIn
		b[1] += t.BytesOut
		bytesOf[key] = b
		if t.LastSeen > seenAt[key] {
			seenAt[key] = t.LastSeen
		}
	}
	// per-app process totals (TCP+UDP) — the app rows' byte source
	appBytes := map[destKey][2]int64{}
	for _, t := range appTraffic {
		b := appBytes[destKey{t.App, ""}]
		b[0] += t.BytesIn
		b[1] += t.BytesOut
		appBytes[destKey{t.App, ""}] = b
		if t.LastSeen > seenAt[destKey{t.App, ""}] {
			seenAt[destKey{t.App, ""}] = t.LastSeen
		}
	}

	// nameOf resolves an IP to the best display name: rDNS hostname first
	// (cached, non-blocking), then the geo service's reverse hostname, then
	// the owning org — the fallback chain that replaces bare IPs in the UI.
	nameOf := func(ip string) (cc, country, host, org string) {
		host = ip
		if ctx.Geo != nil {
			if entry, ok := ctx.Geo.Get(ip); ok {
				cc, country, org = entry.CC, entry.Country, entry.Org
				if entry.Reverse != "" {
					host = strings.TrimSuffix(entry.Reverse, ".")
				}
			}
		}
		if host == ip {
			if r := rdns.Get(ip); r != "" {
				host = r
			}
		}
		return cc, country, host, org
	}
	// detail cell per (app, ip)
	type cell struct {
		app, ip, host, domain, label, cc, country, org string
		connections, open                              int64
		seconds                                        float64
		bytesIn, bytesOut                              int64
		lastSeen                                       float64
	}
	cells := map[destKey]*cell{}
	ensureCell := func(app, ip string) *cell {
		key := destKey{app, ip}
		c, ok := cells[key]
		if !ok {
			c = &cell{app: app, ip: ip}
			c.cc, c.country, c.host, c.org = nameOf(ip)
			if c.host == "" {
				c.host = ip
			}
			c.domain = domainOf(c.host)
			c.label = siteLabelOf(c.domain)
			cells[key] = c
		}
		return c
	}

	for _, span := range spans {
		app := span.App
		if app == "" {
			app = "Unknown"
		}
		ip, _, err := splitEndpoint(span.Remote)
		if err != nil || ip == "" {
			continue
		}
		c := ensureCell(app, ip)
		c.connections += span.Connections
		c.open += span.Open
		c.seconds += span.Seconds
		if span.LastSeen > c.lastSeen {
			c.lastSeen = span.LastSeen
		}
	}
	// span-less byte destinations: connections are gone, bytes still count
	covered := map[destKey]bool{}
	for _, span := range spans {
		app := span.App
		if app == "" {
			app = "Unknown"
		}
		if ip, _, err := splitEndpoint(span.Remote); err == nil && ip != "" {
			covered[destKey{app, ip}] = true
		}
	}
	for key := range bytesOf {
		if covered[key] || key.ip == "" {
			continue
		}
		ensureCell(key.app, key.ip)
	}
	// join the persisted socket bytes onto every cell
	for key, c := range cells {
		if b, ok := bytesOf[key]; ok {
			c.bytesIn = b[0]
			c.bytesOut = b[1]
			if seenAt[key] > c.lastSeen {
				c.lastSeen = seenAt[key]
			}
		}
	}

	// per-IP view (also the site detail rows)
	type ipAgg struct {
		row     IPCountryRow
		domain  string
		label   string
		appSeen map[string]bool
	}
	ipAggs := map[string]*ipAgg{}
	for _, c := range cells {
		agg, ok := ipAggs[c.ip]
		if !ok {
			// Reverse carries a real name only — the bare IP is already
			// the row's IP field, and a fake "reverse == IP" would lie
			// about the name being resolved
			reverse := c.host
			if reverse == c.ip {
				reverse = ""
			}
			agg = &ipAgg{appSeen: map[string]bool{},
				row: IPCountryRow{IP: c.ip, CC: c.cc, Country: c.country,
					Reverse: reverse, Org: c.org},
				domain: c.domain, label: c.label}
			ipAggs[c.ip] = agg
		}
		if !agg.appSeen[c.app] {
			agg.appSeen[c.app] = true
			agg.row.Apps = append(agg.row.Apps, c.app)
		}
		agg.row.Connections += c.connections
		agg.row.Open += c.open
		agg.row.Seconds += c.seconds
		agg.row.BytesIn += c.bytesIn
		agg.row.BytesOut += c.bytesOut
		if c.lastSeen > agg.row.LastSeen {
			agg.row.LastSeen = c.lastSeen
		}
	}
	ipRows := make([]IPCountryRow, 0, len(ipAggs))
	ipDomain := map[string][2]string{} // ip -> [domain, label]
	for ip, agg := range ipAggs {
		ipRows = append(ipRows, agg.row)
		ipDomain[ip] = [2]string{agg.domain, agg.label}
	}

	// per-site view: cells grouped by registrable domain
	siteGroups := map[string]*SiteGroup{}
	siteIPSeen := map[string]map[string]bool{}
	for _, c := range cells {
		g, ok := siteGroups[c.domain]
		if !ok {
			g = &SiteGroup{Host: c.domain, Label: c.label}
			siteGroups[c.domain] = g
			siteIPSeen[c.domain] = map[string]bool{}
		}
		if !containsString(g.Apps, c.app) {
			g.Apps = append(g.Apps, c.app)
		}
		if !siteIPSeen[c.domain][c.ip] {
			siteIPSeen[c.domain][c.ip] = true
			g.IPs++
		}
		g.Connections += c.connections
		g.Open += c.open
		g.Seconds += c.seconds
		g.BytesIn += c.bytesIn
		g.BytesOut += c.bytesOut
		if c.lastSeen > g.LastSeen {
			g.LastSeen = c.lastSeen
		}
	}
	for _, row := range ipRows {
		d := ipDomain[row.IP]
		if g, ok := siteGroups[d[0]]; ok {
			g.IPRows = append(g.IPRows, row)
		}
	}
	sites := make([]SiteGroup, 0, len(siteGroups))
	for _, g := range siteGroups {
		sort.Slice(g.IPRows, func(i, j int) bool {
			return ipRowLess(g.IPRows[i], g.IPRows[j])
		})
		sites = append(sites, *g)
	}

	// per-app view: cells grouped by app, with process-level byte totals
	appGroups := map[string]*AppGroup{}
	appSiteSeen := map[string]map[string]int{} // app -> domain -> index
	for _, c := range cells {
		g, ok := appGroups[c.app]
		if !ok {
			g = &AppGroup{App: c.app}
			appGroups[c.app] = g
			appSiteSeen[c.app] = map[string]int{}
		}
		idx, ok := appSiteSeen[c.app][c.domain]
		if !ok {
			g.Sites = append(g.Sites, AppSiteRow{
				Host: c.domain, Label: c.label})
			idx = len(g.Sites) - 1
			appSiteSeen[c.app][c.domain] = idx
		}
		sub := &g.Sites[idx]
		sub.IPs++
		sub.Connections += c.connections
		sub.Open += c.open
		sub.Seconds += c.seconds
		sub.BytesIn += c.bytesIn
		sub.BytesOut += c.bytesOut
		if c.lastSeen > sub.LastSeen {
			sub.LastSeen = c.lastSeen
		}
		g.Connections += c.connections
		g.Open += c.open
		g.Seconds += c.seconds
		g.BytesIn += c.bytesIn
		g.BytesOut += c.bytesOut
		if c.lastSeen > g.LastSeen {
			g.LastSeen = c.lastSeen
		}
	}
	apps := make([]AppGroup, 0, len(appGroups))
	for _, g := range appGroups {
		// process totals (TCP+UDP) are the truthful app-level bytes
		if total, ok := appBytes[destKey{g.App, ""}]; ok {
			g.BytesIn = total[0]
			g.BytesOut = total[1]
			if seenAt[destKey{g.App, ""}] > g.LastSeen {
				g.LastSeen = seenAt[destKey{g.App, ""}]
			}
		}
		sort.Slice(g.Sites, func(i, j int) bool {
			return appSiteLess(g.Sites[i], g.Sites[j])
		})
		apps = append(apps, *g)
	}

	sort.Slice(ipRows, func(i, j int) bool {
		if (ipRows[i].CC == "") != (ipRows[j].CC == "") {
			return ipRows[j].CC == ""
		}
		if c := strings.Compare(
			strings.ToLower(countryLabel(ipRows[i])), strings.ToLower(countryLabel(ipRows[j]))); c != 0 {
			return c < 0
		}
		return ipRowLess(ipRows[i], ipRows[j])
	})
	sort.Slice(sites, func(i, j int) bool { return siteLess(sites[i], sites[j]) })
	sort.Slice(apps, func(i, j int) bool { return appLess(apps[i], apps[j]) })
	return ipRows, sites, apps, nil
}

func containsString(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

func bytesTotal(in, out int64) int64 { return in + out }

func ipRowLess(a, b IPCountryRow) bool {
	if bytesTotal(a.BytesIn, a.BytesOut) != bytesTotal(b.BytesIn, b.BytesOut) {
		return bytesTotal(a.BytesIn, a.BytesOut) > bytesTotal(b.BytesIn, b.BytesOut)
	}
	if a.Seconds != b.Seconds {
		return a.Seconds > b.Seconds
	}
	return a.LastSeen > b.LastSeen
}

func siteLess(a, b SiteGroup) bool {
	if bytesTotal(a.BytesIn, a.BytesOut) != bytesTotal(b.BytesIn, b.BytesOut) {
		return bytesTotal(a.BytesIn, a.BytesOut) > bytesTotal(b.BytesIn, b.BytesOut)
	}
	if a.Seconds != b.Seconds {
		return a.Seconds > b.Seconds
	}
	return a.LastSeen > b.LastSeen
}

func appSiteLess(a, b AppSiteRow) bool {
	if bytesTotal(a.BytesIn, a.BytesOut) != bytesTotal(b.BytesIn, b.BytesOut) {
		return bytesTotal(a.BytesIn, a.BytesOut) > bytesTotal(b.BytesIn, b.BytesOut)
	}
	return a.LastSeen > b.LastSeen
}

func appLess(a, b AppGroup) bool {
	if bytesTotal(a.BytesIn, a.BytesOut) != bytesTotal(b.BytesIn, b.BytesOut) {
		return bytesTotal(a.BytesIn, a.BytesOut) > bytesTotal(b.BytesIn, b.BytesOut)
	}
	if a.Seconds != b.Seconds {
		return a.Seconds > b.Seconds
	}
	return a.LastSeen > b.LastSeen
}

func countryLabel(row IPCountryRow) string {
	if row.Country != "" {
		return row.Country
	}
	return row.CC
}

// splitEndpoint splits "ip:port" (the connection-history remote format).
// net.SplitHostPort rejects unbracketed IPv6, so fall back to the last colon.
func splitEndpoint(endpoint string) (host, port string, err error) {
	if host, port, err = net.SplitHostPort(endpoint); err == nil {
		return host, port, nil
	}
	if idx := strings.LastIndex(endpoint, ":"); idx >= 0 {
		return endpoint[:idx], endpoint[idx+1:], nil
	}
	return endpoint, "", nil
}

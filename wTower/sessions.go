// Site-visit sessions: reconstruction of *visits* out of connection
// lifecycles. One page load opens many short sockets to several IPs, so a
// visit is merged back together: lifecycles whose IP resolves to the same
// domain, from the same app, that overlap or sit within a small idle gap
// are one session. A session closes when the NETWORK closes — the last
// socket of the cluster ended (the dashboard cannot see browser tabs, and
// an open socket keeps the visit honestly marked "still open").
//
// Bytes per visit come from the per-lifecycle counters connection_history
// has accumulated since the socket opened, so a visit's in/out sums are
// exact for that visit (the shared per-destination totals cannot be split
// across visits). Platforms without per-socket counters show connection
// counts only — the Sites & apps panel remains the totals source of truth.
package wtower

import (
	"net"
	"sort"
	"strings"
)

// VisitSession is one reconstructed visit: a (domain, app) cluster of
// connection lifecycles with its network-visible span, active transfer
// time and byte totals.
type VisitSession struct {
	Domain  string `json:"domain"`
	Label   string `json:"label,omitempty"`
	App     string `json:"app"`
	CC      string `json:"cc,omitempty"`
	Country string `json:"country,omitempty"`

	Started float64  `json:"started"`
	Last    float64  `json:"last"`            // most recent network activity
	Ended   *float64 `json:"ended,omitempty"` // network close; nil = still open
	Open    bool     `json:"open"`

	Span        float64 `json:"span"`   // wall clock: started -> closed/now
	Active      float64 `json:"active"` // summed connection lifetimes
	BytesIn     int64   `json:"bytes_in"`
	BytesOut    int64   `json:"bytes_out"`
	Connections int64   `json:"connections"`

	IPs []string `json:"ips,omitempty"`

	ips map[string]bool
}

// destNameOf resolves an IP to the best display identity (cc, country,
// host, org). The DNS shield's own answer map leads when the opt-in query
// log is on — the name the machine actually asked for beats any reverse
// lookup — then the geo cache's rDNS, then plain rDNS.
func destNameOf(ctx *Ctx, ip string) (cc, country, host, org string) {
	host = ip
	if ctx != nil && ctx.DNSShield != nil {
		if dom, ok := ctx.DNSShield.AnswerDomain(ip); ok && dom != "" {
			host = dom
		}
	}
	if ctx != nil && ctx.Geo != nil {
		if entry, ok := ctx.Geo.Get(ip); ok {
			cc, country, org = entry.CC, entry.Country, entry.Org
			if host == ip && entry.Reverse != "" {
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

// BuildVisits aggregates external connection lifecycles into visit
// sessions (see the package comment for the merge and close rules).
// gapSeconds is the idle tolerance: sockets from the same app to the same
// domain closer together than this belong to one visit.
func BuildVisits(ctx *Ctx, since, gapSeconds float64) ([]VisitSession, error) {
	if gapSeconds < 0 {
		gapSeconds = 300
	}
	rows, err := ctx.Store.SiteLifecycles(since)
	if err != nil {
		return nil, err
	}
	type groupKey struct{ domain, app string }
	type group struct {
		sessions []*VisitSession
		// org carries the geo org of the first naming row — the label
		// fallback for IP-literal domains (no reverse-DNS record published)
		org string
	}
	groups := map[groupKey]*group{}
	for _, row := range rows {
		app := row.App
		if app == "" {
			app = "Unknown"
		}
		cc, country, host, org := destNameOf(ctx, row.RemoteIP)
		domain := domainOf(host)
		key := groupKey{domain, app}
		g := groups[key]
		if g == nil {
			g = &group{org: org}
			groups[key] = g
		}
		end := row.Last
		if row.Ended != nil && *row.Ended > end {
			end = *row.Ended
		}
		duration := end - row.Started
		if duration < 0 {
			duration = 0
		}
		// merge into the group's newest session while the network gap is
		// small (rows arrive oldest-first, so "newest" is the last one)
		if n := len(g.sessions); n > 0 {
			last := g.sessions[n-1]
			if row.Started <= last.Last+gapSeconds {
				if row.Started < last.Started {
					last.Started = row.Started
				}
				if row.Last > last.Last {
					last.Last = row.Last
				}
				if row.Ended == nil {
					// an open socket keeps the whole visit open — network
					// closed is the only close condition
					last.Open = true
					last.Ended = nil
				} else if !last.Open && (last.Ended == nil || *row.Ended > *last.Ended) {
					e := *row.Ended
					last.Ended = &e
				}
				last.Active += duration
				last.BytesIn += row.BytesIn
				last.BytesOut += row.BytesOut
				last.Connections++
				last.ips[row.RemoteIP] = true
				continue
			}
		}
		sess := &VisitSession{
			Domain: domain, App: app, CC: cc, Country: country,
			Started: row.Started, Last: row.Last,
			Active: duration, BytesIn: row.BytesIn, BytesOut: row.BytesOut,
			Connections: 1,
			ips:         map[string]bool{row.RemoteIP: true},
		}
		if row.Ended == nil {
			sess.Open = true
		} else {
			e := *row.Ended
			sess.Ended = &e
		}
		g.sessions = append(g.sessions, sess)
	}
	out := make([]VisitSession, 0, len(groups)*2)
	for _, g := range groups {
		for _, s := range g.sessions {
			s.Span = s.Last - s.Started
			if s.Span < 0 {
				s.Span = 0
			}
			s.Label = siteLabelOf(s.Domain)
			// IP-literal domains (no reverse-DNS published): the geo org is
			// the honest label the internet does offer
			if net.ParseIP(s.Domain) != nil && g.org != "" {
				s.Label = g.org
			}
			for ip := range s.ips {
				s.IPs = append(s.IPs, ip)
			}
			sort.Strings(s.IPs)
			if len(s.IPs) > 8 {
				s.IPs = s.IPs[:8]
			}
			out = append(out, *s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Started > out[j].Started })
	if len(out) > 400 {
		out = out[:400]
	}
	return out, nil
}

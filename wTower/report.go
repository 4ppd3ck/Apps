// Report aggregation: where did time and data go over a window? The report
// view combines three sources the monitor already records —
//
//   - screen time: app_switch events (appfocus collector) diffed into
//     per-app foreground seconds, with long same-app stretches capped and
//     the remainder reported as idle (the monitor has no sleep/wake signal)
//   - site time: connection lifecycles (connection_history) grouped per
//     registrable domain — network presence, not reading time
//   - data usage: the usage_daily rollup fed by the traffic flush
//
// Design benchmark: GlassWire's Usage tab (multi-lens table, period presets,
// host->apps drill-down, explicit idle, CSV export).
package wtower

import (
	"fmt"
	"math"
	"net/url"
	"sort"
	"strconv"
	"time"
)

// usageSegmentCap bounds one app_switch segment: without a sleep/wake
// signal, an app left open overnight would otherwise claim the whole night.
// Seconds beyond the cap land in the idle/unattributed bucket.
const usageSegmentCap = 3600.0

// WireReportRollup attaches the report's IP -> registrable-domain namer to
// the network state so the daily usage flush can bucket bytes by domain.
// Call once after Geo is set; the closure resolves lazily, so a DNSShield
// attached later is picked up automatically. All lookups inside are
// cache-only (destNameOf never blocks — misses fall back to the IP literal).
func WireReportRollup(ctx *Ctx) {
	if ctx == nil || ctx.Net == nil {
		return
	}
	ctx.Net.SetUsageNamer(func(ip string) string {
		_, _, host, _ := destNameOf(ctx, ip)
		return domainOf(host)
	})
}

// AppUsageRow is one app's foreground ("screen") time over the report
// window.
type AppUsageRow struct {
	App      string  `json:"app"`
	Seconds  float64 `json:"seconds"`
	Sessions int64   `json:"sessions"`
}

// AppScreenTime is the screen-time view: per-app foreground seconds plus the
// unattributed remainder, and the window the events actually cover (empty
// when the appfocus collector was off).
type AppScreenTime struct {
	Apps        []AppUsageRow `json:"apps"`
	IdleSeconds float64       `json:"idle_seconds"`
	FirstEvent  float64       `json:"first_event,omitempty"`
	LastEvent   float64       `json:"last_event,omitempty"`
}

// BuildAppScreenTime diffs consecutive app_switch events into per-app
// foreground seconds. A switch ends the previous app's segment; a segment
// longer than usageSegmentCap stops earning time at the cap and the excess
// lands in IdleSeconds. Segments are tracked per device (the android
// collector emits the same kind) so several machines never bleed into each
// other. The pre-window seed rows carry whatever held the foreground when
// the window opened.
func BuildAppScreenTime(store *Store, since, until float64) (*AppScreenTime, error) {
	seeds, rows, err := store.AppSwitchSpans(since, until)
	if err != nil {
		return nil, err
	}
	out := &AppScreenTime{}
	type seg struct {
		app   string
		start float64
	}
	open := map[string]seg{} // device -> currently-open segment
	byApp := map[string]*AppUsageRow{}
	earn := func(dev string, end float64) {
		s, ok := open[dev]
		if !ok || s.app == "" {
			return
		}
		span := end - s.start
		if span <= 0 {
			return
		}
		if span > usageSegmentCap {
			out.IdleSeconds += span - usageSegmentCap
			span = usageSegmentCap
		}
		row := byApp[s.app]
		if row == nil {
			row = &AppUsageRow{App: s.app}
			byApp[s.app] = row
		}
		row.Seconds += span
		row.Sessions++
	}
	for _, seed := range seeds {
		if seed.App == "" {
			continue
		}
		open[seed.Device] = seg{app: seed.App, start: since}
	}
	for _, sw := range rows {
		dev := sw.Device
		if cur, ok := open[dev]; ok && cur.app != sw.App {
			earn(dev, sw.Ts)
		}
		if cur, ok := open[dev]; !ok || cur.app != sw.App {
			open[dev] = seg{app: sw.App, start: sw.Ts}
		}
		if out.FirstEvent == 0 || sw.Ts < out.FirstEvent {
			out.FirstEvent = sw.Ts
		}
		if sw.Ts > out.LastEvent {
			out.LastEvent = sw.Ts
		}
	}
	for dev := range open {
		earn(dev, until)
	}
	for _, row := range byApp {
		out.Apps = append(out.Apps, *row)
	}
	sort.Slice(out.Apps, func(i, j int) bool {
		return out.Apps[i].Seconds > out.Apps[j].Seconds
	})
	return out, nil
}

// AppSpanRow is one app's share of a domain's network time (the report's
// host -> apps drill-down).
type AppSpanRow struct {
	App         string  `json:"app"`
	Connections int64   `json:"connections"`
	Seconds     float64 `json:"seconds"`
}

// SiteTimeRow is one registrable domain's network time over the window —
// summed connection lifetimes (presence, not reading time) with the apps
// that talked to it. Bytes are socket-attributed (TCP), mirroring the sites
// view.
type SiteTimeRow struct {
	Domain      string       `json:"domain"`
	Label       string       `json:"label,omitempty"`
	CC          string       `json:"cc,omitempty"`
	Connections int64        `json:"connections"`
	Seconds     float64      `json:"seconds"`
	BytesIn     int64        `json:"bytes_in"`
	BytesOut    int64        `json:"bytes_out"`
	TopApps     []AppSpanRow `json:"top_apps,omitempty"`
}

// BuildSiteTime groups external connection lifecycles per registrable domain
// (same naming chain as the destinations view: DNS-shield answers, geo
// reverse, rDNS — all cache-only) and ranks the apps behind each domain.
func BuildSiteTime(ctx *Ctx, since float64) ([]SiteTimeRow, error) {
	spans, err := ctx.Store.DestinationSpans(since)
	if err != nil {
		return nil, err
	}
	type siteAgg struct {
		row   SiteTimeRow
		apps  map[string]*AppSpanRow
		first bool
	}
	sites := map[string]*siteAgg{}
	for _, span := range spans {
		ip, _, err := splitEndpoint(span.Remote)
		if err != nil || ip == "" {
			continue
		}
		app := span.App
		if app == "" {
			app = "Unknown"
		}
		cc, _, host, org := destNameOf(ctx, ip)
		domain := domainOf(host)
		agg, ok := sites[domain]
		if !ok {
			agg = &siteAgg{apps: map[string]*AppSpanRow{}, first: true}
			agg.row = SiteTimeRow{Domain: domain, Label: siteLabelOf(domain), CC: cc}
			// IPs with no reverse-DNS record (most CDN/cloud nodes) would
			// show as a bare address — the geo org ("Alibaba.com LLC",
			// "Fastly, Inc.") is the honest name the internet does publish.
			if domain == ip && org != "" && agg.row.Label == "" {
				agg.row.Label = org
			}
			sites[domain] = agg
		}
		if agg.row.CC == "" {
			agg.row.CC = cc
		}
		agg.row.Connections += span.Connections
		agg.row.Seconds += span.Seconds
		ar := agg.apps[app]
		if ar == nil {
			ar = &AppSpanRow{App: app}
			agg.apps[app] = ar
		}
		ar.Connections += span.Connections
		ar.Seconds += span.Seconds
	}
	// socket-attributed bytes ride the same naming (destinations view's
	// per-domain totals; the rollup only buckets future days)
	traffic, err := ctx.Store.DestinationBytes(since)
	if err != nil {
		return nil, err
	}
	for _, t := range traffic {
		if t.RemoteIP == "" {
			continue
		}
		cc, _, host, org := destNameOf(ctx, t.RemoteIP)
		domain := domainOf(host)
		agg, ok := sites[domain]
		if !ok {
			agg = &siteAgg{apps: map[string]*AppSpanRow{}, first: true}
			agg.row = SiteTimeRow{Domain: domain, Label: siteLabelOf(domain), CC: cc}
			if domain == t.RemoteIP && org != "" && agg.row.Label == "" {
				agg.row.Label = org
			}
			sites[domain] = agg
		}
		agg.row.BytesIn += t.BytesIn
		agg.row.BytesOut += t.BytesOut
	}
	out := make([]SiteTimeRow, 0, len(sites))
	for _, agg := range sites {
		for _, ar := range agg.apps {
			agg.row.TopApps = append(agg.row.TopApps, *ar)
		}
		sort.Slice(agg.row.TopApps, func(i, j int) bool {
			return agg.row.TopApps[i].Seconds > agg.row.TopApps[j].Seconds
		})
		out = append(out, agg.row)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Seconds != out[j].Seconds {
			return out[i].Seconds > out[j].Seconds
		}
		return bytesTotal(out[i].BytesIn, out[i].BytesOut) >
			bytesTotal(out[j].BytesIn, out[j].BytesOut)
	})
	return out, nil
}

// Report is the /api/report payload: everything the Report view renders for
// one window.
type Report struct {
	Days        int               `json:"days"`
	Hours       int               `json:"hours,omitempty"` // sub-day windows ("last 3 hours")
	Day         string            `json:"day,omitempty"`   // single-local-day windows
	Since       float64           `json:"since"`
	Until       float64           `json:"until"`
	ScreenTime  *AppScreenTime    `json:"screen_time"`
	Sites       []SiteTimeRow     `json:"sites"`
	Countries   []CountryUsageRow `json:"countries"` // data by country (donut)
	UsageByDay  []UsageDailyRow   `json:"usage_by_day"`
	UsageByApp  []UsageDailyRow   `json:"usage_by_app"`
	ProtoSpans  []ProtoSpan       `json:"protos"`
	Sections    map[string]bool   `json:"sections"` // which view sections show
	FirstEvent  float64           `json:"first_event,omitempty"`
	LastEvent   float64           `json:"last_event,omitempty"`
	RollupFirst string            `json:"rollup_first_day,omitempty"`
}

// reportSectionKeys whitelists the toggleable Report view sections.
var reportSectionKeys = map[string]bool{
	"screen": true, "sites": true, "usage": true, "byapp": true, "protos": true,
}

// ReportSections reads the saved section visibility (everything on by
// default; unknown keys ignored).
func ReportSections(cfg *Config) map[string]bool {
	out := map[string]bool{}
	for k := range reportSectionKeys {
		out[k] = true
	}
	if cfg == nil {
		return out
	}
	if m, ok := cfg.Get("report_sections"); ok {
		if mm, ok := m.(map[string]any); ok {
			for k, v := range mm {
				if reportSectionKeys[k] {
					out[k] = Truthy(v)
				}
			}
		}
	}
	return out
}

// SaveReportSections persists the section visibility after whitelisting.
func SaveReportSections(cfg *Config, sections map[string]any) map[string]bool {
	clean := map[string]any{}
	for k, v := range sections {
		if reportSectionKeys[k] {
			clean[k] = Truthy(v)
		}
	}
	cfg.Data["report_sections"] = clean
	_ = cfg.Save()
	return ReportSections(cfg)
}

// reportWindow resolves the /api/report window from query params, in
// precedence order: an explicit since/until custom range, an hours count
// (last 1/3/6/12 h), a specific date, then a day count (default 1). The
// span is capped at 31 days — the usage rollup keeps 35.
func reportWindow(query string) (since, until float64, err error) {
	now := Now()
	qs, err := url.ParseQuery(query)
	if err != nil {
		return 0, 0, err
	}
	if sinceS, untilS := qsValue(qs, "since", ""), qsValue(qs, "until", ""); sinceS != "" && untilS != "" {
		since, err = strconv.ParseFloat(sinceS, 64)
		if err != nil {
			return 0, 0, fmt.Errorf("since %q is not a timestamp", sinceS)
		}
		until, err = strconv.ParseFloat(untilS, 64)
		if err != nil {
			return 0, 0, fmt.Errorf("until %q is not a timestamp", untilS)
		}
	} else if hoursS := qsValue(qs, "hours", ""); hoursS != "" {
		hours, _ := ToInt(hoursS)
		if hours < 1 || hours > 24*31 {
			return 0, 0, fmt.Errorf("hours %s invalid — use 1–744", hoursS)
		}
		since, until = now-float64(hours)*3600, now
	} else if date := qsValue(qs, "date", ""); date != "" {
		t, err := time.ParseInLocation("2006-01-02", date, time.Local)
		if err != nil {
			return 0, 0, fmt.Errorf("date %q is not YYYY-MM-DD", date)
		}
		since, until = DayStart(float64(t.UnixNano()) / 1e9)
	} else {
		days, _ := ToInt(qsValue(qs, "days", "1"))
		if days < 1 {
			days = 1
		}
		if days > 31 {
			days = 31
		}
		since, until = now-float64(days)*86400, now
	}
	if until > now+60 { // clock-skew headroom, no future windows
		until = now + 60
	}
	if since >= until {
		return 0, 0, fmt.Errorf("empty window — since must be before until")
	}
	if until-since > 31*86400 {
		since = until - 31*86400 // the rollup keeps 35 days; honor 31
	}
	return since, until, nil
}

// CountryUsageRow is one country's share of the window's external data
// (the report's countries donut; flags ride the CC).
type CountryUsageRow struct {
	CC       string `json:"cc"`
	BytesIn  int64  `json:"bytes_in"`
	BytesOut int64  `json:"bytes_out"`
}

// BuildReport assembles the whole report for an arbitrary [since, until]
// window. Callers derive the window from the request: a day count (days 1/7/30
// ending now), an hour count (last 1/3/6/12 h), one specific local day (date),
// or an explicit custom range.
func BuildReport(ctx *Ctx, since, until float64) (*Report, error) {
	span := until - since
	days := int(math.Ceil(span / 86400))
	if days < 1 {
		days = 1
	}
	day := ""
	if span >= 86400 && LocalDay(since) == LocalDay(until-1) {
		day = LocalDay(since) // exactly one local day
	}
	siteRows, err := BuildSiteTime(ctx, since)
	if err != nil {
		return nil, err
	}
	screen, err := BuildAppScreenTime(ctx.Store, since, until)
	if err != nil {
		return nil, err
	}
	byDay, err := ctx.Store.UsageDailyTrend(LocalDay(since), LocalDay(until))
	if err != nil {
		return nil, err
	}
	byApp, err := ctx.Store.UsageDailyKeys("app", LocalDay(since), LocalDay(until))
	if err != nil {
		return nil, err
	}
	protos, err := ctx.Store.ProtoSpans(since)
	if err != nil {
		return nil, err
	}
	rep := &Report{
		Days: days, Day: day, Since: since, Until: until,
		ScreenTime: screen, Sites: siteRows,
		UsageByDay: byDay, UsageByApp: byApp, ProtoSpans: protos,
		Sections: ReportSections(ctx.Cfg),
	}
	if span < 36*3600 { // sub-day windows report in hours ("last 3 hours")
		rep.Hours = int(math.Round(span / 3600))
	}
	// the countries lens: external data aggregated by flag
	byCC := map[string]*CountryUsageRow{}
	for _, s := range siteRows {
		cc := s.CC
		if cc == "" {
			cc = "?"
		}
		row := byCC[cc]
		if row == nil {
			row = &CountryUsageRow{CC: cc}
			byCC[cc] = row
		}
		row.BytesIn += s.BytesIn
		row.BytesOut += s.BytesOut
	}
	for _, row := range byCC {
		rep.Countries = append(rep.Countries, *row)
	}
	sort.Slice(rep.Countries, func(i, j int) bool {
		return bytesTotal(rep.Countries[i].BytesIn, rep.Countries[i].BytesOut) >
			bytesTotal(rep.Countries[j].BytesIn, rep.Countries[j].BytesOut)
	})
	// empty windows marshal as [] not null (mirrors the visits handler)
	if rep.Sites == nil {
		rep.Sites = []SiteTimeRow{}
	}
	if rep.UsageByDay == nil {
		rep.UsageByDay = []UsageDailyRow{}
	}
	if rep.UsageByApp == nil {
		rep.UsageByApp = []UsageDailyRow{}
	}
	if rep.ProtoSpans == nil {
		rep.ProtoSpans = []ProtoSpan{}
	}
	if screen != nil {
		rep.FirstEvent, rep.LastEvent = screen.FirstEvent, screen.LastEvent
	}
	return rep, nil
}

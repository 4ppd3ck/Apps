package main

// Curated mapping from installed apps (as reported by wPurge) to IP
// databases published by their vendors for their OWN services — same
// philosophy as DefaultSources: no cloud-customer space. Match rules are
// "bid:<prefix>" (bundle-id prefix, e.g. com.microsoft.) or "name:<keyword>"
// (substring of the lowercased app name). Entries without match rules never
// match an app; they exist so the dashboard's full list can offer them.

import (
	"sort"
	"strings"
)

type CatalogEntry struct {
	Vendor   string   `json:"vendor"`
	Provider string   `json:"provider"` // provider name the data lands under
	Match    []string `json:"match,omitempty"`
	Source   Source   `json:"source,omitempty"`
	Note     string   `json:"note,omitempty"`
	SeedOnly bool     `json:"seed_only,omitempty"` // no official feed; bundled seed serves
}

func Catalog() []CatalogEntry {
	return []CatalogEntry{
		{
			Vendor: "Google", Provider: "Google & YouTube",
			Match:  []string{"bid:com.google.", "name:chrome", "name:google drive", "name:google meet"},
			Source: Source{Name: "Google & YouTube", URL: "https://www.gstatic.com/ipranges/goog.json", Format: "goog"},
			Note:   "official Google feed; enabled by default",
		},
		{
			Vendor: "Microsoft", Provider: "Microsoft 365",
			Match:  []string{"bid:com.microsoft.", "name:microsoft", "name:office", "name:teams", "name:onedrive", "name:outlook", "name:skype"},
			Source: Source{Name: "Microsoft 365", URL: "https://endpoints.office.com/endpoints/worldwide", Format: "ms365"},
			Note:   "official Microsoft 365 endpoint IPs (worldwide instance)",
		},
		{
			Vendor: "GitHub", Provider: "GitHub",
			Match:  []string{"bid:com.github.", "name:github"},
			Source: Source{Name: "GitHub", URL: "https://api.github.com/meta", Format: "github-meta"},
			Note:   "official GitHub meta feed; enabled by default",
		},
		{
			Vendor: "Telegram", Provider: "Telegram",
			Match:  []string{"bid:ru.keepcoder.", "bid:org.telegram.", "name:telegram"},
			Source: Source{Name: "Telegram", URL: "https://core.telegram.org/resources/cidr.txt", Format: "text"},
			Note:   "Telegram's published datacenter ranges",
		},
		{
			Vendor: "Fastly", Provider: "Fastly",
			Source: Source{Name: "Fastly", URL: "https://api.fastly.com/public-ip-list", Format: "fastly"},
			Note:   "CDN provider — no consumer app to match; add manually if you serve through Fastly",
		},
		{
			Vendor: "Apple", Provider: "Apple", SeedOnly: true,
			Note: "no official feed — bundled seed (17/8) is active",
		},
		{
			Vendor: "Meta", Provider: "Meta", SeedOnly: true,
			Match: []string{"name:facebook", "name:instagram", "name:whatsapp", "name:messenger"},
			Note:  "no official feed — bundled seed snapshot is active",
		},
	}
}

func catalogMatches(e *CatalogEntry, a wPurgeApp) bool {
	if len(e.Match) == 0 {
		return false
	}
	bid := strings.ToLower(a.ID)
	name := strings.ToLower(a.Name)
	for _, rule := range e.Match {
		switch {
		case strings.HasPrefix(rule, "bid:"):
			if bid != "" && strings.HasPrefix(bid, strings.TrimPrefix(rule, "bid:")) {
				return true
			}
		case strings.HasPrefix(rule, "name:"):
			if name != "" && strings.Contains(name, strings.TrimPrefix(rule, "name:")) {
				return true
			}
		}
	}
	return false
}

// AppRef is one installed app as shown in the dashboard.
type AppRef struct {
	Name    string `json:"name"`
	ID      string `json:"id,omitempty"`
	Version string `json:"version,omitempty"`
}

// CatalogMatch is one catalog entry annotated with what wPurge found.
type CatalogMatch struct {
	Vendor    string   `json:"vendor"`
	Provider  string   `json:"provider"`
	Note      string   `json:"note,omitempty"`
	SeedOnly  bool     `json:"seed_only,omitempty"`
	Installed bool     `json:"installed"`
	Apps      []AppRef `json:"apps,omitempty"`
	Active    bool     `json:"active"`
	Source    *Source  `json:"source,omitempty"`
}

// MatchCatalog joins wPurge's installed apps with the catalog. Every entry
// is returned (installed ones first) so the dashboard can offer the full
// list; unmatched apps come back separately.
func (it *Intel) MatchCatalog(apps []wPurgeApp) ([]CatalogMatch, []AppRef) {
	cat := Catalog()
	matched := make([][]AppRef, len(cat))
	unmatched := []AppRef{}
	for _, a := range apps {
		if a.Name == "" {
			continue
		}
		hit := false
		for i := range cat {
			if catalogMatches(&cat[i], a) {
				matched[i] = append(matched[i], AppRef{Name: a.Name, ID: a.ID, Version: a.Version})
				hit = true
			}
		}
		if !hit {
			unmatched = append(unmatched, AppRef{Name: a.Name, ID: a.ID})
		}
	}

	out := make([]CatalogMatch, 0, len(cat))
	for i, e := range cat {
		m := CatalogMatch{
			Vendor:    e.Vendor,
			Provider:  e.Provider,
			Note:      e.Note,
			SeedOnly:  e.SeedOnly,
			Apps:      matched[i],
			Installed: len(matched[i]) > 0,
		}
		if e.SeedOnly {
			m.Active = it.hasProvider(e.Provider)
		} else {
			m.Active = it.sourceConfigured(e.Source)
			src := e.Source
			m.Source = &src
		}
		out = append(out, m)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Installed != out[j].Installed {
			return out[i].Installed
		}
		return out[i].Vendor < out[j].Vendor
	})
	return out, unmatched
}

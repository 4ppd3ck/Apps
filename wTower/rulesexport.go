package wtower

// Rule-as-code: export/import of the whole enforcement rule set (firewall
// blocks + DNS-shield rules) as one JSON document, so a configuration can be
// version-controlled, cloned across machines and shared. The document
// marshals the same Block / DNSRule shapes the REST API already speaks.
//
//   GET  /api/rules/export            → the document
//   POST /api/rules/import            → merge (duplicate rules are skipped)
//   POST /api/rules/import?replace=1  → swap the whole set
//
// Import re-validates everything (unknown types are skipped, not trusted)
// and ends with an enforcer reconcile so the new rules reach pf/the
// application firewall immediately.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const ruleExportVersion = 1

// blockTypes / dnsTypes are the rule vocabularies the enforcer and the DNS
// shield actually dispatch on — anything else in an imported file is
// skipped with a count, never applied.
var blockTypes = map[string]bool{
	"app": true, "ip": true, "connection": true,
	"country": true, "list": true, "provider": true,
}
var dnsTypes = map[string]bool{
	"domain": true, "list": true, "provider": true,
}

type RuleExport struct {
	Version    int        `json:"version"`
	ExportedAt float64    `json:"exported_at"`
	Blocks     []*Block   `json:"blocks"`
	DNS        []*DNSRule `json:"dns"`
}

// buildRuleExport snapshots the current rule set.
func buildRuleExport(ctx *Ctx) (*RuleExport, error) {
	blocks, err := ctx.Store.ListBlocks()
	if err != nil {
		return nil, err
	}
	dns, err := ctx.Store.ListDNSRules()
	if err != nil {
		return nil, err
	}
	return &RuleExport{
		Version:    ruleExportVersion,
		ExportedAt: float64(time.Now().UnixNano()) / 1e9,
		Blocks:     blocks,
		DNS:        dns,
	}, nil
}

// blockIdentity is the dedupe key for a merge-import: same target, same
// action = same rule, regardless of ids or timestamps.
func blockIdentity(b *Block) string {
	app := ""
	if b.AppPath != nil {
		app = *b.AppPath
	}
	return strings.Join([]string{b.Type, b.Action, b.Value, app}, "|")
}

func dnsIdentity(r *DNSRule) string {
	return strings.Join([]string{r.Type, r.Action, r.Value}, "|")
}

// postRulesImport merges (or with ?replace=1, replaces) the imported rule
// set into the live store. Existing rules the document also carries are
// skipped, so re-importing an edited file never duplicates rows.
func postRulesImport(ctx *Ctx, w http.ResponseWriter, r *http.Request) {
	var in RuleExport
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON: " + err.Error()})
		return
	}
	replace := r.URL.Query().Get("replace") == "1"

	addedBlocks, skippedBlocks, badBlocks := 0, 0, []string{}
	addedDNS, skippedDNS, badDNS := 0, 0, []string{}

	// blocks -------------------------------------------------------------
	existing := map[string]bool{}
	if cur, err := ctx.Store.ListBlocks(); err == nil {
		for _, b := range cur {
			existing[blockIdentity(b)] = true
		}
	}
	if replace {
		if cur, err := ctx.Store.ListBlocks(); err == nil {
			for _, b := range cur {
				ctx.Store.RemoveBlock(b.ID) // best effort; identity map above is stale-safe
			}
			existing = map[string]bool{}
		}
	}
	for _, b := range in.Blocks {
		if b == nil {
			continue
		}
		if !blockTypes[b.Type] {
			badBlocks = append(badBlocks, fmt.Sprintf("unknown type %q", b.Type))
			continue
		}
		if b.Action != "allow" {
			b.Action = "block" // normalized like the REST add path
		}
		if strings.TrimSpace(b.Value) == "" {
			badBlocks = append(badBlocks, "empty value")
			continue
		}
		id := blockIdentity(b)
		if existing[id] {
			skippedBlocks++
			continue
		}
		if _, err := ctx.Store.AddBlock(b.Type, b.Action, b.Value, b.AppPath, b.Detail); err != nil {
			badBlocks = append(badBlocks, err.Error())
			continue
		}
		existing[id] = true
		addedBlocks++
	}

	// dns rules ------------------------------------------------------------
	if ctx.DNSShield == nil && len(in.DNS) > 0 {
		writeJSON(w, 500, map[string]any{"error": "dns shield unavailable — blocks imported, dns skipped"})
		return
	}
	if ctx.DNSShield != nil {
		existingDNS := map[string]bool{}
		if cur, err := ctx.Store.ListDNSRules(); err == nil {
			for _, d := range cur {
				existingDNS[dnsIdentity(d)] = true
			}
		}
		if replace {
			if cur, err := ctx.Store.ListDNSRules(); err == nil {
				for _, d := range cur {
					ctx.Store.RemoveDNSRule(d.ID)
				}
				existingDNS = map[string]bool{}
			}
		}
		for _, d := range in.DNS {
			if d == nil {
				continue
			}
			if !dnsTypes[d.Type] {
				badDNS = append(badDNS, fmt.Sprintf("unknown type %q", d.Type))
				continue
			}
			id := dnsIdentity(d)
			if existingDNS[id] {
				skippedDNS++
				continue
			}
			// AddRule validates and normalizes (domains parsed, action
			// block/allow) exactly like the dashboard's add path
			if _, err := ctx.DNSShield.AddRule(d.Type, d.Action, d.Value); err != nil {
				badDNS = append(badDNS, err.Error())
				continue
			}
			existingDNS[id] = true
			addedDNS++
		}
	}

	// let the new rules reach pf / the application firewall right away
	applied := 0
	if ctx.Enforcer != nil {
		if n, err := ctx.Enforcer.Reconcile(); err == nil {
			applied = n
		}
	}
	if ctx.DNSShield != nil {
		ctx.DNSShield.Reload()
	}
	writeJSON(w, 200, map[string]any{
		"ok": true, "replace": replace, "applied": applied,
		"blocks": map[string]any{"added": addedBlocks, "skipped": skippedBlocks, "rejected": badBlocks},
		"dns":    map[string]any{"added": addedDNS, "skipped": skippedDNS, "rejected": badDNS},
	})
}

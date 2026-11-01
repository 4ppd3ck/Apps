// Collector registry: builds the collector set for the running platform,
// honouring the per-category on/off toggles in config (`collectors` section).
// Mirrors collectors/__init__.py.
package collectors

import (
	"strings"

	"wtower"
)

func enabledFor(ctx *wtower.Ctx, category string) bool {
	cols := ctx.Cfg.CollectorsCfg()
	if cols == nil {
		return true
	}
	if v, ok := cols[category]; ok {
		if b, isBool := v.(bool); isBool {
			return b
		}
		return strings.ToLower(wtower.StrOf(v)) != "false"
	}
	return true
}

// BuildCollectors mirrors build_collectors. The three platform collectors
// (privacy/files/network) are provided by build-tagged files:
// *_windows.go, *_linux.go, *_darwin.go.
func BuildCollectors(ctx *wtower.Ctx) []wtower.Collector {
	candidates := []wtower.Collector{
		newPrivacyCollector(ctx),
		newFilesCollector(ctx),
		newNetworkCollector(ctx),
		NewDevicesCollector(ctx),
		NewLoginsCollector(ctx),
		NewAppFocusCollector(ctx),
		NewBatteryCollector(ctx),
		NewAndroidCollector(ctx),
	}
	for _, c := range candidates {
		c.SetEnabled(enabledFor(ctx, c.Category()))
	}
	return candidates
}

// ApplyToggles re-applies the persisted config toggles (used at startup and
// after edits).
func ApplyToggles(ctx *wtower.Ctx) {
	for _, c := range ctx.Collectors() {
		c.SetEnabled(enabledFor(ctx, c.Category()))
	}
}

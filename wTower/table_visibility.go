package wtower

import "fmt"

// normalizeWidth accepts panel widths as column spans on the 12-column grid
// (integers 1–12, decoded from JSON as float64) and maps the legacy named
// widths saved by older builds, so existing arrangements keep working.
func normalizeWidth(value any) (int, bool) {
	switch value := value.(type) {
	case int:
		if value >= 1 && value <= 12 {
			return value, true
		}
	case float64:
		if value >= 1 && value <= 12 && value == float64(int(value)) {
			return int(value), true
		}
	case string:
		switch value {
		case "full":
			return 12, true
		case "half":
			return 6, true
		case "third":
			return 4, true
		}
	}
	return 0, false
}

var tableVisibilityDefaults = map[string]bool{
	"traffic-panel":            true,
	"traffic-totals-panel":     true,
	"live-connections-panel":   true,
	"geo-countries-panel":      true,
	"sites-panel":              true,
	"connections-panel":        true,
	"top-apps-panel":           true,
	"connection-summary-panel": true,
	"heatmap-panel":            true,
	"visits-panel":             true,
	"battery-panel":            true,
	"privacy-panel":            true,
	"files-panel":              true,
	"network-panel":            true,
	"system-panel":             true,
	"blocks-panel":             true,
	"dns-panel":                true,
}

var dashboardLayoutOrder = []string{
	"traffic-totals-panel", "traffic-panel", "live-connections-panel",
	"geo-countries-panel", "sites-panel",
	"connections-panel", "top-apps-panel", "connection-summary-panel",
	"heatmap-panel", "visits-panel",
	"battery-panel", "privacy-panel", "files-panel", "network-panel",
	"system-panel", "blocks-panel", "dns-panel",
}

// reportLayoutOrder whitelists the arrangementable Report view panels (the
// usage-report controls panel is fixed at full width and not rearrangeable).
var reportLayoutOrder = []string{
	"report-screen-panel", "report-protos-panel", "report-sites-panel",
	"report-usage-panel", "report-byapp-panel",
}

func validReportPanel(id string) bool {
	for _, known := range reportLayoutOrder {
		if known == id {
			return true
		}
	}
	return false
}

// panelLayoutSpec pins one layout family to its config key, panel order,
// whitelist and the per-panel defaults the shipped arrangement ships with.
type panelLayoutSpec struct {
	key     string
	order   []string
	valid   func(string) bool
	widths  map[string]any // panel -> non-default width
	heights map[string]any // panel -> non-default height
}

var dashboardLayoutSpec = panelLayoutSpec{
	key:   "dashboard_layout",
	order: dashboardLayoutOrder,
	valid: func(id string) bool { _, ok := tableVisibilityDefaults[id]; return ok },
	widths: map[string]any{
		"top-apps-panel": 6, "connection-summary-panel": 6,
	},
	heights: map[string]any{
		"connection-summary-panel": 461,
	},
}

var reportLayoutSpec = panelLayoutSpec{
	key:   "report_layout",
	order: reportLayoutOrder,
	valid: validReportPanel,
	// the GlassWire-ish defaults: the small tables sit beside their donuts
	// at half width, the wide sites table spans the row
	widths: map[string]any{
		"report-screen-panel": 6, "report-protos-panel": 6,
		"report-usage-panel": 6, "report-byapp-panel": 6,
	},
}

// panelLayout returns one layout family: the shipped arrangement with
// whatever the saved config validly overrides. Unknown ids and out-of-range
// values from hand-edited configs are ignored, never rejected.
func panelLayout(cfg *Config, spec panelLayoutSpec) map[string]any {
	order := append([]string(nil), spec.order...)
	widths := map[string]any{}
	heights := map[string]any{}
	panelLocks := map[string]any{}
	collapsed := map[string]any{}
	for _, panel := range spec.order {
		widths[panel] = 12
		panelLocks[panel] = false
		collapsed[panel] = false
	}
	for id, w := range spec.widths {
		widths[id] = w
	}
	for id, h := range spec.heights {
		heights[id] = h
	}
	locked := false
	savedAny, _ := cfg.Get(spec.key)
	if saved, ok := savedAny.(map[string]any); ok {
		var savedOrder []any
		switch values := saved["order"].(type) {
		case []any:
			savedOrder = values
		case []string:
			for _, id := range values {
				savedOrder = append(savedOrder, id)
			}
		}
		if savedOrder != nil {
			seen := map[string]bool{}
			ordered := make([]string, 0, len(order))
			for _, item := range savedOrder {
				id, ok := item.(string)
				if !ok {
					continue
				}
				if spec.valid(id) && !seen[id] {
					ordered = append(ordered, id)
					seen[id] = true
				}
			}
			for _, id := range order {
				if !seen[id] {
					ordered = append(ordered, id)
				}
			}
			order = ordered
		}
		if savedWidths, ok := saved["widths"].(map[string]any); ok {
			for id, width := range savedWidths {
				if spec.valid(id) {
					if span, ok := normalizeWidth(width); ok {
						widths[id] = span
					}
				}
			}
		}
		if savedHeights, ok := saved["heights"].(map[string]any); ok {
			for id, height := range savedHeights {
				if !spec.valid(id) {
					continue
				}
				if value, ok := height.(float64); ok && value >= 180 && value <= 1200 {
					heights[id] = value
				}
			}
		}
		if savedLocks, ok := saved["panel_locks"].(map[string]any); ok {
			for id, value := range savedLocks {
				if spec.valid(id) {
					if isLocked, ok := value.(bool); ok {
						panelLocks[id] = isLocked
					}
				}
			}
		}
		if savedCollapsed, ok := saved["collapsed"].(map[string]any); ok {
			for id, value := range savedCollapsed {
				if spec.valid(id) {
					if isCollapsed, ok := value.(bool); ok {
						collapsed[id] = isCollapsed
					}
				}
			}
		}
		if value, ok := saved["locked"].(bool); ok {
			locked = value
		}
	}
	return map[string]any{
		"order": order, "widths": widths, "heights": heights,
		"locked": locked, "panel_locks": panelLocks, "collapsed": collapsed,
	}
}

// savePanelLayout validates one layout family against its whitelist and
// persists it. Update restores the previous config when the save fails, so
// the caller only has to surface the error.
func savePanelLayout(cfg *Config, spec panelLayoutSpec, value any) (map[string]any, error) {
	input, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("layout must be an object")
	}
	layout := panelLayout(cfg, spec)
	if rawOrder, exists := input["order"]; exists {
		items, ok := rawOrder.([]any)
		if !ok {
			return nil, fmt.Errorf("layout order must be an array")
		}
		seen := map[string]bool{}
		order := make([]string, 0, len(spec.order))
		for _, item := range items {
			id, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("layout order entries must be strings")
			}
			if !spec.valid(id) {
				return nil, fmt.Errorf("unknown panel %q", id)
			}
			if !seen[id] {
				order = append(order, id)
				seen[id] = true
			}
		}
		for _, id := range spec.order {
			if !seen[id] {
				order = append(order, id)
			}
		}
		layout["order"] = order
	}
	for _, key := range []string{"widths", "heights", "panel_locks", "collapsed"} {
		raw, exists := input[key]
		if !exists {
			continue
		}
		values, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("layout %s must be an object", key)
		}
		current := layout[key].(map[string]any)
		for id, item := range values {
			if !spec.valid(id) {
				return nil, fmt.Errorf("unknown panel %q", id)
			}
			switch key {
			case "widths":
				span, ok := normalizeWidth(item)
				if !ok {
					return nil, fmt.Errorf("invalid width for %q", id)
				}
				current[id] = span
			case "heights":
				height, ok := item.(float64)
				if !ok || height < 180 || height > 1200 {
					return nil, fmt.Errorf("invalid height for %q", id)
				}
				current[id] = height
			case "panel_locks", "collapsed":
				flag, ok := item.(bool)
				if !ok {
					return nil, fmt.Errorf("invalid %s state for %q", key, id)
				}
				current[id] = flag
			}
		}
	}
	if rawLocked, exists := input["locked"]; exists {
		locked, ok := rawLocked.(bool)
		if !ok {
			return nil, fmt.Errorf("layout lock must be boolean")
		}
		layout["locked"] = locked
	}
	if err := cfg.Update(func(data map[string]any) { data[spec.key] = layout }); err != nil {
		return nil, fmt.Errorf("save %s: %w", spec.key, err)
	}
	return layout, nil
}

// named wrappers keep the four historical entry points the server calls.
func dashboardLayout(cfg *Config) map[string]any { return panelLayout(cfg, dashboardLayoutSpec) }
func saveDashboardLayout(cfg *Config, value any) (map[string]any, error) {
	return savePanelLayout(cfg, dashboardLayoutSpec, value)
}
func reportLayout(cfg *Config) map[string]any { return panelLayout(cfg, reportLayoutSpec) }
func saveReportLayout(cfg *Config, value any) (map[string]any, error) {
	return savePanelLayout(cfg, reportLayoutSpec, value)
}

func tableVisibility(cfg *Config) map[string]bool {
	visibility := make(map[string]bool, len(tableVisibilityDefaults))
	for key, value := range tableVisibilityDefaults {
		visibility[key] = value
	}
	savedAny, _ := cfg.Get("table_visibility")
	saved, ok := savedAny.(map[string]any)
	if !ok {
		return visibility
	}
	for key, value := range saved {
		if _, valid := tableVisibilityDefaults[key]; !valid {
			continue
		}
		if visible, ok := value.(bool); ok {
			visibility[key] = visible
		}
	}
	return visibility
}

func saveTableVisibility(cfg *Config, value any) (map[string]bool, error) {
	input, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("visibility must be an object")
	}
	visibility := tableVisibility(cfg)
	for key, value := range input {
		if _, valid := tableVisibilityDefaults[key]; !valid {
			return nil, fmt.Errorf("unknown table %q", key)
		}
		visible, ok := value.(bool)
		if !ok {
			return nil, fmt.Errorf("visibility for %q must be boolean", key)
		}
		visibility[key] = visible
	}
	saved := make(map[string]any, len(visibility))
	for key, visible := range visibility {
		saved[key] = visible
	}
	if err := cfg.Update(func(data map[string]any) { data["table_visibility"] = saved }); err != nil {
		return nil, fmt.Errorf("save table visibility: %w", err)
	}
	return visibility, nil
}

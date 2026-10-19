package monitor

import "fmt"

var tableVisibilityDefaults = map[string]bool{
	"traffic-panel":            true,
	"traffic-totals-panel":     true,
	"live-connections-panel":   true,
	"connections-panel":        true,
	"top-apps-panel":           true,
	"connection-summary-panel": true,
	"battery-panel":            true,
	"privacy-panel":            true,
	"files-panel":              true,
	"network-panel":            true,
	"system-panel":             true,
	"blocks-panel":             true,
}

var dashboardLayoutOrder = []string{
	"traffic-panel", "live-connections-panel", "traffic-totals-panel",
	"connections-panel", "top-apps-panel", "connection-summary-panel",
	"battery-panel", "privacy-panel", "files-panel", "network-panel",
	"system-panel", "blocks-panel",
}

func dashboardLayout(cfg *Config) map[string]any {
	order := append([]string(nil), dashboardLayoutOrder...)
	widths := map[string]any{}
	panelLocks := map[string]any{}
	for _, panel := range dashboardLayoutOrder {
		widths[panel] = "full"
		panelLocks[panel] = false
	}
	widths["top-apps-panel"] = "half"
	widths["connection-summary-panel"] = "half"
	heights := map[string]any{}
	locked := false
	if saved, ok := cfg.Data["dashboard_layout"].(map[string]any); ok {
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
				if _, valid := tableVisibilityDefaults[id]; valid && !seen[id] {
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
				if _, valid := tableVisibilityDefaults[id]; valid {
					if value, ok := width.(string); ok && (value == "full" || value == "half" || value == "third") {
						widths[id] = value
					}
				}
			}
		}
		if savedHeights, ok := saved["heights"].(map[string]any); ok {
			for id, height := range savedHeights {
				if _, valid := tableVisibilityDefaults[id]; !valid {
					continue
				}
				if value, ok := height.(float64); ok && value >= 180 && value <= 1200 {
					heights[id] = value
				}
			}
		}
		if savedLocks, ok := saved["panel_locks"].(map[string]any); ok {
			for id, value := range savedLocks {
				if _, valid := tableVisibilityDefaults[id]; valid {
					if isLocked, ok := value.(bool); ok {
						panelLocks[id] = isLocked
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
		"locked": locked, "panel_locks": panelLocks,
	}
}

func saveDashboardLayout(cfg *Config, value any) (map[string]any, error) {
	input, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("layout must be an object")
	}
	layout := dashboardLayout(cfg)
	if rawOrder, exists := input["order"]; exists {
		items, ok := rawOrder.([]any)
		if !ok {
			return nil, fmt.Errorf("layout order must be an array")
		}
		seen := map[string]bool{}
		order := make([]string, 0, len(tableVisibilityDefaults))
		for _, item := range items {
			id, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("layout order entries must be strings")
			}
			if _, valid := tableVisibilityDefaults[id]; !valid {
				return nil, fmt.Errorf("unknown panel %q", id)
			}
			if !seen[id] {
				order = append(order, id)
				seen[id] = true
			}
		}
		for _, id := range dashboardLayoutOrder {
			if !seen[id] {
				order = append(order, id)
			}
		}
		layout["order"] = order
	}
	for _, key := range []string{"widths", "heights", "panel_locks"} {
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
			if _, valid := tableVisibilityDefaults[id]; !valid {
				return nil, fmt.Errorf("unknown panel %q", id)
			}
			switch key {
			case "widths":
				width, ok := item.(string)
				if !ok || (width != "full" && width != "half" && width != "third") {
					return nil, fmt.Errorf("invalid width for %q", id)
				}
				current[id] = width
			case "heights":
				height, ok := item.(float64)
				if !ok || height < 180 || height > 1200 {
					return nil, fmt.Errorf("invalid height for %q", id)
				}
				current[id] = height
			case "panel_locks":
				isLocked, ok := item.(bool)
				if !ok {
					return nil, fmt.Errorf("invalid lock state for %q", id)
				}
				current[id] = isLocked
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
	previous, hadPrevious := cfg.Data["dashboard_layout"]
	cfg.Data["dashboard_layout"] = layout
	if err := cfg.Save(); err != nil {
		if hadPrevious {
			cfg.Data["dashboard_layout"] = previous
		} else {
			delete(cfg.Data, "dashboard_layout")
		}
		return nil, fmt.Errorf("save dashboard layout: %w", err)
	}
	return layout, nil
}

func tableVisibility(cfg *Config) map[string]bool {
	visibility := make(map[string]bool, len(tableVisibilityDefaults))
	for key, value := range tableVisibilityDefaults {
		visibility[key] = value
	}
	saved, ok := cfg.Data["table_visibility"].(map[string]any)
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
	previous, hadPrevious := cfg.Data["table_visibility"]
	cfg.Data["table_visibility"] = saved
	if err := cfg.Save(); err != nil {
		if hadPrevious {
			cfg.Data["table_visibility"] = previous
		} else {
			delete(cfg.Data, "table_visibility")
		}
		return nil, fmt.Errorf("save table visibility: %w", err)
	}
	return visibility, nil
}

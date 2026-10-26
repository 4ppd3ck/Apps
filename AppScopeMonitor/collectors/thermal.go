// Thermal monitoring: per-platform temperature / throttling reads with one
// shared "does this machine need to cool down" verdict.
//
//   - darwin: battery temperature via ioreg (laptops only) + CPU throttle /
//     thermal-warning state via `pmset -g therm` (works unprivileged; SMC
//     die sensors need root powermetrics, so CPU °C is not readable here)
//   - linux:  /sys/class/thermal + /sys/class/hwmon zone temperatures
//   - windows: WMI MSAcpi_ThermalZoneTemperature (often admin-only; absent
//     gracefully)
//
// The thermal block rides in the battery payload (ctx.battery →
// /api/battery) and the collector emits system events on hot/cold
// transitions so the dashboard's system panel records the alert.
package collectors

import (
	"fmt"
	"sort"
	"strings"

	"monitor"
)

// Thresholds in °C with hysteresis: the alert clears a few degrees below
// where it fired so flapping temperatures don't spam the event log.
const (
	thermalBatteryHot     = 45.0
	thermalBatteryWarm    = 40.0
	thermalBatteryRecover = 43.0
	thermalCPUHot         = 85.0
	thermalCPUWarm        = 75.0
	thermalCPURecover     = 78.0
)

// thermalOf pulls the thermal block out of a vitals payload.
func thermalOf(info map[string]any) map[string]any {
	if info == nil {
		return nil
	}
	thermal, _ := info["thermal"].(map[string]any)
	return thermal
}

// thermalFloat reads an optional °C value from the thermal block.
func thermalFloat(thermal map[string]any, key string) (float64, bool) {
	if thermal == nil {
		return 0, false
	}
	return monitor.ToFloat(thermal[key])
}

// thermalStatus derives the verdict from the current readings. "hot" means
// the machine needs to cool down (throttling counts even without a sensor
// reading — it is the OS saying so itself).
func thermalStatus(thermal map[string]any) string {
	if thermal == nil {
		return ""
	}
	hot, warm := false, false
	if temp, ok := thermalFloat(thermal, "battery_temp_c"); ok {
		hot = hot || temp >= thermalBatteryHot
		warm = warm || temp >= thermalBatteryWarm
	}
	if temp, ok := thermalFloat(thermal, "cpu_temp_c"); ok {
		hot = hot || temp >= thermalCPUHot
		warm = warm || temp >= thermalCPUWarm
	}
	if pct, ok := thermalFloat(thermal, "throttle_percent"); ok && pct < 100 {
		hot = true
	}
	if warn, ok := thermal["thermal_warning"].(bool); ok && warn {
		hot = true
	}
	// macOS machine-wide thermal state (NSProcessInfo): 1 fair, 2 serious,
	// 3 critical — serious+ means the machine is defending itself
	if state, ok := thermalFloat(thermal, "thermal_state"); ok {
		hot = hot || state >= 2
		warm = warm || state >= 1
	}
	switch {
	case hot:
		return "hot"
	case warm:
		return "warm"
	default:
		return "nominal"
	}
}

// finalizeThermal stamps the verdict onto a freshly read thermal block.
func finalizeThermal(thermal map[string]any) map[string]any {
	if thermal == nil {
		return nil
	}
	thermal["status"] = thermalStatus(thermal)
	return thermal
}

// thermalDetail renders the current readings for event text / UI banners.
func thermalDetail(thermal map[string]any) string {
	if thermal == nil {
		return ""
	}
	var parts []string
	if temp, ok := thermalFloat(thermal, "battery_temp_c"); ok {
		parts = append(parts, fmt.Sprintf("battery %.1f°C", temp))
	}
	if temp, ok := thermalFloat(thermal, "cpu_temp_c"); ok {
		zone, _ := thermal["zone"].(string)
		if zone == "" {
			zone = "CPU"
		}
		parts = append(parts, fmt.Sprintf("%s %.1f°C", strings.ToLower(zone), temp))
	}
	if pct, ok := thermalFloat(thermal, "throttle_percent"); ok && pct < 100 {
		parts = append(parts, fmt.Sprintf("CPU throttled to %d%%", int(pct)))
	}
	if warn, ok := thermal["thermal_warning"].(bool); ok && warn {
		parts = append(parts, "macOS thermal warning active")
	}
	if name, ok := thermal["thermal_state_name"].(string); ok && name != "nominal" {
		parts = append(parts, fmt.Sprintf("machine thermal state %s", name))
	}
	return strings.Join(parts, ", ")
}

// checkThermalAlerts emits thermal_hot when the machine enters the hot
// state and thermal_ok once it recovers (with hysteresis — the recovery
// thresholds sit a few degrees under the firing ones).
func (c *BatteryCollector) checkThermalAlerts(thermal map[string]any) {
	status := thermalStatus(thermal)
	if status == "" {
		return // platform has no thermal data
	}
	detail := thermalDetail(thermal)
	if status == "hot" {
		if !c.thermalHot {
			c.thermalHot = true
			c.Emit(&monitor.Event{
				Category: "system",
				Kind:     "thermal_hot",
				Detail: fmt.Sprintf("machine needs to cool down: %s",
					nonEmpty(detail, "throttling active")),
			})
		}
		return
	}
	// warm keeps the current alert state; only nominal clears it
	if status == "nominal" && c.thermalHot {
		c.thermalHot = false
		c.Emit(&monitor.Event{
			Category: "system",
			Kind:     "thermal_ok",
			Detail: fmt.Sprintf("machine cooled down: %s",
				nonEmpty(detail, "back to nominal")),
		})
	}
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// thermalZone is one temperature reading for the Linux zones list.
type thermalZone struct {
	Zone string  `json:"zone"`
	Temp float64 `json:"temp_c"`
}

// sortZones sorts hottest-first.
func sortZones(zones []thermalZone) {
	sort.Slice(zones, func(i, j int) bool { return zones[i].Temp > zones[j].Temp })
}

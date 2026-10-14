// System vitals collector: battery, CPU, RAM and disk gauges + power
// consumers.
//
//   - battery: percent, state (charging/discharging), time remaining,
//     low-power mode -- omitted on machines without a battery
//   - cpu_percent / mem_percent / disk_percent: system-wide utilisation
//   - volumes: every mounted volume with used/total
//   - top power consumers: per-app CPU usage + process runtime
//   - macOS extra: apps holding sleep-prevention assertions
//
// Publishes ctx.battery (served at /api/battery) and emits system events on
// battery state changes and low-battery thresholds.
//
// Mirrors collectors/battery.py. Shared parts live here; the Windows loop is
// in battery_windows.go, the POSIX loop in battery_unix.go, and the
// per-OS stat helpers in battery_darwin.go / battery_linux.go.
package collectors

import (
	"fmt"
	"runtime"
	"strings"

	"monitor"
)

// fmtGB mirrors battery._fmt_gb.
func fmtGB(nbytes float64) string {
	if nbytes < 10*1073741824 {
		return fmt.Sprintf("%.1f GB", nbytes/1073741824)
	}
	return fmt.Sprintf("%d GB", int64(nbytes)/1073741824)
}

// BatteryCollector publishes system vitals.
type BatteryCollector struct {
	*BaseCollector
	state       string
	hasState    bool
	lowFlags    map[string]bool
	prevCPU     [3]float64         // (total jiffies, idle jiffies, ts) -- Linux
	prevJiffies map[int][2]float64 // pid -> (jiffies, ts) -- Linux top apps
}

// NewBatteryCollector creates the collector.
func NewBatteryCollector(ctx *monitor.Ctx) *BatteryCollector {
	b := NewBase(ctx, "battery", "Battery / CPU / disk gauges + top power consumers",
		"battery")
	c := &BatteryCollector{BaseCollector: b, lowFlags: map[string]bool{},
		prevJiffies: map[int][2]float64{}}
	b.setRun(c.run)
	return c
}

// Available: CPU + disk vitals work everywhere; the battery gauge simply
// hides itself on machines without one.
func (c *BatteryCollector) Available() (bool, string) {
	if runtime.GOOS == "windows" {
		rc, _, errOut := runPowerShellProbe()
		if rc == 127 && strings.Contains(errOut, "not found") {
			return false, "powershell.exe not found"
		}
		return true, ""
	}
	return true, ""
}

func (c *BatteryCollector) run() {
	interval := c.Ctx.Poll("battery", 10.0)
	if runtime.GOOS == "windows" {
		c.runWindows(interval)
		return
	}
	c.runPosix(interval)
}

// publish mirrors _publish.
func (c *BatteryCollector) publish(info map[string]any) {
	c.Ctx.SetBattery(info)
	if info["percent"] == nil {
		return // no battery on this machine; CPU/disk gauges still served
	}
	state, _ := info["state"].(string)
	if c.hasState && state != c.state {
		detail := fmt.Sprintf("battery now %s at %s%%", state,
			percentStr(info["percent"]))
		if tr, ok := info["time_remaining"].(string); ok && tr != "" {
			detail += ", " + tr
		}
		c.Emit(&monitor.Event{
			Category: "system",
			Kind:     "battery_state",
			Detail:   detail,
		})
	}
	c.state = state
	c.hasState = true
	percent := 100.0
	if f, ok := monitor.ToFloat(info["percent"]); ok && f != 0 {
		percent = f // Python: info.get("percent") or 100
	}
	discharging := strings.Contains(strings.ToLower(state), "discharg")
	for _, threshold := range []int{20, 10} {
		key := fmt.Sprintf("low%d", threshold)
		t := float64(threshold)
		if discharging && percent <= t && !c.lowFlags[key] {
			c.lowFlags[key] = true
			c.Emit(&monitor.Event{
				Category: "system",
				Kind:     "battery_low",
				Detail: fmt.Sprintf("battery low: %s%% (%s)",
					percentStr(info["percent"]), state),
			})
		} else if (!discharging || percent > t+5) && c.lowFlags[key] {
			delete(c.lowFlags, key)
		}
	}
}

// percentStr renders a JSON number the way Python would print an int percent.
func percentStr(v any) string {
	if f, ok := monitor.ToFloat(v); ok && f == float64(int64(f)) {
		return fmt.Sprintf("%d", int64(f))
	}
	return monitor.StrOf(v)
}

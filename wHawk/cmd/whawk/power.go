package main

// Power — adaptive scanning on battery / low-power machines. The engine
// multiplies its fast/slow ticks by a power factor: 1× on AC, 3× on
// battery, 5× when Low Power Mode is engaged. Detection logic is unchanged
// — only the cadence stretches, so a plugged-in Mac gets the snappy scans
// while a laptop on battery preserves charge (rules.fixed_ticks opts out).
//
// Pure stdlib (pmset / /sys/class/power_supply / Win32_Battery via
// powershell) so build.sh still cross-compiles to every GOOS/GOARCH.

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

type PowerMode string

const (
	PowerAC       PowerMode = "ac"
	PowerBattery  PowerMode = "battery"
	PowerLowPower PowerMode = "lowpower" // Low Power Mode engaged (any source)
	PowerUnknown  PowerMode = "unknown"
)

// powerFactor is the scan-interval multiplier for a power mode. Low Power
// Mode wins over plain battery: the user has explicitly asked the machine
// to conserve.
func powerFactor(m PowerMode) int {
	switch m {
	case PowerLowPower:
		return 5
	case PowerBattery:
		return 3
	default:
		return 1
	}
}

type PowerState struct {
	Mode    PowerMode `json:"mode"`
	Factor  int       `json:"factor"`
	Detail  string    `json:"detail"`  // human hint, e.g. "53%; discharging; 2:35 remaining"
	Checked time.Time `json:"checked"` // when the OS was last asked
}

// PowerReader caches the OS power snapshot for ttl so the scan loop can ask
// on every tick without shelling out each time. read and now are
// indirected for tests.
type PowerReader struct {
	mu   sync.Mutex
	cur  PowerState
	ttl  time.Duration
	now  func() time.Time
	read func() PowerState
}

func NewPowerReader() *PowerReader {
	return &PowerReader{
		ttl:  30 * time.Second,
		now:  time.Now,
		read: readPowerState,
	}
}

// Snapshot returns the cached state, refreshing from the OS when stale.
func (p *PowerReader) Snapshot() PowerState {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cur.Mode != "" && p.now().Sub(p.cur.Checked) < p.ttl {
		return p.cur
	}
	st := p.read()
	st.Checked = p.now()
	st.Factor = powerFactor(st.Mode)
	p.cur = st
	return p.cur
}

// readPowerState asks the OS once. Errors and unsupported platforms answer
// PowerUnknown — factor 1, never slowing a machine we cannot read.
func readPowerState() PowerState {
	switch runtime.GOOS {
	case "darwin":
		return readPowerDarwin()
	case "linux":
		return readPowerLinux()
	case "windows":
		return readPowerWindows()
	}
	return PowerState{Mode: PowerUnknown}
}

func readPowerDarwin() PowerState {
	st := PowerState{Mode: PowerUnknown}
	batt, err := RunOut(10*time.Second, "pmset", "-g", "batt")
	if err != nil {
		return st
	}
	switch {
	case strings.Contains(batt, "'AC Power'"):
		st.Mode = PowerAC
	case strings.Contains(batt, "'Battery Power'"):
		st.Mode = PowerBattery
	default:
		return st
	}
	// The battery line carries the human hint: "53%; discharging; 2:35 remaining"
	if line, ok := pmsetBatteryLine(batt); ok {
		st.Detail = line
	}
	// Low Power Mode lives in the settings dump, not the battery one.
	if settings, err := RunOut(10*time.Second, "pmset", "-g"); err == nil && pmsetLowPower(settings) {
		st.Mode = PowerLowPower
	}
	return st
}

// pmsetBatteryLine extracts the "-InternalBattery-0 …" hint line.
func pmsetBatteryLine(out string) (string, bool) {
	for _, ln := range strings.Split(out, "\n") {
		t := strings.TrimSpace(ln)
		if strings.Contains(t, "%") && strings.Contains(t, "remaining") {
			return t, true
		}
	}
	return "", false
}

// pmsetLowPower parses the settings dump's "lowpowermode   1" row.
func pmsetLowPower(out string) bool {
	fields := strings.Fields(out)
	for i, f := range fields {
		if f == "lowpowermode" && i+1 < len(fields) {
			return fields[i+1] == "1"
		}
	}
	return false
}

func readPowerLinux() PowerState {
	// Any supply currently discharging means we are on battery.
	matches, _ := filepath.Glob("/sys/class/power_supply/*/status")
	for _, path := range matches {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(string(raw)), "discharging") {
			return PowerState{Mode: PowerBattery,
				Detail: filepath.Base(filepath.Dir(path)) + " discharging"}
		}
	}
	if len(matches) > 0 {
		return PowerState{Mode: PowerAC}
	}
	return PowerState{Mode: PowerUnknown} // desktop without power_supply info
}

func readPowerWindows() PowerState {
	// BatteryStatus 2 == "on AC / charging"; anything else is drawing.
	// Desktops without a battery answer empty — unknown, factor 1.
	out, err := RunOut(15*time.Second, "powershell", "-NoProfile", "-Command",
		"(Get-CimInstance Win32_Battery).BatteryStatus")
	if err != nil || strings.TrimSpace(out) == "" {
		return PowerState{Mode: PowerUnknown}
	}
	if strings.TrimSpace(out) == "2" {
		return PowerState{Mode: PowerAC}
	}
	return PowerState{Mode: PowerBattery}
}

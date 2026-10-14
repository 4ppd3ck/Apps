// Device & storage collector: USB connect/disconnect and volume mount events.
//
//   - macOS: `system_profiler SPUSBDataType -json` + /Volumes listing
//   - Linux: /sys/bus/usb/devices + /proc/mounts
//   - Windows: PowerShell Get-PnpDevice + Get-Volume snapshot loop
//
// Mirrors collectors/devices.py.
package collectors

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"monitor"
)

const devicesPS = `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
while ($true) {
  $usb = @()
  Get-PnpDevice -PresentOnly -Class USB -ErrorAction SilentlyContinue |
    ForEach-Object {
      $usb += @{name=$_.FriendlyName; serial=$_.InstanceId}
    }
  $vols = @()
  Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.DriveLetter } |
    ForEach-Object {
      $vols += @{name=("$($_.DriveLetter): " + $_.FriendlyName)}
    }
  @{usb=$usb; volumes=$vols} | ConvertTo-Json -Depth 3 -Compress | Write-Output
  [Console]::Out.Flush()
  Start-Sleep -Seconds 5
}
`

// DevicesCollector watches USB / storage device connect-disconnect events.
type DevicesCollector struct {
	*BaseCollector
	usb  map[usbKey]bool
	vols map[string]bool
}

type usbKey struct{ name, serial string }

// NewDevicesCollector creates the collector.
func NewDevicesCollector(ctx *monitor.Ctx) *DevicesCollector {
	b := NewBase(ctx, "devices", "USB / storage device connect-disconnect events", "devices")
	c := &DevicesCollector{BaseCollector: b, usb: map[usbKey]bool{}, vols: map[string]bool{}}
	b.setRun(c.run)
	return c
}

func (c *DevicesCollector) run() {
	interval := c.Ctx.Poll("devices", 5.0)
	if runtime.GOOS == "windows" {
		c.runWindows(interval)
		return
	}
	c.SetStatus("active", "")
	for !c.Stopped() {
		c.pollUSB()
		c.pollMounts()
		c.Sleep(interval)
	}
}

// ----------------------------------------------------------- posix ----

func (c *DevicesCollector) pollUSB() {
	var current map[usbKey]bool
	if runtime.GOOS == "darwin" {
		current = usbMacOS()
	} else {
		current = usbLinux()
	}
	c.diffUSB(current)
}

func (c *DevicesCollector) diffUSB(current map[usbKey]bool) {
	for key := range current {
		if !c.usb[key] {
			c.emitDevice("device_connect", key.name)
		}
	}
	for key := range c.usb {
		if !current[key] {
			c.emitDevice("device_disconnect", key.name)
		}
	}
	c.usb = current
}

func (c *DevicesCollector) emitDevice(kind, label string) {
	c.Emit(&monitor.Event{
		Category: "devices",
		Kind:     kind,
		User:     monitor.GetPassUser(),
		Device:   label,
		Detail:   deviceKindLabel(kind) + ": " + label,
		Path:     label,
	})
}

func deviceKindLabel(kind string) string {
	// mirrors f"{kind} attached: {label}" / f"{kind} removed: {label}"
	if strings.HasSuffix(kind, "_connect") {
		return strings.TrimSuffix(kind, "_connect") + " attached"
	}
	return strings.TrimSuffix(kind, "_disconnect") + " removed"
}

func usbMacOS() map[usbKey]bool {
	_, out, _ := monitor.Run([]string{"system_profiler", "SPUSBDataType", "-json"},
		20*time.Second)
	if strings.TrimSpace(out) == "" {
		return map[usbKey]bool{}
	}
	found := map[usbKey]bool{}
	var data map[string]any
	if json.Unmarshal([]byte(out), &data) != nil {
		return found
	}
	trees, _ := data["SPUSBDataType"].([]any)
	var walk func(items []any)
	walk = func(items []any) {
		for _, item := range items {
			it, ok := item.(map[string]any)
			if !ok {
				continue
			}
			productID, _ := it["product_id"].(string)
			serial, _ := it["serial_num"].(string)
			name, _ := it["_name"].(string)
			if productID != "" || serial != "" {
				if name == "" {
					name = "USB device"
				}
				if serial == "" {
					serial = "-"
				}
				found[usbKey{name, serial}] = true
			}
			if sub, ok := it["_items"].([]any); ok {
				walk(sub)
			}
		}
	}
	for _, tree := range trees {
		walk([]any{tree})
	}
	return found
}

func usbLinux() map[usbKey]bool {
	found := map[usbKey]bool{}
	base := "/sys/bus/usb/devices"
	entries, err := os.ReadDir(base)
	if err != nil {
		return found
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.Contains(name, ":") { // interface dirs like 1-2:1.0
			continue
		}
		dev := filepath.Join(base, name)
		product, err1 := os.ReadFile(filepath.Join(dev, "product"))
		serial, err2 := os.ReadFile(filepath.Join(dev, "serial"))
		if err1 != nil || err2 != nil {
			continue
		}
		devName := strings.TrimSpace(string(product))
		serialStr := strings.TrimSpace(string(serial))
		if devName != "" {
			if serialStr == "" {
				serialStr = "-"
			}
			found[usbKey{devName, serialStr}] = true
		}
	}
	return found
}

func (c *DevicesCollector) pollMounts() {
	current := map[string]bool{}
	if runtime.GOOS == "darwin" {
		if entries, err := os.ReadDir("/Volumes"); err == nil {
			for _, e := range entries {
				current[e.Name()] = true
			}
		}
	} else {
		if data, err := os.ReadFile("/proc/mounts"); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				parts := strings.Fields(line)
				if len(parts) > 1 && (strings.HasPrefix(parts[1], "/media") ||
					strings.HasPrefix(parts[1], "/mnt") ||
					strings.HasPrefix(parts[1], "/run/media")) {
					current[strings.ReplaceAll(parts[1], "\\040", " ")] = true
				}
			}
		}
	}
	for vol := range current {
		if !c.vols[vol] {
			c.emitVolume("storage_connect", vol)
		}
	}
	for vol := range c.vols {
		if !current[vol] {
			c.emitVolume("storage_disconnect", vol)
		}
	}
	c.vols = current
}

func (c *DevicesCollector) emitVolume(kind, label string) {
	c.Emit(&monitor.Event{
		Category: "devices",
		Kind:     kind,
		User:     monitor.GetPassUser(),
		Device:   label,
		Detail:   deviceKindLabel(kind) + ": " + label,
		Path:     label,
	})
}

// --------------------------------------------------------- windows ----

func (c *DevicesCollector) runWindows(interval float64) {
	path := filepath.Join(os.TempDir(), "appscope_dev.ps1")
	if err := os.WriteFile(path, []byte(devicesPS), 0o644); err != nil {
		c.SetStatus("unavailable", "cannot write helper script: "+err.Error())
		return
	}
	proc, reader, err := monitor.PopenStream([]string{"powershell.exe", "-NoProfile",
		"-ExecutionPolicy", "Bypass", "-File", path})
	if err != nil {
		c.SetStatus("unavailable", "powershell.exe not found")
		return
	}
	c.registerProc(proc)
	c.SetStatus("active", "PowerShell device snapshot loop")
	for !c.Stopped() {
		line, err := reader.ReadString('\n')
		if err != nil && strings.TrimSpace(line) == "" {
			break
		}
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var data struct {
			USB     []usbEntry `json:"usb"`
			Volumes []volEntry `json:"volumes"`
		}
		if json.Unmarshal([]byte(line), &data) != nil {
			continue
		}
		usb := map[usbKey]bool{}
		for _, d := range data.USB {
			serial := d.Serial
			if serial == "" {
				serial = "-"
			}
			usb[usbKey{d.Name, serial}] = true
		}
		vols := map[string]bool{}
		for _, v := range data.Volumes {
			vols[v.Name] = true
		}
		c.diffUSB(usb)
		c.diffVols(vols)
	}
}

func (c *DevicesCollector) diffVols(current map[string]bool) {
	for vol := range current {
		if !c.vols[vol] {
			c.emitVolume("storage_connect", vol)
		}
	}
	for vol := range c.vols {
		if !current[vol] {
			c.emitVolume("storage_disconnect", vol)
		}
	}
	c.vols = current
}

type usbEntry struct {
	Name   string `json:"name"`
	Serial string `json:"serial"`
}

type volEntry struct {
	Name string `json:"name"`
}

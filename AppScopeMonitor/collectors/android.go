// Android collector: attaches to a connected device over adb.
//
// Collects, per device:
//   - camera use   -- `dumpsys media.camera` open clients (package names)
//   - mic use      -- `dumpsys audio` active players (AudioRecord/started state)
//   - foreground   -- `dumpsys activity activities` resumed activity
//   - per-app data -- `dumpsys netstats` per-uid rx/tx deltas mapped to packages
//
// Requires `adb` on PATH and USB debugging enabled on the device. Runs on any
// host platform; events are tagged with the device serial.
//
// Mirrors collectors/android.py.
package collectors

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"monitor"
)

type usageKey struct{ serial, id string }
type netKey struct {
	serial string
	uid    int
}

var (
	reCameraSplit = regexp.MustCompile(`Camera ID[:=]?\s*\d+|Camera \d+`)
	reCameraOpen  = regexp.MustCompile(`(?i)is open|opened by|active client`)
	reCameraID    = regexp.MustCompile(`[Cc]amera (?:ID[:=]?\s*)?(\d+)`)
	rePkgKv       = regexp.MustCompile(`package[:=]\s*([\w.]+)`)
	rePkgPid      = regexp.MustCompile(`([\w.]+)\s*\(pid\s*\d+\)`)
	rePkgLine     = regexp.MustCompile(`package:\s*([\w.]+)`)
	reStateLine   = regexp.MustCompile(`state:\s*(\w+)`)
	rePiid        = regexp.MustCompile(`piid:\s*(\d+)`)
	reTypeLine    = regexp.MustCompile(`type:\s*([\w.]+)`)
	reRecord      = regexp.MustCompile(`(?i)AudioRecord|record`)
	reUsage       = regexp.MustCompile(`usage:\s*([\w_]+)`)
	reFgActivity  = regexp.MustCompile(`(?:topResumedActivity|ResumedActivity)[:=].*?u0\s+([\w.]+)`)
	reFgFallback  = regexp.MustCompile(`mResumedActivity:.*?u0\s+([\w.]+)`)
	reUid         = regexp.MustCompile(`uid=(\d+)`)
	reRxBytes     = regexp.MustCompile(`rxBytes=(\d+)`)
	reTxBytes     = regexp.MustCompile(`txBytes=(\d+)`)
	rePkgUid      = regexp.MustCompile(`^package:([\w.]+)\s+uid:(\d+)`)
)

// AndroidCollector monitors privacy/traffic on attached adb devices.
type AndroidCollector struct {
	*BaseCollector
	adb      string
	camera   map[usageKey]string       // (serial, camera_id) -> package
	mic      map[usageKey]string       // (serial, piid) -> package
	fg       map[string]string         // serial -> package
	net      map[netKey][2]int64       // (serial, uid) -> (rx, tx)
	pkgCache map[string]map[int]string // serial -> {uid: package}
}

// NewAndroidCollector creates the collector.
func NewAndroidCollector(ctx *monitor.Ctx) *AndroidCollector {
	b := NewBase(ctx, "android-adb", "Android device privacy/traffic via adb", "android")
	c := &AndroidCollector{
		BaseCollector: b,
		adb:           monitor.Which("adb"),
		camera:        map[usageKey]string{},
		mic:           map[usageKey]string{},
		fg:            map[string]string{},
		net:           map[netKey][2]int64{},
		pkgCache:      map[string]map[int]string{},
	}
	b.setRun(c.run)
	return c
}

// Available checks config toggle and adb presence.
func (c *AndroidCollector) Available() (bool, string) {
	mode := strings.ToLower(c.Ctx.GetString("android", "auto"))
	if mode == "false" {
		return false, "disabled in config"
	}
	if c.adb == "" {
		return false, "adb not found on PATH " +
			"(install Android platform-tools to enable)"
	}
	return true, ""
}

func (c *AndroidCollector) run() {
	interval := c.Ctx.Poll("android", 12.0)
	for !c.Stopped() {
		serials := c.devices()
		c.Ctx.SetAndroidDevices(serials)
		if len(serials) > 0 {
			c.SetStatus("active", fmt.Sprintf("devices: %s", strings.Join(serials, ", ")))
			for _, serial := range serials {
				if c.Stopped() {
					break
				}
				c.collect(serial)
			}
		} else {
			c.SetStatus("idle", "adb present, no devices attached")
		}
		c.Sleep(interval)
	}
}

func (c *AndroidCollector) devices() []string {
	_, out, _ := monitor.Run([]string{c.adb, "devices"}, 10*time.Second)
	var serials []string
	lines := strings.Split(out, "\n")
	for _, line := range lines[1:] {
		parts := strings.Fields(line)
		if len(parts) >= 2 && parts[1] == "device" {
			serials = append(serials, parts[0])
		}
	}
	return serials
}

// ---------------------------------------------------------- per device ----

func (c *AndroidCollector) collect(serial string) {
	defer func() {
		if r := recover(); r != nil {
			c.SetStatus("degraded", fmt.Sprintf("%s: %v", serial, r))
		}
	}()
	c.cameraUse(serial)
	c.micUse(serial)
	c.foreground(serial)
	c.netstats(serial)
}

func (c *AndroidCollector) sh(serial, cmd string, timeout time.Duration) string {
	_, out, _ := monitor.Run([]string{c.adb, "-s", serial, "shell", cmd}, timeout)
	return out
}

// camera -------------------------------------------------------------------
func (c *AndroidCollector) cameraUse(serial string) {
	dump := c.sh(serial, "dumpsys media.camera", 15*time.Second)
	current := map[usageKey]string{}
	// Blocks look like "Camera 0 is open. Opened by client: package=..." or
	// "Device 0 is open to client: <pkg> (pid N)" depending on version.
	for _, chunk := range reCameraSplit.Split(dump, -1) {
		if !reCameraOpen.MatchString(chunk) {
			continue
		}
		camID := reCameraID.FindStringSubmatch(chunk)
		pkg := rePkgKv.FindStringSubmatch(chunk)
		if pkg == nil {
			pkg = rePkgPid.FindStringSubmatch(chunk)
		}
		if pkg != nil {
			id := "0"
			if camID != nil {
				id = camID[1]
			}
			current[usageKey{serial, id}] = pkg[1]
		}
	}
	c.diffUsage(c.camera, current, serial, "camera")
}

// microphone ---------------------------------------------------------------
func (c *AndroidCollector) micUse(serial string) {
	dump := c.sh(serial, "dumpsys audio", 15*time.Second)
	current := map[usageKey]string{}
	inPlayers := false
	for _, line := range strings.Split(dump, "\n") {
		if strings.Contains(line, "players:") {
			inPlayers = true
			continue
		}
		if !inPlayers {
			continue
		}
		// Python's `^\s{0,4}\S+(?!:)` + "piid"/":" conditions: any
		// non-"key: value" line ends the players section.
		trimmed := strings.TrimLeft(line, " \t")
		if len(line)-len(trimmed) <= 4 && strings.TrimSpace(line) != "" &&
			!strings.Contains(line, "piid") && !strings.Contains(line, ":") {
			inPlayers = false
			continue
		}
		pkg := rePkgLine.FindStringSubmatch(line)
		state := reStateLine.FindStringSubmatch(line)
		piid := rePiid.FindStringSubmatch(line)
		rtype := reTypeLine.FindStringSubmatch(line)
		if pkg != nil && state != nil && piid != nil && state[1] == "started" {
			isRecord := rtype != nil && reRecord.MatchString(rtype[1])
			usage := reUsage.FindStringSubmatch(line)
			if isRecord || (usage != nil && strings.Contains(
				strings.ToUpper(usage[1]), "VOICECOMMUNICATION")) {
				current[usageKey{serial, piid[1]}] = pkg[1]
			}
		}
	}
	c.diffUsage(c.mic, current, serial, "mic")
}

func (c *AndroidCollector) diffUsage(state, current map[usageKey]string, serial, what string) {
	for key, pkg := range current {
		if state[key] != pkg {
			c.Emit(&monitor.Event{
				Device:   serial,
				Category: "privacy",
				Kind:     what + "_start",
				App:      pkg,
				Detail:   fmt.Sprintf("%s is in use on %s", what, serial),
			})
		}
	}
	for key, pkg := range state {
		if key.serial != serial {
			continue
		}
		if _, still := current[key]; !still {
			c.Emit(&monitor.Event{
				Device:   serial,
				Category: "privacy",
				Kind:     what + "_stop",
				App:      pkg,
				Detail:   fmt.Sprintf("%s stopped on %s", what, serial),
			})
			delete(state, key)
		}
	}
	for key, pkg := range current {
		state[key] = pkg
	}
}

// foreground ----------------------------------------------------------------
func (c *AndroidCollector) foreground(serial string) {
	out := c.sh(serial, "dumpsys activity activities", 15*time.Second)
	m := reFgActivity.FindStringSubmatch(out)
	if m == nil {
		m = reFgFallback.FindStringSubmatch(out)
	}
	if m != nil {
		pkg := strings.Split(m[1], "/")[0]
		if c.fg[serial] != pkg {
			c.fg[serial] = pkg
			c.Emit(&monitor.Event{
				Device:   serial,
				Category: "system",
				Kind:     "app_switch",
				App:      pkg,
				Detail:   fmt.Sprintf("foreground app on %s", serial),
			})
		}
	}
}

// per-app network -------------------------------------------------------------
func (c *AndroidCollector) netstats(serial string) {
	dump := c.sh(serial, "dumpsys netstats", 25*time.Second)
	pkgs := c.pkgMap(serial)
	seenNow := map[netKey][2]int64{}
	for _, line := range strings.Split(dump, "\n") {
		m := reUid.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		uid, _ := strconv.Atoi(m[1])
		if uid < 10000 {
			continue
		}
		rx := reRxBytes.FindStringSubmatch(line)
		tx := reTxBytes.FindStringSubmatch(line)
		if rx == nil || tx == nil {
			continue
		}
		rxN, _ := strconv.ParseInt(rx[1], 10, 64)
		txN, _ := strconv.ParseInt(tx[1], 10, 64)
		seenNow[netKey{serial, uid}] = [2]int64{rxN, txN}
	}
	for key, val := range seenNow {
		rx, tx := val[0], val[1]
		prev, had := c.net[key]
		c.net[key] = val
		if !had {
			continue
		}
		drx := rx - prev[0]
		if drx < 0 {
			drx = 0
		}
		dtx := tx - prev[1]
		if dtx < 0 {
			dtx = 0
		}
		if drx+dtx < 30000 { // ignore tiny chatter
			continue
		}
		pkg := fmt.Sprintf("uid%d", key.uid)
		if p, ok := pkgs[key.uid]; ok {
			pkg = p
		}
		c.Emit(&monitor.Event{
			Device:   serial,
			Category: "network",
			Kind:     "app_traffic",
			App:      pkg,
			Detail: fmt.Sprintf("rx +%s, tx +%s (in last poll interval)",
				monitor.FormatBytes(float64(drx)), monitor.FormatBytes(float64(dtx))),
		})
	}
}

func (c *AndroidCollector) pkgMap(serial string) map[int]string {
	if m, ok := c.pkgCache[serial]; ok {
		return m
	}
	out := c.sh(serial, "pm list packages -U", 20*time.Second)
	mapping := map[int]string{}
	for _, line := range strings.Split(out, "\n") {
		m := rePkgUid.FindStringSubmatch(strings.TrimSpace(line))
		if m != nil {
			uid, _ := strconv.Atoi(m[2])
			mapping[uid] = m[1]
		}
	}
	c.pkgCache[serial] = mapping
	return mapping
}

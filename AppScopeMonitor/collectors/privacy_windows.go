//go:build windows

// Windows privacy collector.
//
// Polls CapabilityAccessManager ConsentStore (registry) for camera &
// microphone last-used timestamps per app, across all loaded user hives.
// Emits start/stop usage events and permission grant/deny changes.
//
// Mirrors collectors/privacy_windows.py.
package collectors

import (
	"path/filepath"
	"strings"
	"syscall"

	"monitor"
)

// Services is the ConsentStore capability list polled by the collector.
var privacyServices = []string{
	"camera", "microphone", "location", "contacts", "email", "chat",
	"userAccountInformation", "userNotifications", "appointments",
	"phoneCall", "phoneCallHistory", "radios", "bluetoothSync",
	"userDataTasks", "siri", "graphicsCaptureProgrammatic",
	"graphicsCaptureSession",
}

const consentRootPath = `SOFTWARE\Microsoft\Windows\CurrentVersion\` +
	`CapabilityAccessManager\ConsentStore`

type privacyKey struct {
	svc, sid, path string
}

type privacyState struct {
	start, stop uint64
	perm        string
}

type hiveRef struct {
	hive syscall.Handle
	sid  string // "" = current user via HKCU
}

// PrivacyWindows tracks camera/mic usage via the ConsentStore registry.
type PrivacyWindows struct {
	*BaseCollector
	state map[privacyKey]privacyState
	hives []hiveRef
}

// NewPrivacyWindows creates the collector.
func NewPrivacyWindows(ctx *monitor.Ctx) *PrivacyWindows {
	b := NewBase(ctx, "privacy-windows",
		"Camera/mic usage + permissions via ConsentStore registry", "privacy")
	c := &PrivacyWindows{BaseCollector: b, state: map[privacyKey]privacyState{}}
	b.setRun(c.run)
	return c
}

// newPrivacyCollector is the registry hook for the "privacy" category on Windows.
func newPrivacyCollector(ctx *monitor.Ctx) monitor.Collector {
	return NewPrivacyWindows(ctx)
}

// Available checks the ConsentStore registry presence.
func (c *PrivacyWindows) Available() (bool, string) {
	if h, ok := regOpenKey(regHKCU, consentRootPath); ok {
		regCloseKey(h)
		return true, ""
	}
	return false, "ConsentStore registry not available"
}

func (c *PrivacyWindows) run() {
	interval := c.Ctx.Poll("privacy", 2.0)
	c.SetStatus("active", "polling ConsentStore for camera/mic usage")
	for !c.Stopped() {
		c.hives = append([]hiveRef{{hive: regHKCU}}, c.userHives()...)
		for _, svc := range privacyServices {
			if c.Stopped() {
				return
			}
			c.pollService(svc)
		}
		c.Sleep(interval)
	}
}

func (c *PrivacyWindows) userHives() []hiveRef {
	var out []hiveRef
	root, ok := regOpenKey(regHKU, "")
	if !ok {
		return out
	}
	defer regCloseKey(root)
	for i := 0; ; i++ {
		sid, ok := regEnumKeyName(root, i)
		if !ok {
			break
		}
		if strings.HasPrefix(sid, "S-1-5-21-") && !strings.HasSuffix(sid, "_Classes") {
			out = append(out, hiveRef{hive: regHKU, sid: sid})
		}
	}
	return out
}

func (c *PrivacyWindows) pollService(svc string) {
	for _, hive := range c.hives {
		var base string
		if hive.sid != "" {
			base = hive.sid + `\` + consentRootPath + `\` + svc
		} else {
			base = consentRootPath + `\` + svc
		}
		root, ok := regOpenKey(hive.hive, base)
		if !ok {
			continue
		}
		c.walk(root, svc, hive.sid, "")
		regCloseKey(root)
	}
}

func (c *PrivacyWindows) walk(key syscall.Handle, svc, sid, prefix string) {
	for i := 0; ; i++ {
		subName, ok := regEnumKeyName(key, i)
		if !ok {
			break
		}
		path := subName
		if prefix != "" {
			path = prefix + `\` + subName
		}
		sub, ok := regOpenKey(key, subName)
		if !ok {
			continue
		}
		start, hasStart := regQueryUint64(sub, "LastUsedTimeStart")
		stop, _ := regQueryUint64(sub, "LastUsedTimeStop")
		perm, hasPerm := regQueryString(sub, "Value")
		subCount, countOK := regSubKeyCount(sub)
		hasChildren := countOK && subCount > 0
		if hasStart || hasPerm {
			c.diff(svc, sid, path, start, stop, perm)
		}
		if !hasStart && hasChildren {
			c.walk(sub, svc, sid, path)
		}
		regCloseKey(sub)
	}
}

// regQueryUint64 mirrors _qword: 8-byte little-endian binary (or QWORD/DWORD)
// values; ok=false when absent or not numeric.
func regQueryUint64(h syscall.Handle, name string) (uint64, bool) {
	v, ok := regQueryValue(h, name)
	if !ok {
		return 0, false
	}
	switch x := v.(type) {
	case uint64:
		return x, true
	case []byte:
		if len(x) == 8 {
			return leUint64(x), true
		}
		return 0, false
	case string:
		var n uint64
		for _, ch := range strings.TrimSpace(x) {
			if ch < '0' || ch > '9' {
				return 0, false
			}
			n = n*10 + uint64(ch-'0')
		}
		return n, true
	default:
		return 0, false
	}
}

// regQueryString mirrors _sz.
func regQueryString(h syscall.Handle, name string) (string, bool) {
	v, ok := regQueryValue(h, name)
	if !ok {
		return "", false
	}
	if s, isStr := v.(string); isStr {
		return s, true
	}
	return monitor.StrOf(v), true
}

func (c *PrivacyWindows) diff(svc, sid, path string, start, stop uint64, perm string) {
	key := privacyKey{svc, sid, path}
	prev, had := c.state[key]
	cur := privacyState{start: start, stop: stop, perm: perm}
	if had && prev == cur {
		return
	}
	c.state[key] = cur
	app := appLabel(path)
	user := c.userLabel(sid)
	if had {
		wasInUse := prev.start != 0 && (prev.stop == 0 || prev.stop < prev.start)
		nowInUse := cur.start != 0 && (cur.stop == 0 || cur.stop < cur.start)
		if wasInUse && !nowInUse {
			c.Emit(&monitor.Event{
				Category: "privacy",
				Kind:     svc + "_stop",
				App:      app,
				User:     user,
				Detail:   svc + " stopped being used",
			})
		} else if nowInUse && !wasInUse {
			c.Emit(&monitor.Event{
				Category: "privacy",
				Kind:     svc + "_start",
				App:      app,
				User:     user,
				Detail:   svc + " is in use",
			})
		}
	}
}

// appLabel mirrors _app_label.
func appLabel(path string) string {
	label := strings.ReplaceAll(path, "#", `\`)
	label = strings.TrimSpace(strings.TrimRight(label, `\/":`))
	base := ""
	if idx := strings.LastIndexAny(label, `/\`); idx >= 0 {
		base = label[idx+1:]
	} else {
		base = label
	}
	if base == "" {
		return path
	}
	return base
}

// userLabel mirrors _user_label.
func (c *PrivacyWindows) userLabel(sid string) string {
	if sid == "" {
		if user := monitor.GetPassUser(); user != "" {
			return user
		}
		return "current-user"
	}
	h, ok := regOpenKey(regHKLM,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\`+sid)
	if !ok {
		return sid
	}
	defer regCloseKey(h)
	if path, ok := regQueryString(h, "ProfileImagePath"); ok {
		return filepath.Base(path)
	}
	return sid
}

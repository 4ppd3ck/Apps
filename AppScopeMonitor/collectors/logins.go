// Login session collector: detects user logins / logouts.
//
//   - macOS / Linux: `who` diff (console + remote tty sessions)
//   - Windows: `quser` diff, with a CIM fallback for editions that
//     ship without quser.exe (then only the console user is tracked)
//
// Mirrors collectors/logins.py.
package collectors

import (
	"regexp"
	"runtime"
	"strings"
	"time"

	"monitor"
)

var reSpaces2 = regexp.MustCompile(`\s{2,}`)

type sessionKey struct{ user, tty string }

// LoginsCollector watches user login/logout sessions.
type LoginsCollector struct {
	*BaseCollector
	sessions map[sessionKey]bool
	Mode     string // "quser" or "cim" (Home editions without quser.exe)
}

// NewLoginsCollector creates the collector.
func NewLoginsCollector(ctx *monitor.Ctx) *LoginsCollector {
	b := NewBase(ctx, "logins", "User login / logout sessions", "logins")
	c := &LoginsCollector{BaseCollector: b, sessions: map[sessionKey]bool{}, Mode: "quser"}
	b.setRun(c.run)
	return c
}

// Available probes quser / CIM on Windows.
func (c *LoginsCollector) Available() (bool, string) {
	if runtime.GOOS == "windows" {
		rc, _, _ := monitor.Run([]string{"quser"}, 10*time.Second)
		if rc == 0 {
			c.Mode = "quser"
			return true, ""
		}
		// Home editions ship without quser.exe -- fall back to CIM
		rc, _, _ = monitor.Run([]string{"powershell.exe", "-NoProfile", "-Command",
			"(Get-CimInstance Win32_ComputerSystem).UserName"}, 20*time.Second)
		if rc == 0 {
			c.Mode = "cim"
			return true, "degraded: quser missing, using CIM console user"
		}
		return false, "quser not available and CIM query failed"
	}
	return true, ""
}

func (c *LoginsCollector) run() {
	interval := c.Ctx.Poll("logins", 5.0)
	c.SetStatus("active", "")
	for !c.Stopped() {
		var current map[sessionKey]bool
		if runtime.GOOS == "windows" && c.Mode == "cim" {
			current = sessionsCIM()
		} else if runtime.GOOS == "windows" {
			current = sessionsWindows()
		} else {
			current = sessionsWho()
		}
		for key := range current {
			if !c.sessions[key] {
				c.Emit(&monitor.Event{
					Category: "logins",
					Kind:     "session_login",
					User:     key.user,
					Detail:   "session started (" + key.tty + ")",
				})
			}
		}
		for key := range c.sessions {
			if !current[key] {
				c.Emit(&monitor.Event{
					Category: "logins",
					Kind:     "session_logout",
					User:     key.user,
					Detail:   "session ended (" + key.tty + ")",
				})
			}
		}
		c.sessions = current
		c.Sleep(interval)
	}
}

func sessionsWho() map[sessionKey]bool {
	_, out, _ := monitor.Run([]string{"who"}, 5*time.Second)
	sessions := map[sessionKey]bool{}
	for _, line := range strings.Split(out, "\n") {
		parts := strings.Fields(line)
		if len(parts) >= 2 && parts[0] != "" && parts[1] != "" {
			sessions[sessionKey{parts[0], parts[1]}] = true
		}
	}
	return sessions
}

func sessionsCIM() map[sessionKey]bool {
	_, out, _ := monitor.Run([]string{"powershell.exe", "-NoProfile", "-Command",
		"(Get-CimInstance Win32_ComputerSystem).UserName"}, 20*time.Second)
	user := strings.TrimSpace(out)
	sessions := map[sessionKey]bool{}
	if user != "" {
		sessions[sessionKey{lastBackslashSegment(user), "console"}] = true
	}
	return sessions
}

func sessionsWindows() map[sessionKey]bool {
	rc, out, _ := monitor.Run([]string{"quser"}, 10*time.Second)
	sessions := map[sessionKey]bool{}
	if rc != 0 {
		return sessions
	}
	for _, line := range strings.Split(out, "\n") {
		parts := reSpaces2.Split(strings.TrimSpace(line), -1)
		if len(parts) >= 3 {
			lower := strings.ToLower(parts[0])
			if lower == "username" || lower == "" {
				continue
			}
			user := strings.TrimLeft(parts[0], ">")
			user = lastBackslashSegment(user)
			tty := "console"
			if len(parts) > 1 {
				tty = parts[1]
			}
			sessions[sessionKey{user, tty}] = true
		}
	}
	return sessions
}

func lastBackslashSegment(s string) string {
	if idx := strings.LastIndex(s, "\\"); idx >= 0 {
		return s[idx+1:]
	}
	return s
}

// Foreground app tracker: emits app_switch events when the frontmost app
// changes.
//
//   - macOS:   `lsappinfo front` + `lsappinfo info -only name <ASN>`
//     (the name is parsed from the dump output; see parseLsAppName)
//   - Windows: PowerShell GetForegroundWindow loop
//   - Linux:   xdotool (X11) if installed, otherwise unavailable
//
// Mirrors collectors/appfocus.py.
package collectors

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"monitor"
)

var (
	reLsQuotedToken = regexp.MustCompile(`"([^"]*)"`)
	reLsNameKV      = regexp.MustCompile(`name="?([^"\n]+)"?`)
)

// parseLsAppName extracts the front app name from `lsappinfo info -only
// name <ASN>` output. Current macOS builds ignore the `-only name` filter
// and dump the full app record, so only the first line is considered: its
// first double-quoted token is the app name (`"AppName" ASN:0x0-0xNNNN:
// (in front)`). Older builds print a one-liner `name="AppName"` instead.
// Returns "" when nothing matches, when the first line is empty, or when
// lsappinfo reported the `[ NULL ]` placeholder it uses for apps without
// LaunchServices attributes.
func parseLsAppName(out string) string {
	first := out
	if i := strings.IndexByte(first, '\n'); i >= 0 {
		first = first[:i]
	}
	first = strings.TrimSpace(first)
	if first == "" {
		return ""
	}
	name := ""
	if m := reLsQuotedToken.FindStringSubmatch(first); m != nil {
		name = m[1]
	} else if m := reLsNameKV.FindStringSubmatch(first); m != nil {
		name = strings.Trim(strings.TrimSpace(m[1]), `"`)
	}
	if name == "" || name == "[ NULL ]" {
		return ""
	}
	return name
}

// focusScript is the persistent PowerShell that prints the focused process
// name whenever it changes.
const focusScript = `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type @"
using System; using System.Runtime.InteropServices; using System.Text;
public class FG {
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
}
"@
$last = ''
while ($true) {
  $h = [FG]::GetForegroundWindow()
  $pid2 = 0
  [FG]::GetWindowThreadProcessId($h, [ref]$pid2) | Out-Null
  $n = ''
  if ($pid2 -gt 0) {
    $p = Get-Process -Id $pid2 -ErrorAction SilentlyContinue
    if ($p) { $n = $p.ProcessName }
  }
  if ($n -and $n -ne $last) { $last = $n; Write-Output $n; [Console]::Out.Flush() }
  Start-Sleep -Milliseconds 500
}
`

// AppFocusCollector tracks foreground app switches.
type AppFocusCollector struct {
	*BaseCollector
	current    string
	psCmd      *exec.Cmd
	psReader   *bufio.Reader
	psSpawnErr bool
}

// NewAppFocusCollector creates the collector.
func NewAppFocusCollector(ctx *monitor.Ctx) *AppFocusCollector {
	b := NewBase(ctx, "appfocus", "Foreground app switches", "appfocus")
	c := &AppFocusCollector{BaseCollector: b}
	b.setRun(c.run)
	return c
}

// Available checks for the platform helper.
func (c *AppFocusCollector) Available() (bool, string) {
	switch runtime.GOOS {
	case "darwin":
		rc, _, _ := monitor.Run([]string{"lsappinfo", "help"}, 5*time.Second)
		if rc == 0 {
			return true, ""
		}
		return false, "lsappinfo not found"
	case "windows":
		return true, ""
	default:
		if monitor.Which("xdotool") != "" {
			return true, ""
		}
		return false, "xdotool not installed (X11 only)"
	}
}

func (c *AppFocusCollector) run() {
	interval := c.Ctx.Poll("appfocus", 2.0)
	c.SetStatus("active", "")
	for !c.Stopped() {
		app := ""
		func() {
			defer func() { _ = recover() }() // Python: except Exception: pass
			app = c.frontApp()
		}()
		if app != "" && app != c.current {
			prev := c.current
			c.current = app
			c.Emit(&monitor.Event{
				Category: "system",
				Kind:     "app_switch",
				App:      app,
				User:     monitor.GetPassUser(),
				Detail:   fmtDetailForeground(prev, app),
			})
		}
		c.Sleep(interval)
	}
}

func fmtDetailForeground(prev, app string) string {
	if prev == "" {
		prev = "(start)"
	}
	return "foreground: " + prev + " → " + app
}

func (c *AppFocusCollector) frontApp() string {
	switch runtime.GOOS {
	case "darwin":
		rc, asn, _ := monitor.Run([]string{"lsappinfo", "front"}, 5*time.Second)
		if rc != 0 || !strings.HasPrefix(asn, "ASN:") {
			return ""
		}
		rc, out, _ := monitor.Run([]string{"lsappinfo", "info", "-only", "name",
			strings.TrimSpace(asn)}, 5*time.Second)
		if rc != 0 {
			return ""
		}
		return parseLsAppName(out)
	case "windows":
		return c.frontAppWindows()
	default:
		rc, out, _ := monitor.Run([]string{"xdotool", "getactivewindow",
			"getwindowname"}, 5*time.Second)
		out = strings.TrimSpace(out)
		if rc == 0 && out != "" {
			return out
		}
		return ""
	}
}

// frontAppWindows reads the next process name printed by the persistent
// PowerShell helper (spawned on first use); falls back to nothing when the
// helper is gone.
func (c *AppFocusCollector) frontAppWindows() string {
	if c.psCmd == nil {
		if c.psSpawnErr {
			return ""
		}
		path := filepath.Join(os.TempDir(), "appscope_focus.ps1")
		if err := os.WriteFile(path, []byte(focusScript), 0o644); err != nil {
			c.psSpawnErr = true
			return ""
		}
		cmd, reader, err := monitor.PopenStream([]string{"powershell.exe",
			"-NoProfile", "-ExecutionPolicy", "Bypass", "-File", path})
		if err != nil {
			c.psSpawnErr = true
			return ""
		}
		c.psCmd, c.psReader = cmd, reader
		c.registerProc(cmd)
	}
	line, err := c.psReader.ReadString('\n')
	if err != nil && strings.TrimSpace(line) == "" {
		return ""
	}
	out := strings.TrimSpace(line)
	if out == "" {
		return ""
	}
	return out
}

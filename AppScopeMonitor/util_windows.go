//go:build windows

// Windows stub for the unix user helpers: there is no uid -> username
// mapping in the win32 build (Python has the same gap: `import pwd` fails).
package monitor

import (
	"os"
	"strconv"
	"syscall"
)

// UsernameForUID returns the uid as its string form.
func UsernameForUID(uid int) string { return strconv.Itoa(uid) }

// streamProcAttr: no unix process groups on Windows (JobObject semantics
// are not needed -- the collectors' children die with the parent kill).
func streamProcAttr() *syscall.SysProcAttr { return nil }

// KillCmdGroup: Windows has no killpg and only Kill is widely supported by
// os.Process.Signal, so the signal argument is best-effort and the process
// is killed outright (the collectors' streamed child is the process itself).
func KillCmdGroup(p *os.Process, _ syscall.Signal) error {
	if p == nil {
		return nil
	}
	return p.Kill()
}

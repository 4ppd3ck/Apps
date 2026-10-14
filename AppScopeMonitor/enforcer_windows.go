//go:build windows

// Elevation check on Windows: Shell32.IsUserAnAdmin, the same API the Python
// code reaches for via ctypes (monitor/enforcer.py _is_admin).
package monitor

import "syscall"

var (
	shell32           = syscall.NewLazyDLL("shell32.dll")
	procIsUserAnAdmin = shell32.NewProc("IsUserAnAdmin")
)

func isElevated() bool {
	r1, _, _ := procIsUserAnAdmin.Call()
	return r1 != 0
}

//go:build !windows

// Elevation check on unix: euid == 0 (monitor/enforcer.py _is_admin).
package monitor

import "os"

func isElevated() bool {
	return os.Geteuid() == 0
}

//go:build !windows

// Elevation check on unix: euid == 0 (monitor/enforcer.py _is_admin).
// The Windows broker queue has no unix counterpart -- enforcement goes
// through the sudo/pkexec helper scripts instead.
package monitor

import (
	"errors"
	"os"
)

func isElevated() bool {
	return os.Geteuid() == 0
}

func brokerReady() bool {
	return false
}

func brokerEnqueue(line string) error {
	return errors.New("no broker task on this platform")
}

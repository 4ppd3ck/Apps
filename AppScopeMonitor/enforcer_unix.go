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

// cidrWindows is the Windows-only CIDR enforcement path; unix country and
// list rules go through countryHelper/listHelper/ipsetCIDRRules instead.
func (e *Enforcer) cidrWindows(rule *Block, add bool) (string, string) {
	return "error", "CIDR blocking via the Windows broker is unavailable on this platform"
}

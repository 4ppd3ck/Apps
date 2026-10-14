//go:build !windows && !linux && !darwin

// Fallback platform collectors for the remaining Unixes (FreeBSD, NetBSD,
// OpenBSD, ...), where privacy/files/network have no native implementation.
// They register under the usual categories so the config toggles and the
// dashboard keep working, and report "unavailable" with the reason shown in
// the status table. Everything portable still runs unchanged on these
// systems: vitals (battery/CPU/RAM/disks via statVolume below), devices,
// logins, appfocus (xdotool/X11), android, events, dashboard, store, and
// block-rule queueing.
package collectors

import (
	"monitor"
)

// UnsupportedCollector is a category placeholder for platforms without a
// native implementation of that collector. Available() is false, so startup
// and the dashboard toggle mark it "unavailable" instead of starting it.
type UnsupportedCollector struct {
	*BaseCollector
	reason string
}

// Available always reports unavailable with the platform reason.
func (c *UnsupportedCollector) Available() (bool, string) {
	return false, c.reason
}

func newUnsupported(ctx *monitor.Ctx, name, category, reason string) *UnsupportedCollector {
	b := NewBase(ctx, name, reason, category)
	c := &UnsupportedCollector{BaseCollector: b, reason: reason}
	b.setRun(func() {
		// never reached (Available=false gates Start); kept as a safety net
		for !c.Stopped() {
			c.Sleep(3600)
		}
	})
	return c
}

// Registry hooks for platforms without a native collector set.

func newPrivacyCollector(ctx *monitor.Ctx) monitor.Collector {
	return newUnsupported(ctx, "privacy", "privacy",
		"camera/mic in-use detection is implemented for Windows, macOS and Linux only")
}

func newFilesCollector(ctx *monitor.Ctx) monitor.Collector {
	return newUnsupported(ctx, "files", "files",
		"file-access events are implemented for Windows, macOS and Linux only")
}

func newNetworkCollector(ctx *monitor.Ctx) monitor.Collector {
	return newUnsupported(ctx, "network", "network",
		"connection tracking is implemented for Windows, macOS and Linux only")
}

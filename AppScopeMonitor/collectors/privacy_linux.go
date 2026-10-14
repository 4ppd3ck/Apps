//go:build linux

// Linux privacy collector: camera/microphone *in use* detection.
//
// Scans /proc for processes holding open video capture devices (/dev/video*)
// and capture-capable ALSA pcm devices (/dev/snd/pcmC* D* c). Emits
// camera/mic start/stop events with the owning process and uid.
//
// Mirrors collectors/privacy_linux.py.
package collectors

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"monitor"
)

var (
	videoRe   = regexp.MustCompile(`^/dev/video\d+$`)
	captureRe = regexp.MustCompile(`^/dev/snd/pcmC\d+D\d+c$`)
)

type privacyScanKey struct {
	kind string
	pid  int
}

type privacyScanInfo struct {
	dev  string
	comm string
	uid  int
	seen float64
}

// PrivacyLinux watches /dev/video* and ALSA capture devices via /proc.
type PrivacyLinux struct {
	*BaseCollector
}

// NewPrivacyLinux creates the collector.
func NewPrivacyLinux(ctx *monitor.Ctx) *PrivacyLinux {
	b := NewBase(ctx, "privacy-linux", "Camera/mic in-use via /proc device fd scan",
		"privacy")
	c := &PrivacyLinux{BaseCollector: b}
	b.setRun(c.run)
	return c
}

// newPrivacyCollector is the registry hook for the "privacy" category on Linux.
func newPrivacyCollector(ctx *monitor.Ctx) monitor.Collector {
	return NewPrivacyLinux(ctx)
}

// Available checks /proc.
func (c *PrivacyLinux) Available() (bool, string) {
	if fi, err := os.Stat("/proc"); err == nil && fi.IsDir() {
		return true, ""
	}
	return false, "/proc not available"
}

func (c *PrivacyLinux) run() {
	interval := c.Ctx.Poll("privacy", 2.0)
	active := map[privacyScanKey]privacyScanInfo{}
	c.SetStatus("active", "watching /dev/video* and /dev/snd capture devices")
	for !c.Stopped() {
		found := c.scan()
		for key, dev := range found {
			if _, was := active[key]; !was {
				c.emitUsage(key.kind+"_start", key.pid, dev)
			}
		}
		for key, info := range active {
			if _, still := found[key]; !still {
				c.emitUsage(key.kind+"_stop", key.pid, info)
			}
		}
		active = found
		c.Sleep(interval)
	}
}

func (c *PrivacyLinux) scan() map[privacyScanKey]privacyScanInfo {
	found := map[privacyScanKey]privacyScanInfo{}
	now := monitor.Now()
	pidDirs, _ := os.ReadDir("/proc")
	for _, entry := range pidDirs {
		if !isAllDigits(entry.Name()) {
			continue
		}
		pid, _ := strconv.Atoi(entry.Name())
		procDir := filepath.Join("/proc", entry.Name())
		fds, err := os.ReadDir(filepath.Join(procDir, "fd"))
		if err != nil {
			continue
		}
		uid := -1
		if st, err := os.Stat(procDir); err == nil {
			if sys, ok := st.Sys().(*syscall.Stat_t); ok {
				uid = int(sys.Uid)
			}
		}
		commRaw, err := os.ReadFile(filepath.Join(procDir, "comm"))
		if err != nil {
			continue
		}
		comm := strings.TrimSpace(string(commRaw))
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(procDir, "fd", fd.Name()))
			if err != nil {
				continue
			}
			var kind string
			if videoRe.MatchString(target) {
				kind = "camera"
			} else if captureRe.MatchString(target) {
				kind = "mic"
			} else {
				continue
			}
			// systemd-resolved style services may hold devices momentarily
			key := privacyScanKey{kind, pid}
			if _, exists := found[key]; !exists {
				found[key] = privacyScanInfo{target, comm, uid, now}
			}
			break
		}
	}
	return found
}

func (c *PrivacyLinux) emitUsage(kind string, pid int, info privacyScanInfo) {
	var userVal any
	if info.uid >= 0 {
		userVal = monitor.UsernameForUID(info.uid)
	}
	base := strings.Split(kind, "_")[0]
	c.Emit(&monitor.Event{
		Category: "privacy",
		Kind:     kind,
		App:      info.comm,
		Pid:      pid,
		User:     userVal,
		Path:     info.dev,
		Detail:   base + " device in use: " + info.dev,
	})
}

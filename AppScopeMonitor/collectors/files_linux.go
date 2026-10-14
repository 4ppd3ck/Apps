//go:build linux

// Linux file access collector.
//
// Preferred mode (root + auditd): adds auditd watches on configured dirs and
// parses audit records -- gives full attribution (uid, exe, pid, file,
// result).
//
// Fallback mode (no root): polls /proc for processes holding open files under
// the watched directories (catches long-lived opens only).
//
// Mirrors collectors/files_linux.py.
package collectors

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"monitor"
)

var sysCalls = map[string]string{
	"open": "file_open", "openat": "file_open", "openat2": "file_open",
	"creat": "file_create", "mkdir": "file_create", "mkdirat": "file_create",
	"rename": "file_move", "renameat": "file_move", "renameat2": "file_move",
	"unlink": "file_delete", "unlinkat": "file_delete", "rmdir": "file_delete",
}

var (
	reSerialAudit = regexp.MustCompile(`msg=audit\(([\d.]+):(\d+)\):`)
	reAuditField  = map[string]*regexp.Regexp{
		"syscall": regexp.MustCompile(`syscall=(\w+)`),
		"success": regexp.MustCompile(`success=(\w+)`),
		"uid":     regexp.MustCompile(`\buid=(\d+)`),
		"pid":     regexp.MustCompile(`\bpid=(\d+)`),
		"comm":    regexp.MustCompile(`comm="([^"]*)"`),
		"exe":     regexp.MustCompile(`exe="([^"]*)"`),
		"name":    regexp.MustCompile(`name="([^"]*)"`),
	}
)

type auditFields struct {
	syscall, success, uid, pid, comm, exe string
}

// FilesLinux watches file access on Linux.
type FilesLinux struct {
	*BaseCollector
	Mode string // "auditd" or "proc"
}

// NewFilesLinux creates the collector.
func NewFilesLinux(ctx *monitor.Ctx) *FilesLinux {
	b := NewBase(ctx, "files-linux", "File access via auditd (root) or /proc polling",
		"files")
	c := &FilesLinux{BaseCollector: b}
	b.setRun(c.run)
	return c
}

// newFilesCollector is the registry hook for the "files" category on Linux.
func newFilesCollector(ctx *monitor.Ctx) monitor.Collector { return NewFilesLinux(ctx) }

// Available picks the auditd or /proc mode.
func (c *FilesLinux) Available() (bool, string) {
	if os.Geteuid() == 0 {
		if _, err := os.Stat("/sbin/auditctl"); err == nil {
			rc, out, errOut := monitor.Run([]string{"/sbin/auditctl", "-l"}, 5*time.Second)
			if rc == 0 || strings.Contains(out+errOut, "No rule") {
				c.Mode = "auditd"
				return true, ""
			}
		}
	}
	if fi, err := os.Stat("/proc"); err == nil && fi.IsDir() {
		c.Mode = "proc"
		if os.Geteuid() != 0 {
			return true, "degraded: /proc polling without per-syscall " +
				"coverage (run with sudo + auditd for full detail)"
		}
		return true, "degraded: auditd not found, using /proc polling"
	}
	return false, "neither auditd nor /proc available"
}

func (c *FilesLinux) run() {
	if c.Mode == "auditd" {
		c.runAuditd()
	} else {
		c.runProc()
	}
}

// ------------------------------------------------------------ auditd ----

func (c *FilesLinux) runAuditd() {
	watched := c.Ctx.WatchedDirs()
	for _, d := range watched {
		monitor.Run([]string{"/sbin/auditctl", "-w", d, "-p", "rwxa", "-k",
			"appscope"}, 5*time.Second)
	}
	c.SetStatus("active", "auditd watches on "+strconv.Itoa(len(watched))+" dirs")
	var sources [][]string
	if _, err := os.Stat("/var/log/audit/audit.log"); err == nil {
		sources = append(sources, []string{"tail", "-n", "0", "-F",
			"/var/log/audit/audit.log"})
	} else if rc, _, _ := monitor.Run([]string{"sh", "-c", "command -v journalctl"},
		3*time.Second); rc == 0 {
		sources = append(sources, []string{"journalctl", "-f", "-g", "appscope",
			"-o", "short"})
	}
	if len(sources) == 0 {
		c.SetStatus("degraded", "no audit log source found")
		return
	}
	pending := map[string]auditFields{}
	proc, reader, err := monitor.PopenStream(sources[0])
	if err != nil {
		c.SetStatus("degraded", "cannot start audit log reader")
		return
	}
	c.registerProc(proc)
	for {
		line, readErr := reader.ReadString('\n')
		c.parseAudit(strings.TrimRight(line, "\n"), pending)
		if readErr != nil || c.Stopped() {
			break
		}
	}
	_ = proc.Wait() // reap the stream child (audit reader died or was stopped)
}

func (c *FilesLinux) parseAudit(line string, pending map[string]auditFields) {
	if !strings.Contains(line, "appscope") {
		return
	}
	mserial := reSerialAudit.FindStringSubmatch(line)
	if mserial == nil {
		return
	}
	serial := mserial[2]
	rtype := ""
	if strings.Contains(line, "type=SYSCALL") {
		rtype = "SYSCALL"
	} else if strings.Contains(line, "type=PATH") {
		rtype = "PATH"
	}
	switch rtype {
	case "SYSCALL":
		var f auditFields
		for _, k := range []string{"syscall", "success", "uid", "pid", "comm", "exe"} {
			if m := reAuditField[k].FindStringSubmatch(line); m != nil {
				switch k {
				case "syscall":
					f.syscall = m[1]
				case "success":
					f.success = m[1]
				case "uid":
					f.uid = m[1]
				case "pid":
					f.pid = m[1]
				case "comm":
					f.comm = m[1]
				case "exe":
					f.exe = m[1]
				}
			}
		}
		pending[serial] = f
		if len(pending) > 4096 {
			dropped := 0
			for old := range pending {
				if dropped >= 2048 {
					break
				}
				delete(pending, old)
				dropped++
			}
		}
		// some syscalls embed the name directly
		if nm := reAuditField["name"].FindStringSubmatch(line); nm != nil {
			c.emitFile(f, nm[1])
		}
	case "PATH":
		f, ok := pending[serial]
		if !ok {
			return
		}
		if nm := reAuditField["name"].FindStringSubmatch(line); nm != nil &&
			strings.HasPrefix(nm[1], "/") {
			c.emitFile(f, nm[1])
			delete(pending, serial)
		}
	}
}

func (c *FilesLinux) emitFile(f auditFields, name string) {
	kind, ok := sysCalls[f.syscall]
	if !ok {
		return
	}
	var pidVal any
	if isAllDigits(f.pid) {
		pidVal, _ = strconv.Atoi(f.pid)
	}
	var userVal any
	if isAllDigits(f.uid) {
		if n, err := strconv.Atoi(f.uid); err == nil {
			userVal = monitor.UsernameForUID(n)
		}
	}
	app := f.exe
	if app == "" {
		app = f.comm
	}
	if app == "" {
		app = "?"
	}
	c.Emit(&monitor.Event{
		Category: "file",
		Kind:     kind,
		App:      app,
		Pid:      pidVal,
		User:     userVal,
		Path:     name,
		Detail:   f.syscall + " success=" + f.success,
	})
}

// -------------------------------------------------------------- proc ----

func (c *FilesLinux) runProc() {
	interval := c.Ctx.Poll("files", 2.0)
	watched := c.Ctx.WatchedDirs()
	type openKey struct {
		pid    int
		target string
	}
	seen := map[openKey]bool{}
	c.SetStatus("active", "/proc poll for open files in "+
		strconv.Itoa(len(watched))+" dirs")
	for !c.Stopped() {
		found := map[openKey]bool{}
		pidDirs, _ := os.ReadDir("/proc")
		for _, entry := range pidDirs {
			if !isAllDigits(entry.Name()) {
				continue
			}
			pid, _ := strconv.Atoi(entry.Name())
			procDir := filepath.Join("/proc", entry.Name())
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
			fds, err := os.ReadDir(filepath.Join(procDir, "fd"))
			if err != nil {
				continue
			}
			for _, fd := range fds {
				target, err := os.Readlink(filepath.Join(procDir, "fd", fd.Name()))
				if err != nil {
					continue
				}
				if !strings.HasPrefix(target, "/") ||
					strings.HasPrefix(target, "/dev/") ||
					strings.HasPrefix(target, "/proc/") ||
					strings.HasPrefix(target, "/sys/") ||
					strings.HasPrefix(target, "/tmp/") ||
					strings.HasPrefix(target, "/run/") {
					continue
				}
				if len(watched) > 0 && startsWithAny(target, watched) {
					key := openKey{pid, target}
					found[key] = true
					if !seen[key] {
						var userVal any
						if uid >= 0 {
							userVal = monitor.UsernameForUID(uid)
						}
						c.Emit(&monitor.Event{
							Category: "file",
							Kind:     "file_open",
							App:      comm,
							Pid:      pid,
							User:     userVal,
							Path:     target,
							Detail:   "file held open (poll)",
						})
					}
				}
			}
		}
		seen = found
		c.Sleep(interval)
	}
}

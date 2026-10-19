//go:build darwin

// macOS file access collector via `fs_usage`.
//
// SIP allows fs_usage only for root, so this collector runs it either
// directly (when the monitor itself runs as root) or through passwordless
// sudo (`sudo -n /usr/bin/fs_usage`) when a sudoers grant exists -- see
// scripts/grant_files_macos.sh. Without either, it reports unavailable with
// the exact remediation.
//
// Mirrors collectors/files_macos.py.
package collectors

import (
	"bytes"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"monitor"
)

var callKinds = map[string]string{
	"open": "file_open", "openat": "file_open", "open_nocancel": "file_open",
	"open_extended": "file_open",
	"create":        "file_create", "mkdir": "file_create", "mkdirat": "file_create",
	"rename": "file_move", "renamex_np": "file_move", "renameat": "file_move",
	"unlink": "file_delete", "unlinkat": "file_delete", "rmdir": "file_delete",
	"delete": "file_delete",
}

var pidToken = regexp.MustCompile(`^(\d+)\.\d+$`)

const fsUsagePath = "/usr/bin/fs_usage"

// FilesMacOS traces per-process file access via fs_usage.
type FilesMacOS struct {
	*BaseCollector
	dedup    map[dedupKey]float64
	budgetTs float64
	budget   int
	Mode     string // "direct" (euid 0) | "sudo"
}

type dedupKey struct {
	pid  int
	kind string
	path string
}

// NewFilesMacOS creates the collector.
func NewFilesMacOS(ctx *monitor.Ctx) *FilesMacOS {
	b := NewBase(ctx, "files-macos", "Per-process file access via fs_usage", "files")
	c := &FilesMacOS{BaseCollector: b, dedup: map[dedupKey]float64{}, Mode: "direct"}
	b.setRun(c.run)
	return c
}

// newFilesCollector is the registry hook for the "files" category on darwin.
func newFilesCollector(ctx *monitor.Ctx) monitor.Collector { return NewFilesMacOS(ctx) }

// Available probes fs_usage + privilege.
func (c *FilesMacOS) Available() (bool, string) {
	if _, err := os.Stat(fsUsagePath); err != nil {
		return false, "fs_usage not found"
	}
	if os.Geteuid() == 0 {
		c.Mode = "direct"
		return true, ""
	}
	ok, why := c.sudoProbe()
	if ok {
		c.Mode = "sudo"
		return true, ""
	}
	if why == "password" {
		return false, "needs root: click Grant on this chip (installs a " +
			"read-only fs_usage sudoers entry), or run `sudo monitor` once"
	}
	// fs_usage started (the grant exists) but died immediately: it is a
	// singleton kernel tracer, so something else holds the trace -- most
	// often a stale fs_usage orphaned by a crashed session
	return false, "fs_usage exits immediately — another fs_usage tracer " +
		"holds the kernel trace; kill stale ones (sudo pkill -9 -x fs_usage), " +
		"then click this chip to retry"
}

// sudoProbe starts `sudo -n fs_usage` to prove the grant actually works
// without a password -- the one check that cannot lie, because NOPASSWD
// execution never needs a timestamp or a tty (unlike `sudo -l`, which
// auth-gates its listing whenever no valid timestamp exists).
//
// Outcomes:
//   - still alive after the grace period -> the grant works. TERM both
//     down: sudo relays the signal to its root-owned fs_usage child and
//     both exit, so the probe leaves nothing behind (a SIGKILL'd sudo
//     cannot relay and would leak a root tracer the monitor can never
//     kill).
//   - died with "a password is required" on stderr -> no grant.
//   - died otherwise -> fs_usage refused the kernel trace (ktrace busy: a
//     stale tracer holds it); run() surfaces that with remediation.
func (c *FilesMacOS) sudoProbe() (ok bool, why string) {
	cmd := exec.Command("sudo", "-n", fsUsagePath, "-w", "-f", "filesys")
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} // own process group
	if cmd.Start() != nil {
		return false, "password"
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
		if strings.Contains(errBuf.String(), "password is required") {
			return false, "password"
		}
		return false, "died"
	case <-time.After(800 * time.Millisecond):
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) // relayed to child
		select {
		case <-done:
		case <-time.After(2 * time.Second): // ignored the relay: escalate
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			<-done
		}
		return true, ""
	}
}

func (c *FilesMacOS) run() {
	watched := c.Ctx.WatchedDirs()
	cmdArgs := []string{fsUsagePath, "-w", "-f", "filesys"}
	if c.Mode == "sudo" {
		cmdArgs = append([]string{"sudo", "-n"}, cmdArgs...)
	}
	proc, reader, err := monitor.PopenStream(cmdArgs)
	if err != nil {
		c.SetStatus("unavailable", "cannot start fs_usage")
		return
	}
	c.registerProc(proc)
	via := "root"
	if c.Mode == "sudo" {
		via = "sudo"
	}
	c.SetStatus("active", "tracing file access in "+
		strconv.Itoa(len(watched))+" watched dirs (via "+via+")")
	for {
		line, readErr := reader.ReadString('\n')
		c.parse(strings.TrimRight(line, "\n"), watched)
		if readErr != nil || c.Stopped() {
			break
		}
	}
	// The stream child must be reaped: sudo exits instantly when the
	// passwordless grant disappears between probe and start ("sudo: a
	// password is required" on stderr, which PopenStream discards), and an
	// unwaited dead child lingers as a zombie for Sentinel to flag. Wait
	// always, then surface WHY the stream ended so "active" never lies.
	waitErr := proc.Wait()
	if c.Stopped() {
		return // deliberate stop — nothing to report
	}
	reason := "fs_usage stream ended"
	if waitErr != nil {
		reason = "fs_usage stream lost (" + waitErr.Error() + ")"
		if strings.Contains(waitErr.Error(), "exit status 1") {
			// fs_usage is a singleton kernel tracer: exit 1 right after
			// start almost always means another fs_usage holds the trace
			// (a stale one from before a crashed session, for example).
			reason += " — another fs_usage tracer may already hold the " +
				"kernel trace (kill stale fs_usage processes), then click to retry"
		}
	}
	c.SetStatus("unavailable", reason+" — click to retry")
}

func (c *FilesMacOS) parse(line string, watched []string) {
	if len(line) < 10 || !strings.ContainsRune("0123456789", rune(line[0])) {
		return
	}
	if strings.Contains(line, "fs_usage") {
		return
	}
	tokens := strings.Fields(line)
	if len(tokens) < 4 {
		return
	}
	call := tokens[1]
	kind, ok := callKinds[call]
	if !ok {
		return
	}
	// fs_usage ends every line with "name.pid" dot-joined in ONE token
	// ("touch.47970", the comm name truncated to 15 chars); very old
	// layouts separated them as "pid.stamp name" — try both.
	last := tokens[len(tokens)-1]
	procName := last
	pid := 0
	if idx := strings.LastIndexByte(last, '.'); idx > 0 && isAllDigits(last[idx+1:]) {
		procName = last[:idx]
		pid, _ = strconv.Atoi(last[idx+1:])
	} else if m := pidToken.FindStringSubmatch(last); m != nil {
		pid, _ = strconv.Atoi(m[1])
	} else if len(tokens) >= 2 {
		if m := pidToken.FindStringSubmatch(tokens[len(tokens)-2]); m != nil {
			pid, _ = strconv.Atoi(m[1])
		}
	}
	if pid == os.Getpid() {
		return
	}
	// path = first token starting with '/', possibly spanning several tokens
	start := -1
	for i, t := range tokens {
		if strings.HasPrefix(t, "/") {
			start = i
			break
		}
	}
	if start < 0 {
		return
	}
	path := strings.Join(tokens[start:len(tokens)-2], " ")
	if path == "" || !strings.Contains(path, "/") {
		return
	}
	if len(watched) > 0 && !startsWithAny(path, watched) {
		return
	}
	// dedup repeated syscall lines for the same open within 1s
	now := monitor.Now()
	key := dedupKey{pid, kind, path}
	if now-c.dedup[key] < 1.0 {
		return
	}
	c.dedup[key] = now
	if len(c.dedup) > 8192 {
		cutoff := now - 2.0
		for k, ts := range c.dedup {
			if ts <= cutoff {
				delete(c.dedup, k)
			}
		}
	}
	// soft rate limit: max 40 events / second
	if now-c.budgetTs > 1.0 {
		c.budgetTs = now
		c.budget = 0
	}
	c.budget++
	if c.budget > 40 {
		return
	}
	c.Emit(&monitor.Event{
		Category: "file",
		Kind:     kind,
		App:      procName,
		Pid:      pid,
		User:     monitor.ProcUser(pid),
		Path:     path,
		Detail:   call,
	})
}

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
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
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
	if c.sudoProbe() {
		c.Mode = "sudo"
		return true, ""
	}
	return false, "needs root: run `sudo python3 -m monitor`, or grant one-time " +
		"passwordless access with `scripts/grant_files_macos.sh`, then " +
		"click this chip to retry"
}

// sudoProbe is true if `sudo -n fs_usage` starts without a password prompt.
func (c *FilesMacOS) sudoProbe() bool {
	cmd := exec.Command("sudo", "-n", fsUsagePath, "-w", "-f", "filesys")
	if cmd.Start() != nil {
		return false
	}
	time.Sleep(800 * time.Millisecond)
	running := cmd.ProcessState == nil
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	_ = cmd.Wait()
	return running
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
	}
	c.SetStatus("unavailable", reason+" — click to retry")
}

func (c *FilesMacOS) parse(line string, watched []string) {
	if len(line) < 10 || !strings.ContainsRune("0123456789", rune(line[0])) {
		return
	}
	if strings.Contains(line, "fs_usage") ||
		(strings.Contains(line, "monitor") && strings.Contains(line, "python")) {
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
	procName := tokens[len(tokens)-1]
	m := pidToken.FindStringSubmatch(tokens[len(tokens)-2])
	if m == nil || procName == "" {
		return
	}
	pid, _ := strconv.Atoi(m[1])
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

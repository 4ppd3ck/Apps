//go:build windows

// Windows-side privilege pieces: elevation check (Shell32.IsUserAnAdmin,
// the same API the Python code reaches for via ctypes -- monitor/enforcer.py
// _is_admin) and the AppScopeBlock broker queue (helper mode: the unelevated
// monitor drops one command file per rule into %ProgramData%\AppScopeBlock\queue
// and starts the SYSTEM scheduled task, which validates and applies the
// netsh rules; see scripts/appscope-block-helper.ps1).
package monitor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var (
	shell32           = syscall.NewLazyDLL("shell32.dll")
	procIsUserAnAdmin = shell32.NewProc("IsUserAnAdmin")
)

func isElevated() bool {
	r1, _, _ := procIsUserAnAdmin.Call()
	return r1 != 0
}

func brokerDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "AppScopeBlock")
}

// brokerReady reports helper mode: helper installed AND task registered.
func brokerReady() bool {
	if _, err := os.Stat(filepath.Join(brokerDir(), "appscope-block-helper.ps1")); err != nil {
		return false
	}
	rc, _, _ := Run([]string{"schtasks", "/query", "/fo", "csv", "/tn", BrokerTask},
		10*time.Second)
	return rc == 0
}

// brokerEnqueue writes one command file and asks the task to consume it,
// waiting until the helper deletes the file (its ack).
func brokerEnqueue(line string) error {
	q := filepath.Join(brokerDir(), "queue")
	if err := os.MkdirAll(q, 0o755); err != nil {
		return fmt.Errorf("broker queue unavailable: %w", err)
	}
	tmp, err := os.CreateTemp(q, "blk-*.cmd")
	if err != nil {
		return fmt.Errorf("cannot write to the broker queue (run the grant): %w", err)
	}
	path := tmp.Name()
	if _, err := tmp.WriteString(line + "\n"); err != nil {
		tmp.Close()
		os.Remove(path)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(path)
		return err
	}
	rc, out, errOut := Run([]string{"schtasks", "/run", "/tn", BrokerTask},
		10*time.Second)
	if rc != 0 {
		os.Remove(path)
		detail := strings.TrimSpace(out + errOut)
		if detail == "" {
			detail = fmt.Sprintf("exit %d", rc)
		}
		return fmt.Errorf("cannot start the %s task: %s", BrokerTask, truncate(detail, 160))
	}
	for i := 0; i < 80; i++ { // up to 20 s for the helper to consume the file
		time.Sleep(250 * time.Millisecond)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return nil
		}
	}
	os.Remove(path)
	return fmt.Errorf("the %s task did not consume the request within 20 s",
		BrokerTask)
}

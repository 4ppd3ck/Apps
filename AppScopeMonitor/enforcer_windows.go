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

// ------------------------------------------------------------- country --

// brokerCIDRFile is the broker-dir-relative name of a CIDR rule's list;
// the PS helper reads it from its own directory only (no traversal).
func brokerCIDRFile(rtype, value string) string {
	return fmt.Sprintf("%s-%s.cidr", rtype, value)
}

// brokerWriteCIDRFile drops a validated CIDR list where the AppScopeBlock
// task can read it (the monitor can write its own ProgramData folder).
func brokerWriteCIDRFile(rtype, value string, cidrs []string) error {
	path := filepath.Join(brokerDir(), brokerCIDRFile(rtype, value))
	var sb strings.Builder
	for _, c := range cidrs {
		sb.WriteString(c + "\n")
	}
	if err := os.WriteFile(path, []byte(sb.String()), 0o644); err != nil {
		return fmt.Errorf("cannot write the broker CIDR file: %w", err)
	}
	return nil
}

// chunkNetshName must stay byte-identical to scripts/appscope-block-helper.ps1's
// chunk naming: "AppScope block <type> <value> <dir> <NNN>".
func chunkNetshName(rtype, value, dir string, idx int) string {
	return fmt.Sprintf("AppScope block %s %s %s %03d", rtype, value, dir, idx)
}

// cidrWindows routes a CIDR rule (country / list): helper mode hands a CIDR
// file to the AppScopeBlock task, direct mode chunks the ranges into netsh
// rules.
func (e *Enforcer) cidrWindows(rule *Block, add bool) (string, string) {
	rtype := rule.Type
	value := rule.Value
	if rtype == "country" {
		value = strings.ToUpper(strings.TrimSpace(value))
	} else if rtype == "list" {
		value = SanitizeLabel(value)
	}
	if !add {
		if e.Mode == "helper" {
			if err := brokerEnqueue(fmt.Sprintf("del|%s|%s|", rtype, value)); err != nil {
				return "error", err.Error()
			}
			return "removed", rtype + " removal queued for the " + BrokerTask + " task"
		}
		// netsh delete supports a trailing * on name=: one call per
		// direction removes every chunk rule for the set
		e.netsh("delete", "rule", "name=AppScope block "+rtype+" "+value+" out *")
		e.netsh("delete", "rule", "name=AppScope block "+rtype+" "+value+" in *")
		return "removed", rtype + " netsh rules deleted"
	}
	cidrs, status, detail := e.cidrsForApply(rule)
	if status != "" {
		return status, detail
	}
	cidrs = FilterSafeCIDRs(cidrs)
	if len(cidrs) == 0 {
		return "error", "feed contained no blockable public ranges"
	}
	if e.Mode == "helper" {
		if err := brokerWriteCIDRFile(rtype, value, cidrs); err != nil {
			return "error", err.Error()
		}
		if err := brokerEnqueue(fmt.Sprintf("add|%s|%s|%s", rtype, value,
			brokerCIDRFile(rtype, value))); err != nil {
			return "error", err.Error()
		}
		return "enforced", fmt.Sprintf("%d ranges handed to the %s task (%s %s)",
			len(cidrs), BrokerTask, rtype, value)
	}
	return e.chunkNetshRules(rtype, value, cidrs)
}

// chunkNetshRules adds the rules directly (elevated monitor). netsh's
// remoteip= takes a comma-separated range list bounded by the command-line
// size and the firewall's per-rule entry cap, so the list is chunked and
// each chunk becomes one rule pair with a numbered name.
func (e *Enforcer) chunkNetshRules(rtype, value string, cidrs []string) (string, string) {
	chunks := ChunkCIDRs(cidrs, maxRemoteIPChars, maxRemoteIPRules)
	for i, chunk := range chunks {
		remote := "remoteip=" + strings.Join(chunk, ",")
		if rc, out := e.netsh("add", "rule",
			"name="+chunkNetshName(rtype, value, "out", i+1),
			"dir=out", "action=block", remote); rc != 0 {
			return "error", truncate(fmt.Sprintf("netsh chunk %d: %s", i+1, out), 200)
		}
		if rc, out := e.netsh("add", "rule",
			"name="+chunkNetshName(rtype, value, "in", i+1),
			"dir=in", "action=block", remote); rc != 0 {
			return "error", truncate(fmt.Sprintf("netsh chunk %d: %s", i+1, out), 200)
		}
	}
	return "enforced", fmt.Sprintf("%d ranges in %d netsh rule pairs (%s %s)",
		len(cidrs), len(chunks), rtype, value)
}

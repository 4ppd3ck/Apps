// Connection/IP/app blocking enforcement.
//
// Blocking is enforced through the OS firewall, which needs privileges the
// monitor deliberately does not run with. One elevated install (the
// dashboard's Grant button, or the script by hand) fixes that for good:
//
//   - macOS   -- pf (IP/connection) + the application firewall (app) via a
//     validating root helper: POST /api/block/grant runs
//     scripts/grant_block_macos.sh through osascript's administrator dialog
//     (installs /usr/local/libexec/appscope-block + a NOPASSWD sudoers entry
//     for that helper only).
//   - Linux   -- iptables via the same helper pattern
//     (scripts/grant_block_linux.sh, elevated through pkexec).
//   - Windows -- netsh advfirewall: elevated monitors apply rules directly;
//     otherwise the grant registers the "AppScopeBlock" scheduled task
//     (SYSTEM) and rules flow through its queue (helper mode).
//
// Rules that cannot be applied right away are marked "queued" (kept in the
// store, shown on the dashboard) and retried on the next reconcile, so
// granting privilege later activates pending blocks automatically.
//
// Mirrors monitor/enforcer.py.
package monitor

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	HelperMac   = "/usr/local/libexec/appscope-block"
	HelperLinux = "/usr/local/bin/appscope-block"

	// Windows broker: the "AppScopeBlock" scheduled task (SYSTEM, installed
	// by the one-time grant) consumes rule commands from a queue folder, so
	// the unelevated monitor never has to elevate itself.
	BrokerTask = "AppScopeBlock"
)

var ipv4Re = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)

// ValidIP checks a dotted-quad IPv4 string (enforcer.valid_ip).
func ValidIP(ip string) bool {
	if !ipv4Re.MatchString(ip) {
		return false
	}
	for _, o := range strings.Split(ip, ".") {
		n, err := strconv.Atoi(o)
		if err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return true
}

// Enforcer applies block rules through the platform firewall.
type Enforcer struct {
	Ctx    *Ctx
	Mode   string // "" | "direct" | "helper"
	Reason string
}

// NewEnforcer creates an enforcer (mode "not probed" yet).
func NewEnforcer(ctx *Ctx) *Enforcer {
	return &Enforcer{Ctx: ctx, Reason: "not probed"}
}

// runCombined mirrors enforcer._run: (rc, stdout+stderr combined).
func runCombined(cmd []string, timeout time.Duration) (int, string) {
	rc, out, errOut := Run(cmd, timeout)
	return rc, out + errOut
}

// helperSrcPath mirrors _HELPER_SRC: the project's scripts/appscope-block-helper.sh.
func (e *Enforcer) helperSrcPath() string {
	return filepath.Join(filepath.Dir(e.Ctx.Cfg.Path), "scripts", "appscope-block-helper.sh")
}

// Probe determines the enforcement mode for the running platform.
func (e *Enforcer) Probe() string {
	e.Mode, e.Reason = "", "blocking unsupported on this platform"
	switch runtime.GOOS {
	case "darwin":
		if _, err := os.Stat(HelperMac); err == nil {
			rc, out := runCombined([]string{"sudo", "-n", HelperMac, "status"}, 10*time.Second)
			if rc == 0 || strings.Contains(strings.ToLower(out), "no rules") {
				e.Mode, e.Reason = "helper", HelperMac
				return e.Mode
			}
		}
		if isElevated() {
			e.Mode, e.Reason = "direct", "running as root"
		} else {
			e.Reason = "needs privilege — click Grant on the Blocked panel " +
				"(installs a drop-only helper via the macOS password sheet), " +
				"or run scripts/grant_block_macos.sh"
		}
	case "linux":
		if _, err := os.Stat(HelperLinux); err == nil {
			rc, out := runCombined([]string{"sudo", "-n", HelperLinux, "status"}, 10*time.Second)
			if rc == 0 || strings.Contains(strings.ToLower(out), "no rules") {
				e.Mode, e.Reason = "helper", HelperLinux
				return e.Mode
			}
		}
		if isElevated() {
			e.Mode, e.Reason = "direct", "running as root"
		} else {
			e.Reason = "needs privilege — click Grant on the Blocked panel " +
				"(installs a drop-only helper via the polkit dialog), " +
				"or run scripts/grant_block_linux.sh"
		}
	case "windows":
		if isElevated() {
			e.Mode, e.Reason = "direct", "running elevated"
		} else if brokerReady() {
			e.Mode, e.Reason = "helper", BrokerTask+" task (SYSTEM) applies "+
				"rules from the queue"
		} else {
			e.Reason = "needs elevation — click Grant on the Blocked panel " +
				"(one UAC prompt installs a broker task), or run " +
				"scripts/grant_block_windows.ps1 as Administrator"
		}
	}
	return e.Mode
}

// helperCmd mirrors _helper_cmd: [sudo -n] <helper> <args...>.
func (e *Enforcer) helperCmd(args ...string) []string {
	helper := HelperLinux
	if runtime.GOOS == "darwin" {
		helper = HelperMac
	}
	useSudo := e.Mode == "helper" || !isElevated()
	if _, err := os.Stat(helper); err != nil {
		helper = e.helperSrcPath() // root can run the project copy directly
	}
	base := []string{helper}
	if useSudo {
		base = []string{"sudo", "-n", helper}
	}
	return append(base, args...)
}

// iptables mirrors _iptables: direct iptables enforcement (Linux, as root).
func (e *Enforcer) iptables(rule *Block, add bool) (string, string) {
	ip, port, _ := strings.Cut(rule.Value, ":")
	if rule.Type == "app" {
		return "unsupported", "app blocking is not available via iptables"
	}
	var specOut, specIn []string
	if rule.Type == "ip" {
		specOut = []string{"-d", ip}
		specIn = []string{"-s", ip}
	} else {
		specOut = []string{"-p", "tcp", "-d", ip, "--dport", port}
		specIn = []string{"-p", "tcp", "-s", ip, "--sport", port}
	}
	chains := []struct {
		chain string
		spec  []string
	}{
		{"OUTPUT", specOut}, {"INPUT", specIn},
	}
	var errs []string
	for _, ch := range chains {
		base := append([]string{"iptables", "-w", "-C", ch.chain}, ch.spec...)
		base = append(base, "-j", "DROP")
		rc, out := runCombined(base, 10*time.Second)
		exists := rc == 0
		if add && !exists {
			cmd := append([]string{"iptables", "-w", "-I", ch.chain}, ch.spec...)
			cmd = append(cmd, "-j", "DROP")
			rc, out = runCombined(cmd, 10*time.Second)
			if rc != 0 {
				errs = append(errs, truncate(strings.TrimSpace(out), 120))
			}
		} else if !add && exists {
			cmd := append([]string{"iptables", "-w", "-D", ch.chain}, ch.spec...)
			cmd = append(cmd, "-j", "DROP")
			rc, out = runCombined(cmd, 10*time.Second)
			if rc != 0 {
				errs = append(errs, truncate(strings.TrimSpace(out), 120))
			}
		}
	}
	if len(errs) > 0 {
		return "error", strings.Join(errs, "; ")
	}
	if add {
		return "enforced", "iptables DROP rules active"
	}
	return "removed", "iptables rules removed"
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// Apply enforces one rule; returns (status, detail).
func (e *Enforcer) Apply(rule *Block) (string, string) {
	if e.Mode == "" {
		e.Probe()
	}
	if e.Mode == "" {
		return "queued", e.Reason
	}
	rtype := rule.Type
	if runtime.GOOS == "windows" {
		return e.applyWindows(rule)
	}
	var rc int
	var out string
	switch {
	case rtype == "app":
		if runtime.GOOS == "linux" {
			return "unsupported",
				"app blocking is not available via iptables; block its IPs instead"
		}
		path := rule.Value
		if rule.AppPath != nil && *rule.AppPath != "" {
			path = *rule.AppPath
		}
		rc, out = runCombined(e.helperCmd("add", "app", path), 30*time.Second)
	case rtype == "ip" || rtype == "connection":
		if runtime.GOOS == "linux" && e.Mode == "direct" {
			return e.iptables(rule, true)
		}
		ip, port, _ := strings.Cut(rule.Value, ":")
		args := []string{"add", "ip", ip}
		if port != "" {
			args = append(args, port)
		}
		rc, out = runCombined(e.helperCmd(args...), 30*time.Second)
	default:
		return "error", fmt.Sprintf("unknown rule type %s", rtype)
	}
	if rc == 0 {
		detail := strings.TrimSpace(out)
		detail = truncate(detail, 200)
		if detail == "" {
			detail = "applied"
		}
		return "enforced", detail
	}
	detail := strings.TrimSpace(out)
	if detail == "" {
		detail = fmt.Sprintf("exit %d", rc)
	}
	return "error", truncate(detail, 200)
}

// Unapply removes one rule's enforcement; returns (status, detail).
func (e *Enforcer) Unapply(rule *Block) (string, string) {
	if e.Mode == "" {
		e.Probe()
	}
	if e.Mode == "" {
		return "queued", e.Reason
	}
	if runtime.GOOS == "windows" {
		return e.unapplyWindows(rule)
	}
	rtype := rule.Type
	var rc int
	var out string
	switch {
	case rtype == "app":
		if runtime.GOOS == "linux" {
			return "unsupported", "n/a"
		}
		path := rule.Value
		if rule.AppPath != nil && *rule.AppPath != "" {
			path = *rule.AppPath
		}
		rc, out = runCombined(e.helperCmd("del", "app", path), 30*time.Second)
	case rtype == "ip" || rtype == "connection":
		if runtime.GOOS == "linux" && e.Mode == "direct" {
			return e.iptables(rule, false)
		}
		ip, port, _ := strings.Cut(rule.Value, ":")
		args := []string{"del", "ip", ip}
		if port != "" {
			args = append(args, port)
		}
		rc, out = runCombined(e.helperCmd(args...), 30*time.Second)
	default:
		return "error", fmt.Sprintf("unknown rule type %s", rtype)
	}
	if rc == 0 {
		detail := strings.TrimSpace(out)
		detail = truncate(detail, 200)
		if detail == "" {
			detail = "removed"
		}
		return "removed", detail
	}
	detail := strings.TrimSpace(out)
	if detail == "" {
		detail = fmt.Sprintf("exit %d", rc)
	}
	return "error", truncate(detail, 200)
}

// Reconcile (re)applies all stored rules; call at startup and after grant.
func (e *Enforcer) Reconcile() (int, error) {
	rules, err := e.Ctx.Store.ListBlocks()
	if err != nil {
		return 0, err
	}
	done := 0
	for _, r := range rules {
		status, detail := e.Apply(r)
		e.Ctx.Store.UpdateBlockStatus(r.ID, status, detail)
		done++
	}
	return done, nil
}

// ------------------------------------------------------------ windows ----

func (e *Enforcer) netsh(args ...string) (int, string) {
	return runCombined(append([]string{"netsh", "advfirewall", "firewall"}, args...),
		20*time.Second)
}

func wName(rule *Block, direction string) string {
	return fmt.Sprintf("AppScope block %s %s %s", rule.Type, rule.Value, direction)
}

// brokerApply hands one rule to the AppScopeBlock task via its queue folder
// (helper mode: the monitor is unelevated, the task applies the netsh rules).
// Same-line format the PowerShell helper parses: action|type|value|extra.
func (e *Enforcer) brokerApply(rule *Block, add bool) (string, string) {
	action := "del"
	if add {
		action = "add"
	}
	extra := ""
	if rule.Type == "app" {
		extra = rule.Value
		if rule.AppPath != nil && *rule.AppPath != "" {
			extra = *rule.AppPath
		}
	}
	if err := brokerEnqueue(
		fmt.Sprintf("%s|%s|%s|%s", action, rule.Type, rule.Value, extra)); err != nil {
		return "error", err.Error()
	}
	if add {
		return "enforced", "applied by the " + BrokerTask + " task"
	}
	return "removed", "removed by the " + BrokerTask + " task"
}

func (e *Enforcer) applyWindows(rule *Block) (string, string) {
	if e.Mode == "helper" {
		return e.brokerApply(rule, true)
	}
	var rc1, rc2 int
	var out1, out2 string
	if rule.Type == "app" {
		prog := rule.Value
		if rule.AppPath != nil && *rule.AppPath != "" {
			prog = *rule.AppPath
		}
		rc1, out1 = e.netsh("add", "rule", "name="+wName(rule, "out"),
			"dir=out", "action=block", "program="+prog)
		rc2, out2 = e.netsh("add", "rule", "name="+wName(rule, "in"),
			"dir=in", "action=block", "program="+prog)
	} else {
		ip, port, _ := strings.Cut(rule.Value, ":")
		var extra []string
		if ip != "" {
			extra = append(extra, "remoteip="+ip)
		}
		if port != "" {
			extra = append(extra, "remoteport="+port)
		}
		argsOut := append([]string{"add", "rule", "name=" + wName(rule, "out"),
			"dir=out", "action=block"}, extra...)
		argsIn := append([]string{"add", "rule", "name=" + wName(rule, "in"),
			"dir=in", "action=block"}, extra...)
		rc1, out1 = e.netsh(argsOut...)
		rc2, out2 = e.netsh(argsIn...)
	}
	if rc1 == 0 && rc2 == 0 {
		return "enforced", "netsh rules added"
	}
	return "error", truncate(strings.TrimSpace(out1+out2), 200)
}

func (e *Enforcer) unapplyWindows(rule *Block) (string, string) {
	if e.Mode == "helper" {
		return e.brokerApply(rule, false)
	}
	e.netsh("delete", "rule", "name="+wName(rule, "out"))
	e.netsh("delete", "rule", "name="+wName(rule, "in"))
	return "removed", "netsh rules deleted"
}

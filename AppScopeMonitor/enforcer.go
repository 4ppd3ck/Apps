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
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// PFBlockTable is the pf table holding every blocked country's CIDRs
// (macOS); IPBlockSet is the matching ipset set (Linux direct mode). The
// privileged helpers own both — the monitor only feeds them CIDR lists.
const (
	PFBlockTable = "appscope_block_cn"
	IPBlockSet   = "appscope_block"
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

// runCombinedStdin is runCombined with stdin: the country-block helper
// reads CIDR lists on stdin (thousands of networks cannot ride argv).
func runCombinedStdin(cmd []string, input string, timeout time.Duration) (int, string) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if len(cmd) == 0 {
		return 127, "empty command"
	}
	c := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
	c.WaitDelay = 2 * time.Second
	var stdout, stderr bytes.Buffer
	c.Stdout = &stdout
	c.Stderr = &stderr
	c.Stdin = strings.NewReader(input)
	err := c.Run()
	if ctx.Err() != nil {
		return 124, "timeout"
	}
	out := strings.TrimSpace(stdout.String() + stderr.String())
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && out == "" {
			out = fmt.Sprintf("exit %d", ee.ExitCode())
		}
		if out == "" {
			out = err.Error()
		}
	}
	return exitCodeOf(err), out
}

func exitCodeOf(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return 1
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
	case rtype == "country":
		if runtime.GOOS == "windows" {
			return e.applyWindows(rule) // handled above; unreachable
		}
		if runtime.GOOS == "linux" && e.Mode == "direct" {
			return e.ipsetCIDRRules(rule, true)
		}
		return e.countryHelper(rule, true)
	case rtype == "list" || rtype == "provider":
		if runtime.GOOS == "windows" {
			return e.applyWindows(rule) // handled above; unreachable
		}
		if runtime.GOOS == "linux" && e.Mode == "direct" {
			return e.ipsetCIDRRules(rule, true)
		}
		return e.cidrHelper(rule, true)
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
	case rtype == "country":
		if runtime.GOOS == "windows" {
			return e.unapplyWindows(rule) // handled above; unreachable
		}
		if runtime.GOOS == "linux" && e.Mode == "direct" {
			return e.ipsetCIDRRules(rule, false)
		}
		return e.countryHelper(rule, false)
	case rtype == "list" || rtype == "provider":
		if runtime.GOOS == "windows" {
			return e.unapplyWindows(rule) // handled above; unreachable
		}
		if runtime.GOOS == "linux" && e.Mode == "direct" {
			return e.ipsetCIDRRules(rule, false)
		}
		return e.cidrHelper(rule, false)
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

// ------------------------------------------------------------- country --

// countryHelper feeds the privileged helper a country's CIDR list on stdin
// (thousands of networks cannot ride argv). The helper validates every
// range, filters protected ones and regenerates the pf table / ipset.
func (e *Enforcer) countryHelper(rule *Block, add bool) (string, string) {
	cc := strings.ToUpper(strings.TrimSpace(rule.Value))
	if !add {
		rc, out := runCombinedStdin(e.helperCmd("del", "country", cc), "", 30*time.Second)
		if rc != 0 {
			return "error", truncate(out, 200)
		}
		return "removed", fmt.Sprintf("country %s removed from the firewall", cc)
	}
	cidrs, err := e.Ctx.Country.Ensure(cc)
	if err != nil {
		return "queued", truncate(err.Error(), 200)
	}
	cidrs = FilterSafeCIDRs(cidrs)
	if len(cidrs) == 0 {
		return "error", "country feed contained no blockable public ranges"
	}
	rc, out := runCombinedStdin(e.helperCmd("add", "country", cc),
		strings.Join(cidrs, "\n"), 120*time.Second)
	if rc != 0 {
		return "error", truncate(out, 200)
	}
	return "enforced", fmt.Sprintf("%d CIDRs enforced (country %s)", len(cidrs), cc)
}

// ipsetCIDRRules is the Linux direct-mode path (root): rebuild the
// appscope_block ipset from every active CIDR rule (country + list) —
// idempotent, so add and remove share one code path — and keep exactly one
// iptables -m set rule per direction while any CIDR rule is active.
func (e *Enforcer) ipsetCIDRRules(rule *Block, add bool) (string, string) {
	ranges := map[string][]string{}
	if rules, err := e.Ctx.Store.ListBlocks(); err == nil {
		for _, r := range rules {
			if r.ID == rule.ID {
				continue
			}
			if r.Type != "country" && r.Type != "list" && r.Type != "provider" {
				continue
			}
			if list, ok := e.cidrsForRule(r); ok {
				ranges[r.Type+"\x00"+r.Value] = list
			}
		}
	}
	if add {
		list, status, detail := e.cidrsForApply(rule)
		if status != "" {
			return status, detail
		}
		ranges[rule.Type+"\x00"+rule.Value] = list
	}
	cidrs := FilterSafeCIDRs(unionCIDRs(ranges))

	var sb strings.Builder
	sb.WriteString("create " + IPBlockSet + " hash:net -exist\n")
	sb.WriteString("flush " + IPBlockSet + "\n")
	for _, c := range cidrs {
		sb.WriteString("add " + IPBlockSet + " " + c + "\n")
	}
	rc, out := runCombinedStdin([]string{"ipset", "-exist", "restore"},
		sb.String(), 120*time.Second)
	if rc != 0 {
		return "error", truncate("ipset restore: "+out, 200)
	}
	for _, chain := range []struct{ name, match string }{
		{"OUTPUT", "dst"}, {"INPUT", "src"},
	} {
		check := []string{"iptables", "-w", "-C", chain.name, "-m", "set",
			"--match-set", IPBlockSet, chain.match, "-j", "DROP"}
		present, _ := runCombined(check, 10*time.Second)
		if len(cidrs) > 0 && present != 0 {
			insert := append([]string{"iptables", "-w", "-I", chain.name,
				"-m", "set", "--match-set", IPBlockSet, chain.match}, "-j", "DROP")
			if rc2, out2 := runCombined(insert, 10*time.Second); rc2 != 0 {
				return "error", truncate("iptables -I: "+out2, 200)
			}
		} else if len(cidrs) == 0 && present == 0 {
			del := append([]string{"iptables", "-w", "-D", chain.name,
				"-m", "set", "--match-set", IPBlockSet, chain.match}, "-j", "DROP")
			runCombined(del, 10*time.Second)
		}
	}
	if add {
		return "enforced", fmt.Sprintf("%d CIDRs enforced (%s %s)",
			len(cidrs), rule.Type, rule.Value)
	}
	return "removed", "ranges removed from the ipset"
}

// cidrsForApply fetches the ranges a rule being ADDED should enforce:
// country rules resolve via IPolice (queued on failure), list rules parse
// their file. Returns (nil, status, detail) on a short-circuit.
func (e *Enforcer) cidrsForApply(rule *Block) ([]string, string, string) {
	switch rule.Type {
	case "country":
		cc := strings.ToUpper(strings.TrimSpace(rule.Value))
		cidrs, err := e.Ctx.Country.Ensure(cc)
		if err != nil {
			return nil, "queued", truncate(err.Error(), 200)
		}
		return cidrs, "", ""
	case "list":
		cidrs, err := ParseIPFile(e.listPath(rule))
		if err != nil {
			return nil, "error", truncate("blocklist file: "+err.Error(), 200)
		}
		return cidrs, "", ""
	case "provider":
		cidrs, err := e.Ctx.Country.EnsureProvider(rule.Value)
		if err != nil {
			return nil, "queued", truncate(err.Error(), 200)
		}
		return cidrs, "", ""
	}
	return nil, "error", "unknown CIDR rule type " + rule.Type
}

// cidrsForRule reads the current ranges of an already-stored rule without
// network fetches (country: cache; list: file as it stands now).
func (e *Enforcer) cidrsForRule(rule *Block) ([]string, bool) {
	switch rule.Type {
	case "country":
		return e.Ctx.Country.Cached(rule.Value)
	case "list":
		cidrs, err := ParseIPFile(e.listPath(rule))
		return cidrs, err == nil
	case "provider":
		return e.Ctx.Country.Cached(rule.Value)
	}
	return nil, false
}

// listPath returns the blocklist file path stored with a list rule.
func (e *Enforcer) listPath(rule *Block) string {
	if rule.AppPath != nil {
		return *rule.AppPath
	}
	return ""
}

func unionCIDRs(ranges map[string][]string) []string {
	var out []string
	for _, list := range ranges {
		out = append(out, list...)
	}
	return out
}

// cidrHelper feeds the privileged helper a CIDR list on stdin for the
// monitor-managed set rules (list / provider — both use the helper's
// generic `list <label>` command). list rules additionally mirror their
// file into IPolice (file source) when it is up.
func (e *Enforcer) cidrHelper(rule *Block, add bool) (string, string) {
	label := SanitizeLabel(rule.Value)
	if !add {
		rc, out := runCombinedStdin(e.helperCmd("del", "list", label), "", 30*time.Second)
		if rc != 0 {
			return "error", truncate(out, 200)
		}
		return "removed", fmt.Sprintf("blocklist %s removed from the firewall", label)
	}
	var cidrs []string
	switch rule.Type {
	case "provider":
		var err error
		if cidrs, err = e.Ctx.Country.EnsureProvider(rule.Value); err != nil {
			return "queued", truncate(err.Error(), 200)
		}
	default: // list
		path := e.listPath(rule)
		var err error
		if cidrs, err = ParseIPFile(path); err != nil {
			return "error", truncate("blocklist file: "+err.Error(), 200)
		}
		if e.Ctx.Country != nil {
			go e.Ctx.Country.EnsureListSource(label, path)
		}
	}
	if len(cidrs) == 0 {
		return "error", "rule contained no blockable public ranges"
	}
	rc, out := runCombinedStdin(e.helperCmd("add", "list", label),
		strings.Join(cidrs, "\n"), 120*time.Second)
	if rc != 0 {
		return "error", truncate(out, 200)
	}
	return "enforced", fmt.Sprintf("%d ranges enforced (list %s)", len(cidrs), label)
}

// Reconcile (re)applies all stored rules; call at startup and after grant.
// Country rules additionally refresh their CIDR caches in the background
// (cache-first — an offline IPolice keeps the last good table enforceable).
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
		if r.Type == "country" && e.Ctx.Country != nil {
			go e.Ctx.Country.EnsureBackground(r.Value)
		}
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
	if rule.Type == "country" || rule.Type == "list" || rule.Type == "provider" {
		return e.cidrWindows(rule, true)
	}
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
	if rule.Type == "country" || rule.Type == "list" || rule.Type == "provider" {
		return e.cidrWindows(rule, false)
	}
	if e.Mode == "helper" {
		return e.brokerApply(rule, false)
	}
	e.netsh("delete", "rule", "name="+wName(rule, "out"))
	e.netsh("delete", "rule", "name="+wName(rule, "in"))
	return "removed", "netsh rules deleted"
}

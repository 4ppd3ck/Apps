package main

// Firewall audit — reads the platform's firewall state and per-app rules so
// the App access inventory can show which apps may accept inbound
// connections (and on Windows, the per-profile default outbound policy),
// while the engine alerts on changes (learn-then-diff against the baseline).
//
//	darwin:  /usr/libexec/ApplicationFirewall/socketfilterfw — application
//	         firewall global state, block-all, stealth, per-app allow/block
//	         rules for incoming connections. macOS's application firewall
//	         filters incoming only; there is no per-app outbound rule.
//	windows: Get-NetFirewallProfile / Get-NetFirewallRule via PowerShell
//	         (locale-independent property names) — per-profile on/off plus
//	         default inbound/outbound actions, and enabled rules that name an
//	         explicit program. This is where "allow all incoming/outgoing"
//	         actually lives on Windows.
//	linux:   firewalld / ufw / nftables / iptables backend detection. Rule
//	         details generally need root, so state-only + honest notes.
//	bsd:     pf via pfctl (root usually required; reported as unknown).

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"
)

type firewallProfile struct {
	Name       string `json:"name"`
	Enabled    string `json:"enabled"` // on | off | unknown
	DefaultIn  string `json:"default_in,omitempty"`
	DefaultOut string `json:"default_out,omitempty"`
}

type firewallRule struct {
	Ident   string `json:"ident,omitempty"` // bundle id (macOS) / program path (Windows)
	App     string `json:"app,omitempty"`
	Path    string `json:"path,omitempty"`
	Policy  string `json:"policy"` // allow | block
	Dir     string `json:"dir"`    // in | out
	Profile string `json:"profile,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

type firewallSnapshot struct {
	Source   string            `json:"source"`
	Global   string            `json:"global"` // on | off | unknown
	BlockAll string            `json:"block_all,omitempty"`
	Stealth  string            `json:"stealth,omitempty"`
	Profiles []firewallProfile `json:"profiles,omitempty"`
	Rules    []firewallRule    `json:"rules,omitempty"`
	Notes    []string          `json:"notes,omitempty"`
}

func readFirewall() (firewallSnapshot, error) {
	switch runtime.GOOS {
	case "darwin":
		return readFirewallMac()
	case "windows":
		return readFirewallWindows()
	case "linux":
		return readFirewallLinux()
	case "freebsd", "openbsd", "netbsd":
		return readFirewallBSD()
	}
	return firewallSnapshot{}, fmt.Errorf("firewall audit not implemented on %s", runtime.GOOS)
}

// ---- macOS -----------------------------------------------------------------

func readFirewallMac() (firewallSnapshot, error) {
	const alf = "/usr/libexec/ApplicationFirewall/socketfilterfw"
	snap := firewallSnapshot{Source: "macOS application firewall"}
	stateOut, err := RunOut(6*time.Second, alf, "--getglobalstate")
	if err != nil {
		return snap, fmt.Errorf("socketfilterfw: %w", err)
	}
	snap.Global = parseAlfBool(stateOut)
	if out, err := RunOut(6*time.Second, alf, "--getblockall"); err == nil {
		snap.BlockAll = parseAlfBool(out)
	}
	if out, err := RunOut(6*time.Second, alf, "--getstealthmode"); err == nil {
		snap.Stealth = parseAlfBool(out)
	}
	if out, err := RunOut(12*time.Second, alf, "--listapps"); err == nil {
		snap.Rules = parseSocketFilterfwListapps(out)
	}
	return snap, nil
}

// parseAlfBool reads socketfilterfw's yes/no answers. Newer macOS prints
// "Firewall is enabled. (State = 1)"; older prints "ALF: global state: 1".
func parseAlfBool(out string) string {
	lower := strings.ToLower(out)
	for _, line := range strings.Split(lower, "\n") {
		line = strings.TrimSpace(line)
		i := strings.Index(line, "state")
		if i < 0 {
			continue
		}
		rest := strings.TrimLeft(line[i+len("state"):], " :=:")
		if rest != "" && (rest[0] == '0' || rest[0] == '1') {
			if rest[0] == '1' {
				return "on"
			}
			return "off"
		}
	}
	if strings.Contains(lower, "disabled") {
		return "off"
	}
	if strings.Contains(lower, "enabled") {
		return "on"
	}
	// "Firewall stealth mode is off" — plain on/off without keywords.
	if strings.Contains(lower, "is off") || strings.HasSuffix(lower, " off") {
		return "off"
	}
	if strings.Contains(lower, "is on") || strings.HasSuffix(lower, " on") {
		return "on"
	}
	return "unknown"
}

// parseSocketFilterfwListapps handles both listapps shapes:
//
//	 /Applications/Foo.app (Bundle ID: "com.foo", TEAMID):
//	     Allow incoming connections = 1
//	 /Applications/Bar.app : (allow)
func parseSocketFilterfwListapps(out string) []firewallRule {
	var rules []firewallRule
	var cur *firewallRule
	flush := func() {
		if cur != nil && cur.Policy != "" {
			rules = append(rules, *cur)
		}
		cur = nil
	}
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "applications:") ||
			strings.HasPrefix(lower, "total number of apps") {
			flush()
			continue
		}
		// Numbered format (Sonoma+): "1 : /Applications/Foo.app"
		if path, ok := numberedAppLine(line); ok {
			flush()
			cur = &firewallRule{Ident: path, Path: path,
				App: firewallAppName(path), Dir: "in"}
			continue
		}
		isApp := strings.HasPrefix(line, "/") || strings.HasPrefix(line, "==>") ||
			strings.Contains(lower, "(bundle id:")
		if isApp {
			flush()
			path, ident := "", ""
			if i := strings.Index(line, "(Bundle ID:"); i >= 0 {
				path = strings.TrimSpace(strings.TrimSuffix(line[:i], "("))
				rest := line[i+len("(Bundle ID:"):]
				if j := strings.Index(rest, "\""); j >= 0 {
					rest = rest[j+1:]
					if k := strings.Index(rest, "\""); k >= 0 {
						ident = rest[:k]
					}
				}
			} else {
				path = strings.TrimSpace(strings.TrimPrefix(line, "==> "))
				if strings.HasSuffix(lower, ": (allow)") || strings.HasSuffix(lower, ": (block)") {
					path = strings.TrimSpace(path[:strings.LastIndex(path, ":")])
				}
			}
			pol := ""
			switch {
			case strings.HasSuffix(lower, ": (allow)"):
				pol = "allow"
			case strings.HasSuffix(lower, ": (block)"):
				pol = "block"
			}
			cur = &firewallRule{Ident: ident, Path: path,
				App: firewallAppName(path), Policy: pol, Dir: "in"}
			if cur.Ident == "" {
				cur.Ident = cur.Path // legacy rows have no bundle id
			}
			continue
		}
		if cur == nil {
			continue
		}
		switch {
		// Continuation policy lines: "(Allow incoming connections)" in the
		// numbered format, "(allow)" in some legacy outputs.
		case strings.HasPrefix(lower, "(allow"):
			cur.Policy = "allow"
		case strings.HasPrefix(lower, "(block"):
			cur.Policy = "block"
		// Modern multiline format: the chosen setting carries "= 1"; a
		// "= 0" is the un-chosen default and must not set policy.
		case strings.Contains(lower, "allow incoming connections") && strings.HasSuffix(lower, "= 1"):
			cur.Policy = "allow"
		case strings.Contains(lower, "block incoming connections") && strings.HasSuffix(lower, "= 1"):
			cur.Policy = "block"
		}
	}
	flush()
	return rules
}

// numberedAppLine matches "12 : /path/to/app" — the app rows of the
// socketfilterfw --listapps output used by recent macOS.
func numberedAppLine(line string) (string, bool) {
	i := 0
	for i < len(line) && line[i] >= '0' && line[i] <= '9' {
		i++
	}
	if i == 0 || i+2 > len(line) || line[i] != ' ' || line[i+1] != ':' {
		return "", false
	}
	return strings.TrimSpace(line[i+2:]), true
}

// firewallAppName derives a display name from an app/program path, handling
// POSIX and Windows separators regardless of build platform.
func firewallAppName(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if i := strings.LastIndexAny(path, `/\`); i >= 0 {
		path = path[i+1:]
	}
	dot := strings.LastIndex(path, ".")
	if dot > 0 {
		path = path[:dot]
	}
	return path
}

// ---- Windows ---------------------------------------------------------------

type winFwProfile struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Din     string `json:"din"`
	Dout    string `json:"dout"`
}

type winFwRule struct {
	Name   string `json:"name"`
	Dir    string `json:"dir"`
	Action string `json:"action"`
	Prof   string `json:"prof"`
	Prog   string `json:"prog"`
}

type winFwDump struct {
	Profiles []winFwProfile `json:"profiles"`
	Rules    []winFwRule    `json:"rules"`
}

func readFirewallWindows() (firewallSnapshot, error) {
	snap := firewallSnapshot{Source: "Windows Defender Firewall"}
	script := `$ErrorActionPreference='SilentlyContinue'; `
	script += `$profiles=@(Get-NetFirewallProfile | ForEach-Object { [pscustomobject]@{ name=$_.Name; enabled=$_.Enabled; din=$_.DefaultInboundAction; dout=$_.DefaultOutboundAction } }); `
	script += `$filters=@{}; Get-NetFirewallApplicationFilter | ForEach-Object { $filters[$_.Name]=$_.Program }; `
	script += `$rules=@(Get-NetFirewallRule -Enabled True | Select-Object -First 400 | ForEach-Object { $p=$filters[$_.Name]; `
	script += `if($p -and $p -ne 'Any'){ [pscustomobject]@{ name=$_.DisplayName; dir=$_.Direction; action=$_.Action; prof=$_.Profile; prog=$p } } }); `
	script += `[pscustomobject]@{ profiles=$profiles; rules=$rules } | ConvertTo-Json -Depth 4 -Compress`
	out, err := RunOut(45*time.Second, "powershell", "-NoProfile", "-Command", script)
	if err != nil {
		return snap, fmt.Errorf("firewall powershell: %w", err)
	}
	return parseWindowsFirewallJSON([]byte(out))
}

func parseWindowsFirewallJSON(raw []byte) (firewallSnapshot, error) {
	snap := firewallSnapshot{Source: "Windows Defender Firewall"}
	var dump winFwDump
	if err := json.Unmarshal(raw, &dump); err != nil {
		return snap, fmt.Errorf("firewall response: %w", err)
	}
	for _, p := range dump.Profiles {
		enabled := "off"
		if p.Enabled {
			enabled = "on"
		}
		snap.Profiles = append(snap.Profiles, firewallProfile{
			Name: p.Name, Enabled: enabled,
			DefaultIn:  strings.ToLower(strings.TrimSpace(p.Din)),
			DefaultOut: strings.ToLower(strings.TrimSpace(p.Dout)),
		})
	}
	for _, r := range dump.Rules {
		pol := "block"
		if strings.EqualFold(strings.TrimSpace(r.Action), "allow") {
			pol = "allow"
		}
		dir := "in"
		if strings.EqualFold(strings.TrimSpace(r.Dir), "outbound") {
			dir = "out"
		}
		prog := strings.TrimSpace(r.Prog)
		snap.Rules = append(snap.Rules, firewallRule{
			Ident: strings.ToLower(prog), App: firewallAppName(prog), Path: prog,
			Policy: pol, Dir: dir, Profile: strings.TrimSpace(r.Prof),
			Detail: strings.TrimSpace(r.Name),
		})
	}
	if snap.Global == "" {
		snap.Global = "unknown"
	}
	return snap, nil
}

// ---- Linux -----------------------------------------------------------------

func readFirewallLinux() (firewallSnapshot, error) {
	snap := firewallSnapshot{Source: "Linux host firewall"}
	backends := []string{}
	if out, err := RunOut(5*time.Second, "firewall-cmd", "--state"); err == nil &&
		strings.TrimSpace(out) == "running" {
		snap.Global = "on"
		backends = append(backends, "firewalld (running)")
	}
	if snap.Global == "" {
		if raw, err := os.ReadFile("/etc/ufw/ufw.conf"); err == nil &&
			strings.Contains(string(raw), "ENABLED=yes") {
			snap.Global = "on"
			backends = append(backends, "ufw (enabled)")
		}
	}
	if snap.Global == "" {
		for _, unit := range []string{"firewalld", "nftables", "iptables", "netfilter-persistent"} {
			if out, err := RunOut(4*time.Second, "systemctl", "is-active", unit); err == nil &&
				strings.TrimSpace(out) == "active" {
				snap.Global = "on"
				backends = append(backends, unit+" (active)")
			}
		}
	}
	if out, err := RunOut(6*time.Second, "nft", "list", "ruleset"); err == nil &&
		strings.TrimSpace(out) != "" {
		snap.Notes = append(snap.Notes,
			fmt.Sprintf("nftables ruleset readable: %d chain(s)", strings.Count(out, "chain ")))
	} else {
		snap.Notes = append(snap.Notes,
			"rule details need root (nft/iptables); showing backend state only")
	}
	if snap.Global == "" {
		snap.Global = "unknown"
		snap.Notes = append(snap.Notes,
			"no firewall backend detected as active — the host may have no firewall enabled")
	} else {
		snap.Notes = append(snap.Notes, "backends: "+strings.Join(backends, ", "))
	}
	return snap, nil
}

// ---- BSD -------------------------------------------------------------------

func readFirewallBSD() (firewallSnapshot, error) {
	snap := firewallSnapshot{Source: "BSD packet filter (pf)"}
	out, err := RunOut(5*time.Second, "pfctl", "-s", "info")
	if err != nil {
		snap.Global = "unknown"
		snap.Notes = append(snap.Notes, "pf state requires root to read (pfctl -s info)")
		return snap, nil
	}
	switch {
	case strings.Contains(out, "Status: Enabled"):
		snap.Global = "on"
	case strings.Contains(out, "Status: Disabled"):
		snap.Global = "off"
	default:
		snap.Global = "unknown"
	}
	return snap, nil
}

// ---- baseline diff ---------------------------------------------------------

// firewallSnapshotMap flattens a snapshot into the string map the baseline
// diffs against. Rule keys collapse profile scope (a program with conflicting
// rules on different profiles keeps the last parsed policy).
func firewallSnapshotMap(snap firewallSnapshot) map[string]string {
	m := map[string]string{"global": snap.Global}
	if snap.BlockAll != "" {
		m["blockall"] = snap.BlockAll
	}
	if snap.Stealth != "" {
		m["stealth"] = snap.Stealth
	}
	for _, p := range snap.Profiles {
		m["profile|"+p.Name] = p.Enabled
		m["policy|"+p.Name+"|in"] = p.DefaultIn
		m["policy|"+p.Name+"|out"] = p.DefaultOut
	}
	for _, r := range snap.Rules {
		m["rule|"+r.Dir+"|"+r.Ident] = r.Policy
	}
	return m
}

// firewallDiff turns baseline-to-current firewall changes into findings.
// Alarm direction only: off/allow transitions; removals and tightenings get
// one info-level firewall_change so the dashboard still shows movement.
func firewallDiff(prev, cur map[string]string) []Finding {
	findings := []Finding{}
	reported := map[string]bool{}
	if prev["global"] == "on" && cur["global"] == "off" {
		findings = append(findings, Finding{
			Check: "firewall", Severity: SevHigh,
			Title: "Firewall turned off",
			Detail: "The host firewall was switched from on to off. On macOS: " +
				"System Settings → Network → Firewall. On Windows: wf.msc. " +
				"Re-enable unless this was you.",
			Evidence:    map[string]any{"was": "on", "now": "off"},
			Fingerprint: FingerprintOf("firewall_off", "global"),
		})
		reported["global"] = true
	}
	for k, v := range cur {
		switch {
		case strings.HasPrefix(k, "profile|") && v == "off" && prev[k] == "on":
			findings = append(findings, Finding{
				Check: "firewall", Severity: SevMedium,
				Title: fmt.Sprintf("Firewall profile %s disabled", strings.TrimPrefix(k, "profile|")),
				Detail: "A Windows firewall profile was switched off — all inbound " +
					"filtering for that profile stops with it.",
				Evidence:    map[string]any{"profile": strings.TrimPrefix(k, "profile|"), "was": "on", "now": "off"},
				Fingerprint: FingerprintOf("firewall_profile_off", k),
			})
			reported[k] = true
		case strings.HasPrefix(k, "policy|") && prev[k] == "block" && v == "allow":
			findings = append(findings, Finding{
				Check: "firewall", Severity: SevMedium,
				Title: fmt.Sprintf("Firewall default policy opened: %s", strings.TrimPrefix(k, "policy|")),
				Detail: "Default firewall policy changed from block to allow — " +
					"this is the 'allow all incoming/outgoing connections' switch " +
					"for that profile.",
				Evidence:    map[string]any{"key": k, "was": "block", "now": "allow"},
				Fingerprint: FingerprintOf("firewall_policy", k),
			})
			reported[k] = true
		case strings.HasPrefix(k, "rule|") && v == "allow" && prev[k] != "allow":
			findings = append(findings, Finding{
				Check: "firewall", Severity: SevMedium,
				Title: fmt.Sprintf("Firewall now allows an app: %s", strings.TrimPrefix(k, "rule|")),
				Detail: "An application gained an explicit allow rule (or an app " +
					"that was blocked is now allowed). Inbound-accepting apps are " +
					"how remote attackers first reach a machine.",
				Evidence:    map[string]any{"key": k, "was": prev[k], "now": "allow"},
				Fingerprint: FingerprintOf("firewall_allow", k),
			})
			reported[k] = true
		case k == "blockall" && prev[k] == "on" && v == "off":
			findings = append(findings, Finding{
				Check: "firewall", Severity: SevLow,
				Title:  "Block-all incoming disabled",
				Detail: "The firewall's block-all-incoming mode was switched off; " +
					"per-app rules apply again.",
				Evidence:    map[string]any{"was": "on", "now": "off"},
				Fingerprint: FingerprintOf("firewall_blockall", "off"),
			})
			reported[k] = true
		case k == "stealth" && prev[k] == "on" && v == "off":
			findings = append(findings, Finding{
				Check: "firewall", Severity: SevLow,
				Title:  "Stealth mode disabled",
				Detail: "The firewall stopped dropping unsolicited probes silently; " +
					"the machine answers per normal IP semantics and is slightly " +
					"easier to map.",
				Evidence:    map[string]any{"was": "on", "now": "off"},
				Fingerprint: FingerprintOf("firewall_stealth", "off"),
			})
			reported[k] = true
		}
	}
	changed := []string{}
	for k, v := range cur {
		if pk, ok := prev[k]; ok && pk != v && !reported[k] {
			changed = append(changed, k+": "+pk+" → "+v)
		}
	}
	for k := range prev {
		if _, ok := cur[k]; !ok {
			changed = append(changed, k+": removed")
		}
	}
	if len(changed) > 0 {
		sort.Strings(changed)
		findings = append(findings, Finding{
			Check: "firewall", Severity: SevInfo,
			Title: fmt.Sprintf("Firewall configuration changed (%d)", len(changed)),
			Detail: strings.Join(changed, "; "),
			Evidence: map[string]any{"changes": changed},
			Fingerprint: FingerprintOf("firewall_change",
				fmt.Sprint(len(changed))+"|"+changed[0]),
		})
	}
	return findings
}

// firewallFindings is the engine's slow "firewall" check.
func firewallFindings(store *Store) []Finding {
	snap, err := readFirewall()
	if err != nil {
		return []Finding{{Check: "firewall", Severity: SevInfo,
			Title: "Firewall scan unavailable", Detail: FmtErr(err)}}
	}
	findings := []Finding{}

	// Transient posture findings — current state, surfaced every scan so a
	// pre-existing bad state is visible even though the baseline learned it.
	if snap.Global == "off" {
		findings = append(findings, Finding{
			Check: "firewall", Severity: SevMedium,
			Title:  "Firewall is disabled",
			Detail: snap.Source + " reports the firewall is off. On macOS: System " +
				"Settings → Network → Firewall; on Windows: wf.msc.",
		})
	} else if snap.Global == "unknown" {
		findings = append(findings, Finding{
			Check: "firewall", Severity: SevInfo,
			Title:  "Firewall state undetermined",
			Detail: snap.Source + ": " + strings.Join(snap.Notes, "; "),
		})
	}
	for _, p := range snap.Profiles {
		if p.Enabled == "off" {
			findings = append(findings, Finding{
				Check: "firewall", Severity: SevMedium,
				Title: fmt.Sprintf("Firewall profile %s is disabled", p.Name),
				Detail: snap.Source + " profile " + p.Name +
					" is off — no inbound filtering while it is the active profile.",
			})
		}
	}

	cur := firewallSnapshotMap(snap)
	prevVal, existed := store.BaselineKey("firewall", mapToAny(cur))
	if existed {
		prev, _ := prevVal.(map[string]any)
		prevMap := map[string]string{}
		for k, v := range prev {
			prevMap[k] = fmt.Sprint(v)
		}
		findings = append(findings, firewallDiff(prevMap, cur)...)
	}
	store.BaselineUpdate("firewall", mapToAny(cur))
	return findings
}

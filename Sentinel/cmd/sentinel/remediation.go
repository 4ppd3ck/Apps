package main

// Remediation — the deliberate exception to Sentinel's detection-only
// stance: user-initiated, per-entry actions from the App access tab.
//   - TCC grant removal (macOS): delete a leftover/unwanted grant row from
//     the user TCC database (row is backed up first). System-database rows
//     are root-owned and returned as a sudo command instead.
//   - Firewall rule changes: block/allow/remove an app's firewall rule.
//     macOS: socketfilterfw (incoming only), run through an osascript
//     administrator-privilege prompt. Windows: New/Remove-NetFirewallRule
//     through a UAC elevation. Linux/BSD packet filters cannot match per
//     app, so no buttons are offered there.
//   - LaunchDaemon / LaunchAgent / privileged-helper removal (macOS):
//     unload from launchd and delete the file, via an administrator prompt.
//   - Guardrails: remediation refuses Apple-owned targets server-side —
//     com.apple.* launchd items (by filename and plist Label), firewall
//     entries for system-path binaries, and com.apple.* TCC grants — so a
//     misclick or bad request cannot delete OS-critical files, rules or
//     grants.
//
// Everything is explicit and confirmed in the UI; nothing runs unattended.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// tccIdentRe guards every string interpolated into sqlite3 SQL arguments.
var tccIdentRe = regexp.MustCompile(`^[A-Za-z0-9 ._/+@=-]+$`)

func tccIdentValid(s string) bool {
	return s != "" && len(s) < 512 && tccIdentRe.MatchString(s) && !strings.ContainsAny(s, `';"`)
}

// systemPathPrefixes are macOS locations whose files and TCC grants belong
// to the OS itself; Sentinel refuses remediation actions against them.
var systemPathPrefixes = []string{"/System", "/usr", "/bin", "/sbin", "/private/var/db"}

// systemPathProtected reports whether path is inside (or equals) one of the
// system-owned locations.
func systemPathProtected(path string) bool {
	clean := filepath.Clean(path)
	for _, p := range systemPathPrefixes {
		if clean == p || strings.HasPrefix(clean, p+"/") {
			return true
		}
	}
	return false
}

// tccClientProtected blocks removal of Apple's own TCC grants: deleting
// system rows (FDA for mds, screen recording for controlcenter, grants held
// by /usr/libexec tools, …) can break macOS services, and tccd re-creates
// them anyway.
func tccClientProtected(client string) bool {
	return strings.HasPrefix(strings.ToLower(client), "com.apple.") ||
		(strings.HasPrefix(client, "/") && systemPathProtected(client))
}

// ---- TCC grant removal -----------------------------------------------------

// tccRemove deletes a TCC grant row. override bypasses the Apple/system
// guardrail for expert use (the UI's Guardrails toggle).
func tccRemove(dataDir, client, service string, override bool) (string, error) {
	if runtime.GOOS != "darwin" {
		return "", fmt.Errorf("TCC removal is macOS-only")
	}
	if !tccIdentValid(client) || !tccIdentValid(service) {
		return "", fmt.Errorf("invalid client or service identifier")
	}
	if !override && tccClientProtected(client) {
		return "", fmt.Errorf("refusing to remove an Apple system TCC grant for %s — "+
			"removing macOS's own grants can break system services; change it in "+
			"System Settings, or turn Guardrails off in the App Access header to "+
			"proceed anyway", client)
	}
	home, _ := os.UserHomeDir()
	userDB := filepath.Join(home, "Library", "Application Support", "com.apple.TCC", "TCC.db")
	sysDB := "/Library/Application Support/com.apple.TCC/TCC.db"
	where := fmt.Sprintf("where client='%s' and service='%s'", client, service)

	// Locate the grant: user database first (removable without root).
	found := ""
	for _, db := range []string{userDB, sysDB} {
		out, err := RunOut(6*time.Second, "sqlite3", "-csv", db,
			"select auth_value from access "+where+";")
		if err != nil {
			continue
		}
		if strings.TrimSpace(out) != "" {
			found = db
			break
		}
	}
	if found == "" {
		return "", fmt.Errorf("no TCC row for %s / %s is visible — if the grant "+
			"is in the system database, the querying process needs Full Disk "+
			"Access to see it", client, service)
	}
	if found == sysDB {
		rows, err := tccBackupRows(sysDB, where)
		if err != nil {
			return "", fmt.Errorf("could not back up system TCC grant: %w", err)
		}
		if err := appendTCCBackup(dataDir, map[string]string{
			"ts": fmt.Sprint(NowF()), "db": "system",
			"client": client, "service": service, "rows": rows,
		}); err != nil {
			return "", fmt.Errorf("could not save system TCC backup: %w", err)
		}
		command := fmt.Sprintf("/usr/bin/sqlite3 %q %q", sysDB, "delete from access "+where+";")
		if _, err := runMacAdmin(command); err != nil {
			return "", fmt.Errorf("system TCC removal failed: %w", err)
		}
		out, err := RunOut(6*time.Second, "sqlite3", "-csv", sysDB,
			"select client from access "+where+";")
		if err != nil {
			return "", fmt.Errorf("could not verify system TCC removal: %w", err)
		}
		if strings.TrimSpace(out) != "" {
			return "", fmt.Errorf("system TCC row still present after delete")
		}
		return "removed " + service + " grant for " + client +
			" (system database backup saved to tcc-removed-backup.jsonl)", nil
	}

	// Back up the affected rows, then delete and verify.
	rows, err := tccBackupRows(userDB, where)
	if err != nil {
		return "", fmt.Errorf("could not back up user TCC grant: %w", err)
	}
	if err := appendTCCBackup(dataDir, map[string]string{
		"ts": fmt.Sprint(NowF()), "db": "user",
		"client": client, "service": service, "rows": rows,
	}); err != nil {
		return "", fmt.Errorf("could not save user TCC backup: %w", err)
	}
	if err := runSQLite(userDB, "delete from access "+where+";"); err != nil {
		return "", fmt.Errorf("TCC delete failed (does the host app have Full "+
			"Disk Access?): %w", err)
	}
	out, err := RunOut(6*time.Second, "sqlite3", "-csv", userDB,
		"select client from access "+where+";")
	if err == nil && strings.TrimSpace(out) != "" {
		return "", fmt.Errorf("row still present after delete — TCCd may have " +
			"re-created it; check System Settings → Privacy & Security")
	}
	return "removed " + service + " grant for " + client +
		" (backup row saved to tcc-removed-backup.jsonl)", nil
}

func tccBackupRows(db, where string) (string, error) {
	rows, err := RunOut(6*time.Second, "sqlite3", "-csv", db,
		"select service, client, auth_value, last_used_time from access "+where+";")
	if err != nil {
		rows, err = RunOut(6*time.Second, "sqlite3", "-csv", db,
			"select service, client, auth_value from access "+where+";")
		if err != nil {
			return "", err
		}
	}
	if strings.TrimSpace(rows) == "" {
		return "", fmt.Errorf("grant row disappeared before backup")
	}
	return rows, nil
}

func runSQLite(db, sql string) error {
	out, err := RunOut(8*time.Second, "sqlite3", db, sql)
	if err != nil {
		if out != "" {
			return fmt.Errorf("%w: %s", err, out)
		}
		return err
	}
	return nil
}

func appendTCCBackup(dataDir string, entry map[string]string) error {
	raw, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dataDir, "tcc-removed-backup.jsonl"),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(raw, '\n'))
	return err
}

// ---- firewall rule changes -------------------------------------------------

const macSocketFilterFW = "/usr/libexec/ApplicationFirewall/socketfilterfw"

// firewallSetRule changes an app's firewall rule. override bypasses the
// system-path guardrail for expert use (the UI's Guardrails toggle).
func firewallSetRule(action, dir, path string, override bool) (string, error) {
	switch runtime.GOOS {
	case "darwin":
		return firewallSetRuleMac(action, dir, path, override)
	case "windows":
		return firewallSetRuleWindows(action, dir, path)
	case "linux", "freebsd", "openbsd", "netbsd":
		return "", fmt.Errorf("per-app firewall rules are not supported on %s — "+
			"pf/nftables/iptables match ports and interfaces, not applications", runtime.GOOS)
	}
	return "", fmt.Errorf("firewall rule changes not implemented on %s", runtime.GOOS)
}

// firewallMacCommand builds the (unescalated) shell command for the action.
// Split out for tests. override skips the system-path guardrail.
func firewallMacCommand(action, path string, override bool) (string, error) {
	if !strings.HasSuffix(path, ".app") || strings.ContainsAny(path, "`$&;|<>") {
		return "", fmt.Errorf("expected an installed .app bundle path, got %q", path)
	}
	if !override && systemPathProtected(path) {
		return "", fmt.Errorf("refusing firewall changes for macOS system software (%s) — "+
			"these entries are managed by the OS; turn Guardrails off in the App "+
			"Access header to proceed anyway", path)
	}
	// Double-quote shell quoting; " is escaped, $ ` ; etc. are rejected above.
	q := `"` + strings.ReplaceAll(path, `"`, `\"`) + `"`
	switch action {
	case "block":
		return macSocketFilterFW + " --blockapp " + q, nil
	case "allow":
		// --add is idempotent and registers apps not yet in the list, which
		// --unblockapp alone requires.
		return macSocketFilterFW + " --add " + q + " && " + macSocketFilterFW +
			" --unblockapp " + q, nil
	case "remove":
		return macSocketFilterFW + " --remove " + q, nil
	}
	return "", fmt.Errorf("unknown firewall action %q", action)
}

func firewallSetRuleMac(action, dir, path string, override bool) (string, error) {
	if dir != "in" {
		return "", fmt.Errorf("macOS's application firewall cannot filter " +
			"outbound connections per app (incoming only)")
	}
	cmd, err := firewallMacCommand(action, path, override)
	if err != nil {
		return "", err
	}
	if _, err := runMacAdmin(cmd); err != nil {
		msg := FmtErr(err)
		if strings.Contains(strings.ToLower(msg), "cancel") {
			return "", fmt.Errorf("administrator prompt was cancelled — no changes made")
		}
		return "", fmt.Errorf("%w. You can run it manually: sudo %s", err, cmd)
	}
	switch action {
	case "block":
		return "blocked incoming connections for " + path, nil
	case "allow":
		return "allowed incoming connections for " + path, nil
	default:
		return "removed the firewall entry for " + path, nil
	}
}

// runMacAdmin runs a shell command through an osascript administrator-
// privilege prompt (the system password dialog). %q quoting is compatible
// with AppleScript string literals for the ASCII commands built here.
func runMacAdmin(cmd string) (string, error) {
	script := fmt.Sprintf("do shell script %q with administrator privileges", cmd)
	return RunOut(150*time.Second, "osascript", "-e", script)
}

// daemonLabel reads a launchd plist's Label via plutil. Empty when
// unreadable — PrivilegedHelperTools binaries are not plists and carry no
// label, so the filename check in daemonRemoveCommand covers those.
func daemonLabel(path string) string {
	out, err := RunOut(4*time.Second, "plutil", "-extract", "Label", "raw", "-o", "-", path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// daemonRemoveCommand builds the shell command that unloads (if the path is
// a launchd plist) and deletes a third-party daemon/agent/helper file.
// Split out for tests; user input only ever lands in the quoted path.
// override skips the com.apple.* filename guardrail.
func daemonRemoveCommand(path string, override bool) (string, error) {
	clean := filepath.Clean(path)
	if strings.ContainsAny(clean, "\"`$") || strings.Contains(clean, "..") {
		return "", fmt.Errorf("invalid path %q", path)
	}
	if !override && strings.HasPrefix(filepath.Base(clean), "com.apple.") {
		return "", fmt.Errorf("%s is part of macOS (com.apple.*) and cannot be removed "+
			"here; turn Guardrails off in the App Access header to proceed anyway", clean)
	}
	domain := ""
	switch {
	case strings.HasPrefix(clean, "/Library/LaunchDaemons/"):
		domain = "system"
	case strings.HasPrefix(clean, "/Library/LaunchAgents/"):
		domain = "gui"
	case strings.HasPrefix(clean, "/Library/PrivilegedHelperTools/"):
		domain = ""
	default:
		return "", fmt.Errorf("only items under /Library/LaunchDaemons, " +
			"/Library/LaunchAgents and /Library/PrivilegedHelperTools can be removed here")
	}
	q := `"` + clean + `"`
	switch domain {
	case "system":
		return "/bin/launchctl bootout system " + q + " 2>/dev/null; /bin/rm -f " + q, nil
	case "gui":
		// /Library/LaunchAgents run in the console user's gui domain; the
		// elevated shell runs as root, so resolve the console uid on disk.
		return "/bin/launchctl bootout gui/$(/usr/bin/stat -f %u /dev/console) " +
			q + " 2>/dev/null; /bin/rm -f " + q, nil
	}
	return "/bin/rm -f " + q, nil
}

// daemonRemove unloads and deletes a third-party LaunchDaemon/LaunchAgent
// plist or a PrivilegedHelperTools binary, with an administrator prompt.
// override bypasses the Apple guardrails for expert use.
func daemonRemove(path string, override bool) (string, error) {
	if runtime.GOOS != "darwin" {
		return "", fmt.Errorf("daemon removal is macOS-only")
	}
	cmd, err := daemonRemoveCommand(path, override)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(filepath.Clean(path)); err != nil {
		return "", fmt.Errorf("%s no longer exists — refresh the inventory", filepath.Clean(path))
	}
	if !override {
		if label := daemonLabel(filepath.Clean(path)); strings.HasPrefix(label, "com.apple.") {
			return "", fmt.Errorf("launchd label %q belongs to macOS and cannot be removed "+
				"here; turn Guardrails off in the App Access header to proceed anyway", label)
		}
	}
	if _, err := runMacAdmin(cmd); err != nil {
		msg := FmtErr(err)
		if strings.Contains(strings.ToLower(msg), "cancel") {
			return "", fmt.Errorf("administrator prompt was cancelled — no changes made")
		}
		return "", fmt.Errorf("%w. You can run it manually: sudo %s", err, cmd)
	}
	return "deleted " + filepath.Clean(path) + " (unloaded from launchd if it was loaded)", nil
}

// winRuleName is the display name of the rule Sentinel manages for a program.
// Only rules carrying this prefix are ever deleted by "remove"/"allow".
func winRuleName(action, base string, dir string) string {
	d := "in"
	if dir == "out" {
		d = "out"
	}
	return "Sentinel " + action + " " + base + " (" + d + ")"
}

// firewallWinScript builds the elevated PowerShell command for the action.
// Split out for tests.
func firewallWinScript(action, dir, path string) (string, error) {
	if dir != "in" && dir != "out" {
		return "", fmt.Errorf("invalid direction %q", dir)
	}
	if strings.ContainsAny(path, "`'\"") ||
		!((len(path) >= 3 && path[1] == ':' && path[2] == '\\') || strings.HasPrefix(path, `\\`)) {
		return "", fmt.Errorf("expected an absolute Windows program path, got %q", path)
	}
	base := firewallAppName(path)
	direction := "Inbound"
	if dir == "out" {
		direction = "Outbound"
	}
	blockName := winRuleName("block", base, dir)
	allowName := winRuleName("allow", base, dir)
	prog := "'" + path + "'"
	var inner string
	switch action {
	case "block":
		inner = fmt.Sprintf("New-NetFirewallRule -DisplayName '%s' -Direction %s -Action Block -Program %s | Out-Null",
			blockName, direction, prog)
	case "allow":
		inner = fmt.Sprintf("Remove-NetFirewallRule -DisplayName '%s' -ErrorAction SilentlyContinue; "+
			"New-NetFirewallRule -DisplayName '%s' -Direction %s -Action Allow -Program %s | Out-Null",
			blockName, allowName, direction, prog)
	case "remove":
		inner = fmt.Sprintf("Remove-NetFirewallRule -DisplayName '%s','%s' -ErrorAction SilentlyContinue",
			blockName, allowName)
	default:
		return "", fmt.Errorf("unknown firewall action %q", action)
	}
	// Wrap in a UAC elevation; propagate the elevated process's exit code so
	// a declined prompt or failed cmdlet surfaces as an error here.
	escaped := strings.ReplaceAll(inner, "'", "''")
	return "try { $p = Start-Process powershell -Verb RunAs -Wait -PassThru " +
		"-WindowStyle Hidden -ArgumentList '-NoProfile','-Command','" + escaped +
		"'; exit $p.ExitCode } catch { exit 1 }", nil
}

func firewallSetRuleWindows(action, dir, path string) (string, error) {
	script, err := firewallWinScript(action, dir, path)
	if err != nil {
		return "", err
	}
	if _, err := RunOut(150*time.Second, "powershell", "-NoProfile", "-Command", script); err != nil {
		return "", fmt.Errorf("%w. Run it manually from an elevated prompt: %s", err, script)
	}
	return action + " rule for " + path + " (" + dir + "bound) applied", nil
}

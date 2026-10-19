// Privileged-blocking grant flow: the dashboard's Grant button.
//
// Blocking enforcement needs firewall privileges (pf/socketfilterfw on
// macOS, iptables on Linux, netsh on Windows) that the monitor deliberately
// does not run with. The compromise is a one-time grant: an elevated run of
// scripts/grant_block_<os>.* installs a small validating drop-only helper
// plus the minimum privilege to invoke it, and the monitor keeps running
// unelevated forever after.
//
// The scripts ship embedded in this binary (a single-file AppDeck build
// carries no scripts/ folder on disk) and are materialized beside the
// config on every start, so the elevation commands below always have a
// real file to run:
//
//	macOS    osascript "do shell script ... with administrator privileges"
//	         -- the native password sheet, same as any installer
//	Linux    pkexec sh grant_block_linux.sh -- the polkit dialog
//	Windows  PowerShell Start-Process -Verb RunAs -- one UAC prompt
//
// Both elevation dialogs run interactively on the console user's session,
// so the endpoint is loopback-only (a phone on the LAN must not be able to
// pop password dialogs on the host).
package monitor

import (
	"embed"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

//go:embed scripts
var scriptsFS embed.FS

// MaterializeScripts writes the packaged scripts/ folder (the validating
// helper plus its per-OS grant scripts) into dir -- the config directory's
// scripts/ subfolder, exactly where helperSrcPath's root fallback and
// runGrantScript expect them. It runs at every startup and overwrites
// unconditionally, so a monitor update refreshes the installed helper the
// next time the app starts.
func MaterializeScripts(dir string) error {
	if dir == "" {
		return fmt.Errorf("no scripts dir resolved")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	entries, err := fs.ReadDir(scriptsFS, "scripts")
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		body, err := scriptsFS.ReadFile("scripts/" + e.Name())
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), body, 0o755); err != nil {
			return err
		}
	}
	return nil
}

// grantScript returns (name, exists) for a grant target on this platform:
// "block" (firewall enforcement) or "files" (read-only fs_usage tracing,
// macOS only -- Linux traces files unprivileged via /proc, Windows via
// FileSystemWatcher, so neither needs a grant).
func grantScript(target string) (string, bool) {
	switch target {
	case "block":
		switch runtime.GOOS {
		case "darwin":
			return "grant_block_macos.sh", true
		case "linux":
			return "grant_block_linux.sh", true
		case "windows":
			return "grant_block_windows.ps1", true
		}
	case "files":
		if runtime.GOOS == "darwin" {
			return "grant_files_macos.sh", true
		}
	}
	return "", false
}

// runGrantScript elevates the grant script through the platform's native
// dialog and waits for it to finish. The returned string is combined output
// (survives for the dashboard's error detail).
func runGrantScript(ctx *Ctx, target string, revoke bool) (int, string) {
	name, ok := grantScript(target)
	if !ok {
		return 2, "no " + target + " grant script for " + runtime.GOOS
	}
	if err := MaterializeScripts(filepath.Join(filepath.Dir(ctx.Cfg.Path), "scripts")); err != nil {
		return 2, "cannot materialize scripts: " + err.Error()
	}
	script := filepath.Join(filepath.Dir(ctx.Cfg.Path), "scripts", name)
	arg := ""
	if revoke {
		arg = " --revoke"
	}
	var cmd []string
	switch runtime.GOOS {
	case "darwin":
		// Two quoting layers: the shell command inside AppleScript's
		// "do shell script", then the AppleScript string literal itself.
		shPath := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "$", `\$`, "`", "\\`").
			Replace(script)
		inner := fmt.Sprintf(`sh "%s"%s`, shPath, arg)
		asInner := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(inner)
		cmd = []string{"osascript", "-e",
			fmt.Sprintf(`do shell script "%s" with administrator privileges`, asInner)}
	case "linux":
		cmd = []string{"pkexec", "sh", script}
		if revoke {
			cmd = append(cmd, "--revoke")
		}
	case "windows":
		inner := fmt.Sprintf(`-NoProfile -ExecutionPolicy Bypass -File "%s"`, script)
		if revoke {
			inner += " -Revoke"
		}
		ps := fmt.Sprintf(`Start-Process powershell -Verb RunAs -Wait -PassThru `+
			`-ArgumentList '%s' | ForEach-Object { exit $_.ExitCode }`, inner)
		cmd = []string{"powershell", "-NoProfile", "-Command", ps}
	default:
		return 2, "no grant flow for " + runtime.GOOS
	}
	rc, out, errOut := Run(cmd, 15*time.Minute)
	return rc, strings.TrimSpace(out + errOut)
}

// filesCollector returns the files-category collector, if built (the BSDs
// and any future build without one have none).
func filesCollector(ctx *Ctx) Collector {
	for _, c := range ctx.Collectors() {
		if c.Category() == "files" {
			return c
		}
	}
	return nil
}

// fsusageSudoers is the file scripts/grant_files_macos.sh installs. Its
// NAME is the grant's state marker: the sudoers.d directory itself is world
// listable and stat needs no privileges, so the padlock state is a plain
// file check -- reliable and side-effect free (unlike `sudo -l`, which
// auth-gates when no valid timestamp exists, and unlike running fs_usage,
// which would briefly claim the singleton kernel trace on every status
// poll).
const fsusageSudoers = "/etc/sudoers.d/appscope-fsusage"

// filesGrantInstalled reports whether the on-demand fs_usage grant is
// installed.
func filesGrantInstalled() bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	_, err := os.Stat(fsusageSudoers)
	return err == nil
}

// Grant runs the target's grant (or revoke) script elevated, then re-probes
// the enforcer and re-applies every stored block rule. The response payload
// is ready for writeJSON: {"ok", "mode", "reason", "applied"|"error"}.
func Grant(ctx *Ctx, target, action string) (map[string]any, int) {
	if _, ok := grantScript(target); !ok {
		return map[string]any{"ok": false,
			"error": target + " grants are not supported on " + PlatformString()}, 400
	}
	revoke := action == "revoke"
	// File tracing is ON-DEMAND: revoking stops the collector first, while
	// its sudo wrapper can still relay a TERM to the root fs_usage child --
	// removing the sudoers entry alone would leave a root stream running
	// until the next stop.
	if target == "files" && revoke {
		if files := filesCollector(ctx); files != nil {
			files.Stop()
			files.SetStatus("unavailable", "stopping — removing the on-demand grant…")
		}
	}
	rc, out := runGrantScript(ctx, target, revoke)
	if rc != 0 {
		// osascript reports "User canceled." (-128) when the password sheet
		// is dismissed -- a user choice, not a failure to shout about.
		if strings.Contains(out, "User canceled") {
			return map[string]any{"ok": false, "error": "cancelled",
				"canceled": true}, 400
		}
		detail := out
		if detail == "" {
			detail = fmt.Sprintf("exit %d", rc)
		}
		return map[string]any{"ok": false,
			"error": truncate(detail, 300)}, 500
	}
	if target == "files" {
		files := filesCollector(ctx)
		payload := map[string]any{"ok": true, "installed": !revoke}
		if files == nil {
			return payload, 200
		}
		if revoke {
			files.SetStatus("unavailable",
				"tracing is on-demand — grant it with the padlock to trace again")
			return payload, 200
		}
		if !files.Enabled() {
			return payload, 200
		}
		if ok, reason := files.Available(); ok {
			files.Start()
		} else {
			files.SetStatus("unavailable", reason)
		}
		return payload, 200
	}
	enf := ctx.Enforcer
	if enf == nil {
		return map[string]any{"ok": true, "warning": "enforcer unavailable"}, 200
	}
	mode := enf.Probe()
	applied := 0
	verb := "granted"
	if revoke {
		verb = "revoked"
	}
	// reconcile in BOTH directions: after a grant it re-applies the queued
	// rules; after a revoke it flips still-"enforced" rows back to queued
	// (Apply reports queued with the current no-privilege reason)
	if _, err := enf.Reconcile(); err != nil {
		return map[string]any{"ok": true, "mode": mode, "reason": enf.Reason,
			"warning": verb + ", but re-apply failed: " + err.Error()}, 200
	}
	if rules, err := ctx.Store.ListBlocks(); err == nil {
		applied = len(rules)
	}
	payload := map[string]any{"ok": true, "mode": mode, "reason": enf.Reason,
		"applied": applied}
	if mode == "" && revoke {
		payload["reason"] = "revoked: rules are queued again until the next grant"
	}
	return payload, 200
}

// requestIsLoopback reports whether the request arrived over the loopback
// interface (the local dashboard). Elevated-dialog endpoints must not be
// reachable from the LAN.
func requestIsLoopback(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return host == "127.0.0.1" || host == "::1"
}

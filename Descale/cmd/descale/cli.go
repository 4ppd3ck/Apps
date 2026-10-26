package main

/* CLI mode: the same engine the dashboard uses, scriptable.
 *
 *   descale serve [port]               the dashboard (default; AppDeck passes a port)
 *   descale scan [--json]              buildup report for this machine
 *   descale clean --only a,b [--yes]   plan, or clean with --yes
 *   descale apps                       installed applications
 *   descale startup                    autostart items
 *   descale nudge [--install|--remove|--run]  weekly buildup reminder (macOS)
 *   descale rules genkeys|sign|verify  ed25519-signed rules database
 *   descale version
 *
 * Exit codes: 0 success · 1 failure (unknown command, refused plan,
 * failed items).
 */

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func cliRun(args []string) error {
	cmd, rest := args[0], args[1:]
	srv := &server{root: resolveRoot()}
	switch cmd {
	case "scan":
		return cliScan(srv, rest)
	case "clean":
		return cliClean(srv, rest)
	case "apps":
		return cliApps(srv)
	case "startup":
		return cliStartup(srv)
	case "nudge":
		return cliNudge(srv, rest)
	case "rules":
		return cliRules(rest)
	case "version":
		fmt.Println("descale " + appVersion + " (" + runtime.GOOS + "/" + runtime.GOARCH + ")")
		return nil
	case "help":
		cliUsage()
		return nil
	default:
		cliUsage()
		return fmt.Errorf("unknown command: %s", cmd)
	}
}

func cliNudge(srv *server, args []string) error {
	fs := flag.NewFlagSet("nudge", flag.ContinueOnError)
	install := fs.Bool("install", false, "install the weekly reminder LaunchAgent")
	remove := fs.Bool("remove", false, "remove it")
	run := fs.Bool("run", false, "run the reminder check now")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch {
	case *install:
		return nudgeInstall()
	case *remove:
		return nudgeRemove()
	case *run:
		return nudgeRun(srv)
	default:
		state := "not installed"
		if nudgeInstalled() {
			state = "installed"
		}
		fmt.Println("weekly reminder:", state)
		fmt.Println("use --install / --remove / --run")
		return nil
	}
}

func cliUsage() {
	fmt.Print(`Descale — honest buildup cleaning. Usage:

  descale serve [port]                run the dashboard (default; AppDeck passes a port)
  descale scan [--json]               buildup report for this machine
  descale clean --only a,b [--yes]    plan, or execute with --yes
  descale apps                        list installed applications
  descale startup                     list autostart items
  descale nudge [--install|--remove|--run]  weekly reminder (macOS)
  descale rules genkeys|sign|verify   ed25519-signed rules database
  descale version

Exit codes: 0 success · 1 failure.
`)
}

func humanBytes(n int64) string {
	if n <= 0 {
		return "0 B"
	}
	units := []string{"B", "KB", "MB", "GB", "TB"}
	i := 0
	v := float64(n)
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d B", n)
	}
	return fmt.Sprintf("%.1f %s", v, units[i])
}

func signedNote(signed bool) string {
	if signed {
		return " · rules signature verified"
	}
	return ""
}

/* ---------- scan ---------- */

func cliScan(srv *server, args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "machine-readable output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	db, signed, err := srv.loadRules()
	if err != nil {
		return err
	}
	home := homeDir()
	vars := resolveVars(db)
	results := make([]RuleResult, len(db.Rules))
	for i := range db.Rules {
		results[i] = scanRule(&db.Rules[i], vars, home)
	}
	rep := srv.buildReport(results, time.Now(), 0)
	rep.RulesSigned = signed
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	}
	fmt.Printf("💧 Descale %s — buildup report (%s/%s)%s\n", appVersion, runtime.GOOS, runtime.GOARCH, signedNote(signed))
	for _, r := range rep.Rules {
		switch r.Status {
		case "ok":
			fmt.Printf("  %9s  %-7s %-24s %s\n", humanBytes(r.SizeBytes), r.Safety, r.ID, r.Title)
		case "command":
			fmt.Printf("  %9s  %-7s %-24s %s (manual command)\n", "-", r.Safety, r.ID, r.Title)
		default:
			note := ""
			if r.Status == "blocked" && r.Reason != "" {
				// Keep the line readable: the note already carries the fix hint.
				note = " — " + r.Reason
				if len(note) > 110 {
					note = note[:107] + "…"
				}
			}
			fmt.Printf("          %s  %-24s %s [%s]%s\n", "", r.ID, r.Title, r.Status, note)
		}
	}
	fmt.Printf("\nTotal reclaimable: %s across %d files (safe tier: %s)\n",
		humanBytes(rep.TotalBytes), rep.TotalFiles, humanBytes(rep.SafeBytes))
	return nil
}

/* ---------- clean ---------- */

func cliClean(srv *server, args []string) error {
	fs := flag.NewFlagSet("clean", flag.ContinueOnError)
	only := fs.String("only", "", "comma-separated rule IDs (required)")
	yes := fs.Bool("yes", false, "execute the plan (without it: plan only)")
	jsonOut := fs.Bool("json", false, "machine-readable output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*only) == "" {
		return errors.New("clean requires --only id1,id2 (see: descale scan)")
	}
	ids := strings.Split(*only, ",")
	for i := range ids {
		ids[i] = strings.TrimSpace(ids[i])
	}
	result, err := srv.cleanRules(ids, *yes)
	if err != nil {
		return err
	}
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}
	if planOK, _ := result["confirmRequired"].(bool); planOK {
		fmt.Println("Plan — nothing deleted yet (add --yes to execute):")
		if plan, ok := result["plan"].([]RuleResult); ok {
			for _, p := range plan {
				if p.Status == "ok" {
					fmt.Printf("  %-24s %9s · %d files · %s\n", p.ID, humanBytes(p.SizeBytes), p.FileCount, p.Title)
				} else {
					fmt.Printf("  %-24s [%s] %s\n", p.ID, p.Status, p.Title)
				}
			}
		}
		fmt.Printf("  total: %s\n", humanBytes(toI64(result["totalBytes"])))
		return nil
	}
	failed := toStrMapList(result["failed"])
	fmt.Printf("cleaned %d files · %s moved to the trash · %d failed\n",
		toI(result["files"]), humanBytes(toI64(result["bytes"])), len(failed))
	if h := toI(result["husks"]); h > 0 {
		fmt.Printf("removed %d now-empty folder(s)\n", h)
	}
	for _, f := range failed {
		fmt.Printf("  FAILED %s: %s\n", f["path"], f["error"])
	}
	if len(failed) > 0 {
		return errors.New("some items failed")
	}
	return nil
}

/* ---------- apps / startup ---------- */

func cliApps(srv *server) error {
	d := srv.appsList()
	if d.Note != "" {
		fmt.Println(d.Note)
	}
	for _, a := range d.Apps {
		flag := ""
		if a.Running {
			flag = " (running)"
		}
		fmt.Printf("  %-34s %-40s v%s%s\n", a.Name, a.ID, a.Version, flag)
	}
	fmt.Printf("\n%d applications\n", len(d.Apps))
	return nil
}

func cliStartup(srv *server) error {
	items := listStartup()
	for _, it := range items {
		state := "active"
		if !it.Active {
			state = "deactivated"
		}
		scope := it.Scope
		if it.Scope != "user" {
			scope += " (read-only)"
		}
		fmt.Printf("  [%s] %-8s %-34s %s\n", state, scope, it.Label, it.Program)
	}
	fmt.Printf("\n%d autostart items\n", len(items))
	return nil
}

/* ---------- weekly nudge (macOS) ---------- */

const nudgeLabel = "app.descale.nudge"

func nudgePlistPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", nudgeLabel+".plist")
}

func nudgeInstalled() bool {
	_, err := os.Stat(nudgePlistPath())
	return err == nil
}

func nudgeInstall() error {
	if runtime.GOOS != "darwin" {
		return errors.New("the reminder is macOS-only in this release")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, _ = filepath.Abs(exe)
	uid := os.Getuid()
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>` + nudgeLabel + `</string>
  <key>ProgramArguments</key><array>
    <string>` + exe + `</string><string>nudge</string><string>--run</string>
  </array>
  <key>StartCalendarInterval</key><dict>
    <key>Weekday</key><integer>1</integer>
    <key>Hour</key><integer>10</integer>
    <key>Minute</key><integer>0</integer>
  </dict>
  <key>RunAtLoad</key><false/>
</dict></plist>
`
	p := nudgePlistPath()
	if err := os.WriteFile(p, []byte(plist), 0o644); err != nil {
		return err
	}
	_ = exec.Command("launchctl", "bootstrap", fmt.Sprintf("gui/%d", uid), p).Run()
	fmt.Println("weekly reminder installed:", p)
	return nil
}

func nudgeRemove() error {
	uid := os.Getuid()
	_ = exec.Command("launchctl", "bootout", fmt.Sprintf("gui/%d/%s", uid, nudgeLabel)).Run()
	err := os.Remove(nudgePlistPath())
	if os.IsNotExist(err) {
		fmt.Println("reminder was not installed")
		return nil
	}
	if err != nil {
		return err
	}
	fmt.Println("weekly reminder removed")
	return nil
}

func nudgeRun(srv *server) error {
	db, _, err := srv.loadRules()
	if err != nil {
		return err
	}
	home := homeDir()
	vars := resolveVars(db)
	var total int64
	for i := range db.Rules {
		r := &db.Rules[i]
		if r.Safety != "safe" || !r.enabled() || !ruleApplies(r) {
			continue
		}
		if res := scanRule(r, vars, home); res.Status == "ok" {
			total += res.SizeBytes
		}
	}
	threshold := int64(500) << 20 // 500 MB default
	if v := strings.TrimSpace(os.Getenv("DESCALE_NUDGE_MIN")); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 {
			threshold = n
		}
	}
	fmt.Printf("safe-tier buildup: %s (threshold %s)\n", humanBytes(total), humanBytes(threshold))
	if total < threshold {
		fmt.Println("below threshold — no notification shown")
		return nil
	}
	msg := fmt.Sprintf("%s of buildup is waiting. Open Descale to review.", humanBytes(total))
	script := `display notification "` + msg + `" with title "💧 Descale"`
	if err := exec.Command("osascript", "-e", script).Run(); err != nil {
		return err
	}
	fmt.Println("notification shown")
	return nil
}

func (s *server) handleNudgeStatus(w http.ResponseWriter, r *http.Request) {
	supported := runtime.GOOS == "darwin"
	writeJSON(w, http.StatusOK, map[string]any{"supported": supported, "installed": supported && nudgeInstalled()})
}

func (s *server) handleNudgeToggle(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Install bool `json:"install"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, "bad request body")
		return
	}
	var err error
	if req.Install {
		err = nudgeInstall()
	} else {
		err = nudgeRemove()
	}
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "installed": req.Install})
}

/* ---------- signed rules database ---------- */

const rulesKeyPath = ".descale/rules-ed25519.key" // under home; keep private

func rulesPrivKeyPath() string {
	return filepath.Join(homeDir(), filepath.FromSlash(rulesKeyPath))
}

func cliRules(args []string) error {
	if len(args) == 0 {
		return errors.New("rules: use genkeys | sign <rulesfile> | verify <rulesfile>")
	}
	switch args[0] {
	case "genkeys":
		return rulesGenkeys()
	case "sign":
		if len(args) < 2 {
			return errors.New("sign requires the rules file path")
		}
		return rulesSign(args[1])
	case "verify":
		if len(args) < 2 {
			return errors.New("verify requires the rules file path")
		}
		return rulesVerify(args[1])
	default:
		return errors.New("rules: use genkeys | sign | verify")
	}
}

func rulesGenkeys() error {
	p := rulesPrivKeyPath()
	if _, err := os.Stat(p); err == nil {
		return errors.New("a signing key already exists at " + p + " — delete it deliberately before generating a new one")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(p, []byte(hex.EncodeToString(priv)), 0o600); err != nil {
		return err
	}
	fmt.Println("private key written to:", p)
	fmt.Println("  (keep it private — anyone holding it can sign rule updates)")
	fmt.Println()
	fmt.Println("public key — embed as rulesPubKey in main.go, then rebuild:")
	fmt.Println("  " + hex.EncodeToString(pub))
	return nil
}

func rulesLoadPriv() (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(rulesPrivKeyPath())
	if err != nil {
		return nil, errors.New("no signing key — run: descale rules genkeys")
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("signing key file is corrupt")
	}
	return ed25519.PrivateKey(key), nil
}

func rulesSign(file string) error {
	priv, err := rulesLoadPriv()
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(priv, raw)
	if err := os.WriteFile(file+".sig", []byte(base64.StdEncoding.EncodeToString(sig)), 0o644); err != nil {
		return err
	}
	pub := hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	fmt.Println("signed", file, "->", file+".sig")
	fmt.Println("distribute the .sig next to the rules file; public key (must match rulesPubKey):", pub)
	return nil
}

func rulesVerify(file string) error {
	raw, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(file + ".sig")
	if err != nil {
		return errors.New("no signature file (" + file + ".sig)")
	}
	if err := verifyRulesSignature(raw, sig); err != nil {
		return err
	}
	fmt.Println("signature OK — rules file matches the embedded public key")
	return nil
}

func verifyRulesSignature(raw, sigB64 []byte) error {
	if rulesPubKey == "" {
		return errors.New("no public key embedded in this build")
	}
	pub, err := hex.DecodeString(rulesPubKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("embedded public key is invalid")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigB64)))
	if err != nil {
		return errors.New("signature is not valid base64")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), raw, sig) {
		return errors.New("signature does not match the rules file")
	}
	return nil
}

/* ---------- small conversion helpers for the CLI ---------- */

func toI64(v any) int64 {
	if f, ok := v.(int64); ok {
		return f
	}
	return 0
}

func toI(v any) int {
	if f, ok := v.(int); ok {
		return f
	}
	return 0
}

func toStrMapList(v any) []map[string]string {
	if l, ok := v.([]map[string]string); ok {
		return l
	}
	return nil
}

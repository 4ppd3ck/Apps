package main

/* Rules loading and the rules settings surface.
 *
 * The rules database ships as per-OS files: wpurge-<os>-rules.json (the
 * built-in set) plus wpurge-<os>-extra-rules.json (the extra catalog: AI
 * model caches, dev-tool caches, extra Docker pruning). Only the pair for
 * the running OS is ever loaded, so a Windows machine never evaluates a
 * macOS rule and vice versa. On top of the built-ins an operator can
 * import their own ruleset (~/.wpurge/rules-user.json — user-authored,
 * therefore not signature-pinned; the deletion guardrails apply to it
 * exactly the same). A user rule whose id matches a built-in REPLACES it,
 * which is how an operator tunes minAgeDays or disables a built-in
 * (enabled:false) without touching shipped files.
 *
 * Duplicates are a loud error, never a silent shadow: within any file,
 * across the built-in pair, and (for vars) user-vs-builtin — a user var
 * with the same name replaces the built-in. The one silent case is the
 * intentional one: a user rule replacing a same-id built-in.
 *
 * Extra and user rules can each be switched off under ⚙️ Settings
 * (settings.json "disabledExtras"): a disabled extra is dropped from the
 * effective set entirely, and a disabled user override falls back to the
 * default built-in rule — "unchecked means go with the default ones".
 */

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	rulesMainFmt  = "wpurge-%s-rules.json"
	rulesExtraFmt = "wpurge-%s-extra-rules.json"
	userRulesName = "rules-user.json" // under ~/.wpurge
)

// rule origin tags, set at load time (never from JSON)
const (
	originBuiltin = "builtin"
	originExtra   = "extra"
	originUser    = "user"
	originCustom  = "custom"
)

// loadRulesFile reads one rules JSON file, verifying its .sig when one is
// present, and rejects duplicate rule ids / var names inside the file.
func loadRulesFile(path string) (*RulesDB, bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}
	signed := false
	if sig, err := os.ReadFile(path + ".sig"); err == nil {
		if rulesPubKey == "" {
			return nil, false, errors.New("rules file carries a signature but no public key is embedded in this build")
		}
		if err := verifyRulesSignature(raw, sig); err != nil {
			return nil, false, fmt.Errorf("rules signature INVALID for %s: %w", filepath.Base(path), err)
		}
		signed = true
	}
	var db RulesDB
	if err := json.Unmarshal(raw, &db); err != nil {
		return nil, signed, fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	if err := validateRuleSet(&db, filepath.Base(path)); err != nil {
		return nil, signed, err
	}
	return &db, signed, nil
}

// validateRuleSet rejects the shape a clean could silently mis-run on:
// rules without an id, and duplicate ids or var names inside one file.
func validateRuleSet(db *RulesDB, name string) error {
	ids := map[string]bool{}
	for i := range db.Rules {
		id := strings.TrimSpace(db.Rules[i].ID)
		if id == "" {
			return fmt.Errorf("%s: rule %d has no id", name, i+1)
		}
		if ids[id] {
			return fmt.Errorf("%s: duplicate rule id %q", name, id)
		}
		ids[id] = true
		rule := &db.Rules[i]
		if rule.TrashRoots {
			if len(rule.Paths) != 1 || strings.ContainsAny(rule.Paths[0], "*?[") {
				return fmt.Errorf("%s: rule %q with trashRoots must have exactly one literal path", name, id)
			}
			if len(rule.Exclude) > 0 || rule.MinAgeDays > 0 || rule.MinAgeSetting != "" {
				return fmt.Errorf("%s: rule %q with trashRoots cannot use exclusions or age filters", name, id)
			}
			if rule.Action != "" && rule.Action != "trash" {
				return fmt.Errorf("%s: rule %q with trashRoots must use the Trash action", name, id)
			}
			if rule.Command != "" || rule.Permanent {
				return fmt.Errorf("%s: rule %q with trashRoots cannot be permanent or run a command", name, id)
			}
		}
	}
	vars := map[string]bool{}
	for _, v := range db.Vars {
		if vars[v.Name] {
			return fmt.Errorf("%s: duplicate var %q", name, v.Name)
		}
		vars[v.Name] = true
	}
	return nil
}

// loadRulesRaw assembles the full rule set without applying the extra-rule
// toggles: built-in per-OS files, then the user ruleset overriding by id.
// replaced maps each user-overridden id to the built-in rule it displaced —
// the toggle filter needs it to restore the default. Signed = every loaded
// built-in file carried a verified signature (the user ruleset is unsigned
// by design and does not affect the flag).
func (s *server) loadRulesRaw() (db *RulesDB, replaced map[string]*Rule, signed bool, err error) {
	osName := runtime.GOOS
	signed = true

	db = &RulesDB{Version: 1, Note: "Merged wPurge rules for " + osName}
	varNames := map[string]bool{}
	ids := map[string]bool{}
	mainName := filepath.Base(filepath.Join(s.root, "rules", fmt.Sprintf(rulesMainFmt, osName)))

	addBuiltIn := func(fdb *RulesDB, fname, origin string) {
		for _, v := range fdb.Vars {
			if varNames[v.Name] {
				err = fmt.Errorf("duplicate var %q across %s and %s", v.Name, mainName, fname)
				return
			}
			varNames[v.Name] = true
			db.Vars = append(db.Vars, v)
		}
		for i := range fdb.Rules {
			if ids[fdb.Rules[i].ID] {
				err = fmt.Errorf("duplicate rule id %q across the built-in rules files (%s)", fdb.Rules[i].ID, fname)
				return
			}
			ids[fdb.Rules[i].ID] = true
			fdb.Rules[i].origin = origin
			db.Rules = append(db.Rules, fdb.Rules[i])
		}
	}

	mainPath := filepath.Join(s.root, "rules", fmt.Sprintf(rulesMainFmt, osName))
	mdb, mainSigned, lerr := loadRulesFile(mainPath)
	if lerr != nil {
		if os.IsNotExist(lerr) {
			return nil, nil, false, fmt.Errorf("%s not found under %s/rules — this build loads per-OS rule files", fmt.Sprintf(rulesMainFmt, osName), s.root)
		}
		return nil, nil, false, lerr
	}
	if !mainSigned {
		signed = false
	}
	addBuiltIn(mdb, mainName, originBuiltin)
	if err != nil {
		return nil, nil, false, err
	}

	extraPath := filepath.Join(s.root, "rules", fmt.Sprintf(rulesExtraFmt, osName))
	extraName := filepath.Base(extraPath)
	xdb, extraSigned, lerr := loadRulesFile(extraPath)
	switch {
	case lerr == nil:
		if !extraSigned {
			signed = false
		}
		addBuiltIn(xdb, extraName, originExtra)
		if err != nil {
			return nil, nil, false, err
		}
	case os.IsNotExist(lerr):
		// extras are optional
	default:
		return nil, nil, false, lerr
	}

	// user ruleset: overrides built-ins by id (in place), fresh ids appended
	replaced = map[string]*Rule{}
	udb, _, uerr := loadRulesFile(userRulesPath())
	if uerr == nil {
		for i := range udb.Rules {
			udb.Rules[i].origin = originUser
			for k := range db.Rules {
				if db.Rules[k].ID == udb.Rules[i].ID {
					// copy the built-in aside BEFORE it is overwritten — a
					// pointer into the slice would alias the substitute
					orig := db.Rules[k]
					replaced[udb.Rules[i].ID] = &orig
					db.Rules[k] = udb.Rules[i]
					break
				}
			}
		}
		for i := range udb.Rules {
			if _, wasReplaced := replaced[udb.Rules[i].ID]; !wasReplaced {
				db.Rules = append(db.Rules, udb.Rules[i])
			}
		}
		for _, v := range udb.Vars {
			if varNames[v.Name] {
				// a user var replaces the built-in with the same name
				for k := range db.Vars {
					if db.Vars[k].Name == v.Name {
						db.Vars[k] = v
					}
				}
			} else {
				varNames[v.Name] = true
				db.Vars = append(db.Vars, v)
			}
		}
	} else if !os.IsNotExist(uerr) {
		return nil, nil, false, uerr
	}
	// operator-added folders: one synthetic review rule per folder. These
	// are not toggleable via disabledExtras — the folder list itself is the
	// control (remove = stop scanning), so the disabled filter must not
	// drop them.
	for _, p := range customFoldersList() {
		db.Rules = append(db.Rules, customFolderRule(p))
	}

	return db, replaced, signed, nil
}

// customFolderRule builds the synthetic rule for one operator-added
// folder. Review tier on purpose: the operator chose the folder, not the
// files in it, so nothing inside is ever pre-selected. The id is a hash of
// the path — stable across restarts and reloads, which is what lets a
// scan-offered clean resolve the same rule again. The folder itself is
// never the clean target: collect() walks its CONTENTS, and every path
// inside still passes criticalReason like any other rule's.
func customFolderRule(path string) Rule {
	sum := sha256.Sum256([]byte(filepath.Clean(path)))
	return Rule{
		ID:    "custom-" + hex.EncodeToString(sum[:4]),
		Title: "Folder — " + filepath.Base(filepath.Clean(path)),
		Description: "Folder you added under ⚙️ Settings → Folders to scan: " + filepath.Clean(path) +
			". Its contents are offered for cleaning as review — nothing is pre-selected, the guardrails still apply inside, and the folder itself is never moved. Remove it there to stop scanning it.",
		Category: "Custom",
		Safety:   "review",
		Paths:    []string{filepath.Clean(path)},
		origin:   originCustom,
	}
}

// loadRules is the effective set every scan/clean/info sees: loadRulesRaw
// with the disabled extras filtered out. A disabled extra is dropped; a
// disabled user override restores the built-in default it had replaced.
func (s *server) loadRules() (*RulesDB, bool, error) {
	db, replaced, signed, err := s.loadRulesRaw()
	if err != nil {
		return nil, false, err
	}
	disabled := disabledExtrasSet()
	if len(disabled) == 0 {
		return db, signed, nil
	}
	eff := make([]Rule, 0, len(db.Rules))
	for i := range db.Rules {
		r := db.Rules[i]
		if r.origin != originBuiltin && disabled[r.ID] {
			if orig, ok := replaced[r.ID]; ok {
				eff = append(eff, *orig) // unchecked override → the default rule
			}
			continue
		}
		eff = append(eff, r)
	}
	db.Rules = eff
	return db, signed, nil
}

// userRulesPath is the operator's imported ruleset (unsigned by design).
func userRulesPath() string {
	return filepath.Join(homeDir(), ".wpurge", userRulesName)
}

/* ---------- /api/rules/user (import / view / clear) ---------- */

// validateImportableRule checks one imported rule for the minimum the
// engine needs; safety defaults to review (never pre-checked).
func validateImportableRule(r *Rule, name string, i int) error {
	if strings.TrimSpace(r.ID) == "" {
		return fmt.Errorf("%s: rule %d has no id", name, i+1)
	}
	if strings.TrimSpace(r.Title) == "" {
		return fmt.Errorf("%s: rule %q has no title", name, r.ID)
	}
	switch r.Safety {
	case "", "review":
		r.Safety = "review"
	case "safe":
	default:
		return fmt.Errorf("%s: rule %q has safety %q (use \"safe\" or \"review\")", name, r.ID, r.Safety)
	}
	if r.Action != "command" && len(r.Paths) == 0 {
		return fmt.Errorf("%s: rule %q has no paths", name, r.ID)
	}
	if r.Action == "command" && strings.TrimSpace(r.Command) == "" {
		return fmt.Errorf("%s: command rule %q has no command", name, r.ID)
	}
	return nil
}

func (s *server) handleUserRulesGet(w http.ResponseWriter, r *http.Request) {
	raw, err := os.ReadFile(userRulesPath())
	if os.IsNotExist(err) {
		writeJSON(w, http.StatusOK, map[string]any{"count": 0, "rules": nil,
			"note": "no imported rules — the built-in per-OS set is in effect"})
		return
	}
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	var db RulesDB
	if json.Unmarshal(raw, &db) != nil {
		fail(w, http.StatusInternalServerError, "imported rules file is corrupt: "+userRulesPath())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"count": len(db.Rules), "rules": db.Rules, "path": userRulesPath(),
		"note": "imported rules are not signature-pinned (you authored them); the deletion guardrails apply to them exactly the same, and a rule id matching a built-in replaces it",
	})
}

// handleUserRulesPut validates and stores an imported ruleset. Validation
// is structural (ids, titles, paths/command, safety) — never content: the
// operator is allowed to aim rules wherever they want, and the deletion
// guardrails stay the last line of defense.
func (s *server) handleUserRulesPut(w http.ResponseWriter, r *http.Request) {
	var db RulesDB
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20)).Decode(&db); err != nil {
		fail(w, http.StatusBadRequest, "bad rules JSON: "+err.Error())
		return
	}
	for i := range db.Rules {
		if err := validateImportableRule(&db.Rules[i], "imported rules", i); err != nil {
			fail(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if err := validateRuleSet(&db, "imported rules"); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	db.Version = 1
	if db.Note == "" {
		db.Note = "Imported rules — loaded on top of the built-in per-OS set; a rule id matching a built-in replaces it."
	}
	data, err := json.MarshalIndent(db, "", " ")
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	path := userRulesPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "count": len(db.Rules), "path": path,
		"note": "imported — takes effect on the next scan; rules are not signature-pinned (you authored them) and the guardrails still apply",
	})
}

func (s *server) handleUserRulesDelete(w http.ResponseWriter, r *http.Request) {
	if err := os.Remove(userRulesPath()); err != nil && !os.IsNotExist(err) {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "count": 0,
		"note": "imported rules cleared — the built-in per-OS set is in effect on the next scan"})
}

// handleRulesExport downloads the effective merged ruleset (built-in pair
// + user overrides) as one importable JSON. Toggles are settings, not part
// of the ruleset, so disabled extras are exported too — nothing is lost.
func (s *server) handleRulesExport(w http.ResponseWriter, r *http.Request) {
	db, _, _, err := s.loadRulesRaw()
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	db.Version = 1
	db.Note = fmt.Sprintf("Exported from wPurge v%s (%s/%s) — import under ⚙️ Settings; a rule id matching a built-in replaces it.",
		appVersion, runtime.GOOS, runtime.GOARCH)
	data, err := json.MarshalIndent(db, "", " ")
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="wpurge-rules-export.json"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

/* ---------- /api/settings ---------- */

// handleSettingsGet returns the operator settings plus the extra/user rule
// list with each rule's checked state (checked = scanned, unchecked =
// default built-ins apply) and whether the rule is even present on this
// machine — a rule whose every target folder is missing is dormant, and a
// checkbox for it would be noise.
func (s *server) handleSettingsGet(w http.ResponseWriter, r *http.Request) {
	type extraRule struct {
		ID         string `json:"id"`
		Title      string `json:"title"`
		Category   string `json:"category"`
		Origin     string `json:"origin"`
		Disabled   bool   `json:"disabled"`
		Available  bool   `json:"available"`  // has targets on this machine
		Overriding bool   `json:"overriding"` // replaces a built-in — its toggle always matters
	}
	var extras []extraRule
	db, replaced, _, err := s.loadRulesRaw()
	if err == nil {
		off := disabledExtrasSet()
		home := homeDir()
		vars := resolveVars(db)
		for i := range db.Rules {
			if o := db.Rules[i].origin; o == originBuiltin || o == originCustom {
				continue // custom folders are managed in their own section
			}
			_, overriding := replaced[db.Rules[i].ID]
			extras = append(extras, extraRule{
				ID:         db.Rules[i].ID,
				Title:      db.Rules[i].Title,
				Category:   db.Rules[i].Category,
				Origin:     db.Rules[i].origin,
				Disabled:   off[db.Rules[i].ID],
				Available:  ruleTargetsPresent(&db.Rules[i], vars, home),
				Overriding: overriding,
			})
		}
	}
	if extras == nil {
		extras = []extraRule{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"guardrails":          guardrailsEnabled(),
		"downloadsMinAgeDays": downloadsMinAge(),
		"disabledExtras":      disabledExtrasList(),
		"extraRules":          extras,
		"customFolders":       customFoldersList(),
	})
}

// handleSettingsSet accepts either field independently: downloadsMinAgeDays
// (1–3650) and/or disabledExtras (the full list of unchecked extra ids).
func (s *server) handleSettingsSet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DownloadsMinAgeDays *int      `json:"downloadsMinAgeDays,omitempty"`
		DisabledExtras      *[]string `json:"disabledExtras,omitempty"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, "bad request body")
		return
	}
	if req.DownloadsMinAgeDays != nil {
		days := *req.DownloadsMinAgeDays
		if days < 1 || days > 3650 {
			fail(w, http.StatusBadRequest, "downloadsMinAgeDays must be between 1 and 3650")
			return
		}
		setDownloadsMinAge(days)
	}
	if req.DisabledExtras != nil {
		setDisabledExtras(*req.DisabledExtras)
	}
	s.handleSettingsGet(w, r)
}

/* ---------- /api/folders (folders to scan) ---------- */

// tryAddCustomFolder validates one folder path and appends it to the list.
// Validation mirrors the engine's own last line of defense — with one
// deliberate override: the standard user folders (Desktop, Documents,
// Downloads, Music, …) sit on the protected table to keep the IMPLICIT
// scanners out of them, but an explicit operator pick is the custom-folder
// feature's whole point, so exactly those folders may be added here. Their
// contents are offered as review (never pre-checked), every path inside
// still passes criticalReason at scan/clean time, and the folder itself is
// never the target. Everything else the table protects — Library roots,
// system locations, browser data — and the structural floor stay refused,
// so the operator learns at add time what the scan would otherwise filter
// out match by match. Returns an HTTP status (0 = added) and the message
// for a refusal.
func tryAddCustomFolder(raw string) (int, string) {
	p := filepath.Clean(strings.TrimSpace(raw))
	if p == "" || !filepath.IsAbs(p) {
		return http.StatusBadRequest, "give an absolute folder path"
	}
	if fi, err := os.Stat(p); err != nil || !fi.IsDir() {
		return http.StatusBadRequest, "not a folder: " + p
	}
	if reason := criticalReason(p); reason != "" && !explicitUserFolderPick(p) {
		return http.StatusForbidden, "refused: " + reason + " — wPurge never scans that location"
	}
	list := customFoldersList()
	if len(list) >= customFoldersMax {
		return http.StatusBadRequest, fmt.Sprintf("the folder list is full (%d) — remove one first", customFoldersMax)
	}
	for _, existing := range list {
		if strings.EqualFold(existing, p) {
			return http.StatusConflict, "this folder is already on the list"
		}
	}
	setCustomFolders(append(list, p))
	return 0, ""
}

// explicitUserFolderPick reports whether p is exactly one of the standard
// user folders — the only refusals a custom-folder add may override. A
// descendant of them is not on the table anyway (exact-match keys), and
// nothing above home or any Library/system/browser location qualifies.
func explicitUserFolderPick(p string) bool {
	if reason := criticalReason(p); !strings.HasPrefix(reason, "protected system location:") {
		return false // structural floor / browser data: never overridden
	}
	lower := strings.ToLower(filepath.Clean(p))
	home := strings.ToLower(homeDir())
	for _, name := range standardUserFolders {
		if lower == filepath.Join(home, strings.ToLower(name)) {
			return true
		}
	}
	return false
}

// handleCustomFolderPick opens the OS folder picker and, on a pick, runs
// the exact same validation + add as the manual input. Cancelling the
// dialog is a normal, quiet outcome; one dialog at a time.
func (s *server) handleCustomFolderPick(w http.ResponseWriter, r *http.Request) {
	if !pickInUse.CompareAndSwap(false, true) {
		fail(w, http.StatusConflict, "a folder dialog is already open — finish or cancel it first")
		return
	}
	defer pickInUse.Store(false)
	picked, err := pickFolderFunc()
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	if picked == "" {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cancelled": true,
			"note": "no folder chosen"})
		return
	}
	if code, msg := tryAddCustomFolder(picked); code != 0 {
		fail(w, code, msg+" (picked: "+picked+")")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "path": filepath.Clean(strings.TrimSpace(picked)),
		"count": len(customFoldersList()), "folders": customFoldersList(),
		"note": "added — the next scan offers its contents as review (nothing pre-checked); remove it any time",
	})
}

func (s *server) handleCustomFolderDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, "bad request body")
		return
	}
	p := filepath.Clean(strings.TrimSpace(req.Path))
	list := customFoldersList()
	out := make([]string, 0, len(list))
	removed := false
	for _, existing := range list {
		if strings.EqualFold(existing, p) {
			removed = true
			continue
		}
		out = append(out, existing)
	}
	if !removed {
		fail(w, http.StatusNotFound, "that folder is not on the list")
		return
	}
	setCustomFolders(out)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "count": len(out), "folders": out,
		"note": "removed — the next scan no longer includes it (nothing was deleted from disk)",
	})
}

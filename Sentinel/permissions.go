package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

type PermissionInventory struct {
	Platform     string          `json:"platform"`
	ScannedAt    float64         `json:"scanned_at"`
	Apps         []PermissionApp `json:"apps"`
	Warnings     []string        `json:"warnings"`
	CanModifyTCC bool            `json:"can_modify_tcc"`
}

type PermissionApp struct {
	Name        string      `json:"name"`
	Identifier  string      `json:"identifier"`
	Path        string      `json:"path,omitempty"`
	Source      string      `json:"source"`
	Permissions []AppAccess `json:"permissions"`
}

type AppAccess struct {
	Category     string   `json:"category"`
	Name         string   `json:"name"`
	Status       string   `json:"status"`
	Scope        string   `json:"scope,omitempty"`
	Detail       string   `json:"detail,omitempty"`
	Source       string   `json:"source"`
	LastAccessed *float64 `json:"last_accessed,omitempty"`
	// Service is the raw TCC service id (e.g. kTCCServiceAccessibility) —
	// what the remove endpoint needs. Stale flags a TCC grant whose client
	// app is no longer installed.
	Service string `json:"service,omitempty"`
	Stale   bool   `json:"stale,omitempty"`
	DB      string `json:"db,omitempty"`
	// Dir ("in"/"out") marks firewall rule rows, for the block/allow buttons.
	Dir string `json:"dir,omitempty"`
	// Target is the on-disk file a daemon/helper removal row acts on — it
	// can differ from the app-level path when rows merge into one entry.
	Target string `json:"target,omitempty"`
}

type permissionBuilder struct {
	inventory PermissionInventory
	byID      map[string]int
}

func permissionInventory() PermissionInventory {
	b := permissionBuilder{inventory: PermissionInventory{
		Platform: runtime.GOOS + "/" + runtime.GOARCH, ScannedAt: NowF(),
		Apps: []PermissionApp{}, Warnings: []string{},
	}, byID: map[string]int{}}

	switch runtime.GOOS {
	case "darwin":
		b.scanMacApps()
		b.scanMacTCC()
		b.scanMacFirewall()
		b.scanMacPrivileged()
		b.inventory.Warnings = append(b.inventory.Warnings,
			"macOS reports privacy grants through TCC; a missing entry is not proof of denial.",
			"Keychain access is controlled per item and is not exposed as a machine-wide per-app grant.",
			"The macOS application firewall filters incoming connections only — there is no per-app outbound firewall rule on macOS.")
	case "linux":
		b.scanLinuxApps()
		b.scanLinuxFirewall()
		b.inventory.Warnings = append(b.inventory.Warnings,
			"Sandbox permissions are reported for Flatpak and Snap apps; other desktop apps have no central permission-grant inventory.",
			"Linux packet filters (nftables/iptables) match ports and interfaces, not applications — firewall state is shown per backend, not per app.")
	case "windows":
		b.scanWindowsApps()
		b.scanWindowsFirewall()
		b.inventory.Warnings = append(b.inventory.Warnings,
			"Windows package capabilities are declarations, not proof of current runtime access; classic desktop app permissions are not centrally enumerated.",
			"Firewall profile rows show the default inbound/outbound policy — 'allow' there means every app may connect unless a specific rule blocks it.")
	case "freebsd", "openbsd", "netbsd":
		b.scanBSDApps()
		b.scanBSDFirewall()
		b.inventory.Warnings = append(b.inventory.Warnings,
			"This OS does not provide a central per-app privacy grant database; listed app access is unknown unless reported by another source.",
			"pf matches ports and interfaces, not applications — firewall state is shown globally only.")
	default:
		b.inventory.Warnings = append(b.inventory.Warnings, "Installed apps and per-app permissions are not supported on this OS.")
	}

	for i := range b.inventory.Apps {
		sort.Slice(b.inventory.Apps[i].Permissions, func(a, c int) bool {
			if b.inventory.Apps[i].Permissions[a].Category == b.inventory.Apps[i].Permissions[c].Category {
				return b.inventory.Apps[i].Permissions[a].Name < b.inventory.Apps[i].Permissions[c].Name
			}
			return b.inventory.Apps[i].Permissions[a].Category < b.inventory.Apps[i].Permissions[c].Category
		})
	}
	sort.Slice(b.inventory.Apps, func(i, j int) bool {
		return strings.ToLower(b.inventory.Apps[i].Name) < strings.ToLower(b.inventory.Apps[j].Name)
	})
	return b.inventory
}

func (b *permissionBuilder) app(id, name, path, source string) *PermissionApp {
	id = strings.TrimSpace(id)
	if id == "" {
		id = path
	}
	key := strings.ToLower(id)
	if i, ok := b.byID[key]; ok {
		app := &b.inventory.Apps[i]
		if app.Name == "" || app.Name == app.Identifier {
			app.Name = name
		}
		if app.Path == "" {
			app.Path = path
		}
		if app.Source == "" || source == "macOS TCC" || source == "Windows package" ||
			source == "Flatpak" || source == "Snap" {
			app.Source = source
		}
		return app
	}
	if name == "" {
		name = id
	}
	b.inventory.Apps = append(b.inventory.Apps, PermissionApp{
		Name: name, Identifier: id, Path: path, Source: source,
		Permissions: []AppAccess{},
	})
	i := len(b.inventory.Apps) - 1
	b.byID[key] = i
	return &b.inventory.Apps[i]
}

func (b *permissionBuilder) addAccess(app *PermissionApp, access AppAccess) {
	for i, old := range app.Permissions {
		if old.Category == access.Category && old.Name == access.Name && old.Source == access.Source {
			if old.Status != access.Status || old.Scope != access.Scope || old.Detail != access.Detail {
				app.Permissions[i] = access
			} else if access.LastAccessed != nil &&
				(old.LastAccessed == nil || *access.LastAccessed > *old.LastAccessed) {
				app.Permissions[i].LastAccessed = access.LastAccessed
			}
			return
		}
	}
	app.Permissions = append(app.Permissions, access)
}

func (b *permissionBuilder) warning(err error) {
	if err != nil {
		b.inventory.Warnings = append(b.inventory.Warnings, FmtErr(err))
	}
}

func (b *permissionBuilder) scanMacApps() {
	home, _ := os.UserHomeDir()
	roots := []string{"/Applications", "/System/Applications", "/System/Library/CoreServices/Applications"}
	if home != "" {
		roots = append(roots, filepath.Join(home, "Applications"))
	}
	seen := map[string]bool{}
	for _, root := range roots {
		_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if entry.IsDir() && strings.HasSuffix(strings.ToLower(entry.Name()), ".app") {
				if !seen[path] {
					seen[path] = true
					id, name := readBundleInfo(filepath.Join(path, "Contents", "Info.plist"))
					if id == "" {
						id = path
					}
					if name == "" {
						name = strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name()))
					}
					b.app(id, name, path, "Installed application")
				}
				return filepath.SkipDir
			}
			return nil
		})
	}
}

func readBundleInfo(path string) (string, string) {
	f, err := os.Open(path)
	if err != nil {
		return "", ""
	}
	defer f.Close()
	var id, name, key string
	d := xml.NewDecoder(f)
	for {
		t, err := d.Token()
		if err != nil {
			break
		}
		start, ok := t.(xml.StartElement)
		if !ok {
			continue
		}
		if start.Name.Local == "key" {
			_ = d.DecodeElement(&key, &start)
			continue
		}
		if start.Name.Local == "string" {
			var value string
			if d.DecodeElement(&value, &start) == nil {
				switch key {
				case "CFBundleIdentifier":
					id = value
				case "CFBundleDisplayName", "CFBundleName":
					if name == "" {
						name = value
					}
				}
			}
			key = ""
		}
	}
	return id, name
}

var macPermissionServices = map[string]struct{ category, name string }{
	"kTCCServiceSystemPolicyAllFiles":         {"Files & folders", "Full Disk Access"},
	"kTCCServiceSystemPolicyDesktopFolder":    {"Files & folders", "Desktop folder"},
	"kTCCServiceSystemPolicyDocumentsFolder":  {"Files & folders", "Documents folder"},
	"kTCCServiceSystemPolicyDownloadsFolder":  {"Files & folders", "Downloads folder"},
	"kTCCServiceSystemPolicyNetworkVolumes":   {"Files & folders", "Network volumes"},
	"kTCCServiceSystemPolicyRemovableVolumes": {"Files & folders", "Removable volumes"},
	"kTCCServiceSystemPolicyAppData":          {"Files & folders", "Other app data"},
	"kTCCServiceSystemPolicySysAdminFiles":    {"System access", "System administration files"},
	"kTCCServiceSystemPolicyDeveloperFiles":   {"System access", "Developer files"},
	"kTCCServiceCamera":                       {"Camera & microphone", "Camera"},
	"kTCCServiceMicrophone":                   {"Camera & microphone", "Microphone"},
	"kTCCServiceScreenCapture":                {"Screen & input", "Screen recording"},
	"kTCCServiceAccessibility":                {"Screen & input", "Accessibility"},
	"kTCCServiceListenEvent":                  {"Screen & input", "Input monitoring"},
	"kTCCServicePostEvent":                    {"Screen & input", "Send keystrokes"},
	"kTCCServiceAppleEvents":                  {"Automation", "Control other apps (AppleEvents)"},
	"kTCCServiceAddressBook":                  {"Personal data", "Contacts"},
	"kTCCServiceCalendar":                     {"Personal data", "Calendars"},
	"kTCCServicePhotos":                       {"Personal data", "Photos"},
	"kTCCServiceReminders":                    {"Personal data", "Reminders"},
	"kTCCServiceLocation":                     {"Personal data", "Location"},
	"kTCCServiceMediaLibrary":                 {"Personal data", "Media library"},
	"kTCCServiceBluetoothAlways":              {"Devices & network", "Bluetooth"},
	"kTCCServiceSpeechRecognition":            {"Personal data", "Speech recognition"},
	"kTCCServiceLocalNetwork":                 {"Devices & network", "Local network devices"},
}

func (b *permissionBuilder) scanMacTCC() {
	home, _ := os.UserHomeDir()
	userDB := filepath.Join(home, "Library", "Application Support", "com.apple.TCC", "TCC.db")
	b.inventory.CanModifyTCC = tccDBWritable(userDB)
	if !b.inventory.CanModifyTCC {
		b.warning(fmt.Errorf("TCC grants are read-only because Sentinel cannot write the user TCC database; enable Sentinel's Elevated launch in AppDeck, grant Sentinel Full Disk Access in System Settings, then restart it to enable removal"))
	}
	rows, err := tccEntries()
	if err != nil {
		b.warning(err)
		return
	}
	installed := map[string]bool{}
	for id := range b.byID {
		installed[id] = true
	}
	spotCache := map[string]bool{}
	for _, row := range rows {
		service, client, auth := row.Service, row.Client, row.Auth
		accessType, ok := macPermissionServices[service]
		if !ok {
			continue
		}
		name := client
		path := ""
		if strings.HasPrefix(client, "/") {
			path = client
			name = strings.TrimSuffix(filepath.Base(client), filepath.Ext(client))
		} else if p := strings.LastIndex(client, "."); p >= 0 {
			name = client[p+1:]
		}
		status := tccStatus(auth)
		stale := tccClientStale(client, installed, func(c string) bool {
			if v, ok := spotCache[c]; ok {
				return v
			}
			missing := false
			if out, err := RunOut(5*time.Second, "mdfind",
				"kMDItemCFBundleIdentifier == '"+strings.ReplaceAll(c, "'", "")+"'"); err == nil &&
				strings.TrimSpace(out) == "" {
				missing = true
			}
			spotCache[c] = missing
			return missing
		})
		detail := "TCC authorization value " + auth
		if row.DB == "system" {
			detail += " · system database (root required to remove)"
		}
		if stale {
			detail += " · app not installed — leftover grant"
		}
		app := b.app(client, name, path, "macOS TCC")
		b.addAccess(app, AppAccess{
			Category: accessType.category, Name: accessType.name, Status: status,
			Detail: detail, Source: "macOS TCC", Service: service, Stale: stale,
			LastAccessed: tccLastAccessed(row.LastUsed), DB: row.DB,
		})
	}
}

func tccDBWritable(path string) bool {
	_, err := RunOut(5*time.Second, "sqlite3", "-batch", path, "BEGIN IMMEDIATE; ROLLBACK;")
	return err == nil
}

// tccClientStale reports whether a TCC client no longer exists on this
// machine. Path-style clients are skipped (services and CLI tools), Apple's
// own clients are skipped (they legitimately live outside /Applications),
// and an installed match (bundle id collected by scanMacApps) clears the
// flag. spotCheck is the Spotlight double-check for clients outside the
// scanned roots; when it's nil the static set's answer stands.
func tccClientStale(client string, installed map[string]bool, spotCheck func(string) bool) bool {
	if client == "" || strings.HasPrefix(client, "/") || strings.HasPrefix(client, "com.apple.") {
		return false
	}
	if installed[strings.ToLower(client)] {
		return false
	}
	if spotCheck == nil {
		return true
	}
	return spotCheck(client)
}

func tccLastAccessed(value string) *float64 {
	seconds, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil || seconds <= 0 {
		return nil
	}
	unixSeconds := seconds + 978307200 // TCC stores NSDate seconds from 2001-01-01.
	return &unixSeconds
}

func tccStatus(auth string) string {
	switch auth {
	case "0":
		return "denied"
	case "2":
		return "granted"
	case "3":
		return "limited"
	default:
		return "unknown"
	}
}

func (b *permissionBuilder) scanMacFirewall() {
	snap, err := readFirewall()
	if err != nil {
		b.warning(fmt.Errorf("firewall: %w", err))
		return
	}
	sys := b.app("com.apple.alf", "macOS Firewall (system settings)", "", "macOS firewall")
	b.addAccess(sys, AppAccess{Category: "Firewall", Name: "Firewall (incoming)",
		Status: snap.Global, Source: "macOS firewall",
		Detail: "Application firewall global state (socketfilterfw)."})
	if snap.BlockAll != "" {
		b.addAccess(sys, AppAccess{Category: "Firewall", Name: "Block all incoming",
			Status: snap.BlockAll, Source: "macOS firewall",
			Detail: "When on, every incoming connection is dropped regardless of per-app rules."})
	}
	if snap.Stealth != "" {
		b.addAccess(sys, AppAccess{Category: "Firewall", Name: "Stealth mode",
			Status: snap.Stealth, Source: "macOS firewall",
			Detail: "When on, unsolicited probes are dropped silently."})
	}
	for _, r := range snap.Rules {
		ident := r.Ident
		if ident == "" {
			ident = r.Path
		}
		if ident == "" {
			continue
		}
		app := b.app(ident, r.App, r.Path, "macOS firewall")
		b.addAccess(app, AppAccess{Category: "Firewall", Name: "Incoming connections",
			Status: r.Policy, Dir: r.Dir, Source: "macOS firewall",
			Detail: "Application firewall rule for incoming connections."})
	}
}

func (b *permissionBuilder) scanWindowsFirewall() {
	snap, err := readFirewall()
	if err != nil {
		b.warning(fmt.Errorf("firewall: %w", err))
		return
	}
	sys := b.app("windows.defender.firewall", "Windows Defender Firewall (system)", "", "Windows firewall")
	for _, p := range snap.Profiles {
		b.addAccess(sys, AppAccess{Category: "Firewall", Name: p.Name + " profile",
			Status: p.Enabled, Source: "Windows firewall",
			Detail: "Default inbound: " + p.DefaultIn + ", default outbound: " + p.DefaultOut +
				". 'allow' here means every app may connect unless a specific rule blocks it."})
	}
	for _, r := range snap.Rules {
		if r.Ident == "" {
			continue
		}
		name := "Incoming connections"
		if r.Dir == "out" {
			name = "Outgoing connections"
		}
		app := b.app(r.Ident, r.App, r.Path, "Windows firewall")
		scope := r.Profile
		b.addAccess(app, AppAccess{Category: "Firewall", Name: name,
			Status: r.Policy, Dir: r.Dir, Scope: scope, Source: "Windows firewall",
			Detail: "Firewall rule: " + r.Detail})
	}
}

func (b *permissionBuilder) scanLinuxFirewall() {
	snap, err := readFirewall()
	if err != nil {
		b.warning(fmt.Errorf("firewall: %w", err))
		return
	}
	sys := b.app("linux.firewall", "Linux host firewall (system)", "", "Linux firewall")
	b.addAccess(sys, AppAccess{Category: "Firewall", Name: "Firewall (backend state)",
		Status: snap.Global, Source: "Linux firewall",
		Detail: strings.Join(snap.Notes, "; ")})
}

func (b *permissionBuilder) scanBSDFirewall() {
	snap, err := readFirewall()
	if err != nil {
		b.warning(fmt.Errorf("firewall: %w", err))
		return
	}
	sys := b.app("bsd.pf", "PF packet filter (system)", "", "BSD firewall")
	b.addAccess(sys, AppAccess{Category: "Firewall", Name: "Packet filter (pf)",
		Status: snap.Global, Source: "BSD firewall",
		Detail: strings.Join(snap.Notes, "; ")})
}

// scanMacPrivileged lists third-party items that run outside TCC entirely:
// root LaunchDaemons and privileged helpers can change firewall/network
// configuration without any permission prompt, which is exactly the
// "who can change network settings" question.
func (b *permissionBuilder) scanMacPrivileged() {
	dirs := []struct {
		path   string
		name   string
		status string
	}{
		{"/Library/LaunchDaemons", "Runs as root (LaunchDaemon)", "granted"},
		{"/Library/PrivilegedHelperTools", "Runs as root (privileged helper)", "granted"},
		{"/Library/LaunchAgents", "Launch agent (user session)", "declared"},
	}
	for _, d := range dirs {
		ents, err := os.ReadDir(d.path)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if e.IsDir() || strings.HasPrefix(e.Name(), "com.apple.") {
				continue
			}
			full := filepath.Join(d.path, e.Name())
			// Only .plist carries a trimmable extension — helper binaries like
			// com.macpaw.CleanMyMac5.Agent must keep their full name or the id
			// collides with the parent app's bundle id.
			id := daemonItemID(e.Name())
			detail := plistProgramDetail(full)
			app := b.app(id, id, full, "System daemon/helper")
			b.addAccess(app, AppAccess{Category: "System access", Name: d.name,
				Status: d.status, Source: "System daemon/helper", Detail: detail,
				Target: full})
		}
	}
}

// daemonItemID derives an inventory id from a LaunchDaemon/HelperTools entry
// name: ".plist" is an extension to strip; everything else is literal.
func daemonItemID(name string) string {
	if strings.HasSuffix(name, ".plist") {
		return strings.TrimSuffix(name, ".plist")
	}
	return name
}

// plistProgramDetail extracts the program path a launchd plist runs — the
// first string under ProgramArguments (or the Program key). Empty for
// non-plist files.
func plistProgramDetail(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil || !strings.HasSuffix(strings.ToLower(path), ".plist") {
		return ""
	}
	s := string(raw)
	key := "<key>ProgramArguments</key>"
	i := strings.Index(s, key)
	if i < 0 {
		key = "<key>Program</key>"
		i = strings.Index(s, key)
	}
	if i < 0 {
		return ""
	}
	rest := s[i+len(key):]
	if key == "<key>ProgramArguments</key>" {
		if j := strings.Index(rest, "</array>"); j > 0 {
			rest = rest[:j] // only array elements here; first string wins
		}
	}
	i = strings.Index(rest, "<string>")
	if i < 0 {
		return ""
	}
	rest = rest[i+len("<string>"):]
	j := strings.Index(rest, "</string>")
	if j < 0 {
		return ""
	}
	out := strings.TrimSpace(rest[:j])
	if len(out) > 160 {
		out = out[:160] + "…"
	}
	return out
}

func (b *permissionBuilder) scanLinuxApps() {
	b.scanLinuxDesktopEntries()
	b.scanFlatpak()
	b.scanSnap()
}

func (b *permissionBuilder) scanLinuxDesktopEntries() {
	home, _ := os.UserHomeDir()
	roots := []string{"/usr/share/applications", "/usr/local/share/applications"}
	if home != "" {
		roots = append(roots, filepath.Join(home, ".local/share/applications"))
	}
	for _, root := range roots {
		_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if entry.IsDir() {
				return nil
			}
			if !strings.HasSuffix(entry.Name(), ".desktop") {
				return nil
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			name := ""
			for _, line := range strings.Split(string(raw), "\n") {
				if strings.HasPrefix(line, "Name=") && name == "" {
					name = strings.TrimSpace(strings.TrimPrefix(line, "Name="))
				}
			}
			id := strings.TrimSuffix(entry.Name(), ".desktop")
			b.app(id, name, path, "Desktop entry")
			return nil
		})
	}
}

func (b *permissionBuilder) scanFlatpak() {
	out, err := RunOut(8*time.Second, "flatpak", "list", "--app", "--columns=application,name")
	if err != nil {
		if !isCommandMissing(err) {
			b.warning(fmt.Errorf("Flatpak inventory: %w", err))
		}
		return
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.SplitN(strings.TrimSpace(line), "\t", 2)
		if len(f) != 2 || f[0] == "" {
			continue
		}
		app := b.app(f[0], f[1], "", "Flatpak")
		permissions, err := RunOut(8*time.Second, "flatpak", "info", "--show-permissions", f[0])
		if err != nil {
			b.warning(fmt.Errorf("Flatpak permissions for %s: %w", f[0], err))
			continue
		}
		b.parseFlatpakPermissions(app, permissions)
	}
}

func (b *permissionBuilder) parseFlatpakPermissions(app *PermissionApp, text string) {
	section := ""
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.Trim(line, "[]")
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		items := strings.Split(value, ";")
		value = strings.TrimSpace(value)
		switch {
		case section == "Context" && key == "filesystems" && value != "":
			scope := nonEmpty(items)
			b.addAccess(app, AppAccess{Category: "Files & folders", Name: "Filesystem access",
				Status: flatpakFilesystemStatus(scope), Scope: strings.Join(scope, ", "),
				Detail: "Flatpak sandbox permissions", Source: "Flatpak"})
		case section == "Context" && (key == "shared" && strings.Contains(value, "network") ||
			key == "sockets" && strings.Contains(value, "network")):
			b.addAccess(app, AppAccess{Category: "Network", Name: "Network access", Status: "granted",
				Detail: value, Source: "Flatpak"})
		case section == "Context" && key == "devices" && value != "":
			b.addAccess(app, AppAccess{Category: "Devices", Name: "Device access", Status: "declared",
				Scope:  strings.Join(nonEmpty(items), ", "),
				Detail: "Device access is broad; camera/microphone use is not individually identified.", Source: "Flatpak"})
		case strings.Contains(strings.ToLower(section), "bus policy") &&
			strings.Contains(strings.ToLower(key), "secrets") && value != "":
			b.addAccess(app, AppAccess{Category: "Credentials", Name: "Desktop secrets service",
				Status: "granted", Detail: value, Source: "Flatpak"})
		}
	}
}

func flatpakFilesystemStatus(scopes []string) string {
	for _, scope := range scopes {
		path, _, _ := strings.Cut(scope, ":")
		if path == "host" || path == "/" {
			return "granted"
		}
	}
	return "restricted"
}

func nonEmpty(items []string) []string {
	out := []string{}
	for _, item := range items {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func (b *permissionBuilder) scanSnap() {
	out, err := RunOut(8*time.Second, "snap", "list")
	if err != nil {
		if !isCommandMissing(err) {
			b.warning(fmt.Errorf("Snap inventory: %w", err))
		}
		return
	}
	for i, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || i == 0 {
			continue
		}
		name := fields[0]
		app := b.app(name, name, "", "Snap")
		connections, err := RunOut(8*time.Second, "snap", "connections", name)
		if err != nil {
			b.warning(fmt.Errorf("Snap permissions for %s: %w", name, err))
			continue
		}
		b.parseSnapConnections(app, connections)
	}
}

func (b *permissionBuilder) parseSnapConnections(app *PermissionApp, text string) {
	categories := map[string]struct{ category, name string }{
		"camera":                   {"Camera & microphone", "Camera"},
		"audio-record":             {"Camera & microphone", "Microphone"},
		"home":                     {"Files & folders", "Home folder"},
		"removable-media":          {"Files & folders", "Removable media"},
		"personal-files":           {"Files & folders", "Personal files"},
		"system-files":             {"System access", "System files"},
		"password-manager-service": {"Credentials", "Password manager service"},
		"ssh-keys":                 {"Credentials", "SSH private keys"},
		"ssh-public-keys":          {"Credentials", "SSH public keys"},
		"login-session-observe":    {"Screen & input", "Login session observation"},
		"screen-capture":           {"Screen & input", "Screen capture"},
		"desktop":                  {"Desktop integration", "Desktop access"},
		"desktop-legacy":           {"Desktop integration", "Legacy desktop access"},
		"screen-inhibit-control":   {"Screen & input", "Screen control"},
		"network":                  {"Network", "Network access"},
		"network-bind":             {"Network", "Listen for inbound connections"},
		"network-control":          {"Network", "Manage network configuration"},
		"firewall-control":         {"Network", "Manage firewall"},
		"system-observe":           {"System access", "System process observation"},
		"process-control":          {"System access", "Control other processes"},
		"mount-observe":            {"System access", "Observe mounted filesystems"},
		"hardware-observe":         {"Devices", "Hardware information"},
		"raw-usb":                  {"Devices", "Raw USB device access"},
		"bluetooth-control":        {"Devices", "Control Bluetooth"},
		"bluez":                    {"Devices", "Bluetooth"},
		"location-control":         {"Personal data", "Control location service"},
		"location-observe":         {"Personal data", "Observe location service"},
	}
	for i, line := range strings.Split(text, "\n") {
		if i == 0 {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		accessType, ok := categories[f[0]]
		if !ok || !strings.HasPrefix(f[1], app.Identifier+":") {
			continue
		}
		status := "granted"
		if f[2] == "-" {
			status = "denied"
		}
		b.addAccess(app, AppAccess{Category: accessType.category, Name: accessType.name,
			Status: status, Scope: f[2], Detail: "Snap interface connection", Source: "Snap"})
	}
}

func (b *permissionBuilder) scanWindowsApps() {
	script := `$ErrorActionPreference='Stop'; $rows=@(); `
	script += `Get-AppxPackage | ForEach-Object { $caps=@(); try { $m=Get-AppxPackageManifest $_.PackageFullName; `
	script += `$caps=@($m.SelectNodes("//*[local-name()='Capability']") | ForEach-Object { $_.Name }) } catch {}; `
	script += `$rows += [pscustomobject]@{Name=$_.Name; Id=$_.PackageFamilyName; Path=$_.InstallLocation; Capabilities=$caps; Source='Windows package'} }; `
	script += `foreach($root in @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')) { `
	script += `Get-ItemProperty $root -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | ForEach-Object { `
	script += `$rows += [pscustomobject]@{Name=$_.DisplayName; Id=$_.PSChildName; Path=$_.InstallLocation; Capabilities=@(); Source='Windows installed app'} } }; `
	script += `$rows | ConvertTo-Json -Depth 4 -Compress`
	out, err := RunOut(25*time.Second, "powershell", "-NoProfile", "-Command", script)
	if err != nil {
		b.warning(fmt.Errorf("Windows app inventory: %w", err))
		return
	}
	type row struct {
		Name         string   `json:"Name"`
		ID           string   `json:"Id"`
		Path         string   `json:"Path"`
		Capabilities []string `json:"Capabilities"`
		Source       string   `json:"Source"`
	}
	rows, err := decodeJSONRows[row]([]byte(out))
	if err != nil {
		b.warning(fmt.Errorf("Windows app inventory response: %w", err))
		return
	}
	for _, r := range rows {
		source := r.Source
		if source == "" {
			source = "Windows package"
		}
		app := b.app(r.ID, r.Name, r.Path, source)
		for _, capability := range r.Capabilities {
			category, name := windowsCapability(capability)
			if category == "" {
				continue
			}
			b.addAccess(app, AppAccess{Category: category, Name: name, Status: "declared",
				Detail: "Declared in the app package manifest; runtime approval may differ.",
				Source: "Windows package"})
		}
	}
}

func windowsCapability(capability string) (string, string) {
	switch strings.ToLower(capability) {
	case "webcam":
		return "Camera & microphone", "Camera"
	case "microphone":
		return "Camera & microphone", "Microphone"
	case "pictureslibrary":
		return "Files & folders", "Pictures library"
	case "videoslibrary":
		return "Files & folders", "Videos library"
	case "musiclibrary":
		return "Files & folders", "Music library"
	case "documentslibrary":
		return "Files & folders", "Documents library"
	case "removablestorage":
		return "Files & folders", "Removable storage"
	case "location":
		return "Personal data", "Location"
	case "contacts":
		return "Personal data", "Contacts"
	case "appointments":
		return "Personal data", "Calendars"
	case "enterpriseauthentication", "sharedusercertificates", "useraccountinformation":
		return "Credentials", "Certificates / enterprise authentication"
	case "documentslibraryrestricted", "pictureslibraryrestricted", "videoslibraryrestricted", "musiclibraryrestricted":
		return "Files & folders", strings.TrimSuffix(capability, "Restricted") + " (restricted)"
	case "internetclient", "internetclientserver", "privatenetworkclientserver":
		return "Network", "Network access"
	case "broadfilesystemaccess", "runfulltrust":
		return "System access", capability
	default:
		return "", ""
	}
}

func (b *permissionBuilder) scanBSDApps() {
	home, _ := os.UserHomeDir()
	roots := []string{"/usr/local/share/applications", "/usr/share/applications"}
	if home != "" {
		roots = append(roots, filepath.Join(home, ".local/share/applications"))
	}
	for _, root := range roots {
		_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".desktop") {
				return nil
			}
			id := strings.TrimSuffix(entry.Name(), ".desktop")
			b.app(id, id, path, "Desktop entry")
			return nil
		})
	}
}

func isCommandMissing(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "executable file not found")
}

func decodeJSONRows[T any](raw []byte) ([]T, error) {
	if strings.TrimSpace(string(raw)) == "" {
		return []T{}, nil
	}
	var rows []T
	if err := json.Unmarshal(raw, &rows); err == nil {
		return rows, nil
	}
	var row T
	if err := json.Unmarshal(raw, &row); err != nil {
		return nil, err
	}
	return []T{row}, nil
}

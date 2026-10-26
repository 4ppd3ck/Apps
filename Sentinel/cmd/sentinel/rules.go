package main

// Rules — default detection configuration, merged with the user's
// rules.user.json. Everything is plain data so the dashboard can edit it.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

type Rules struct {
	MonitorURL string `json:"monitor_url"`
	// IntelURL is the IPolice base URL (optional known-IP companion app).
	// IntelMatch decides what happens when an endpoint resolves to a known
	// provider: "label" (record at info, labelled — never notifies),
	// "suppress" (never alert at all), "autoack" (alert lands pre-acked),
	// "off" (ignore IPolice entirely).
	IntelURL       string   `json:"intel_url"`
	IntelMatch     string   `json:"intel_match"`
	TickSeconds    int      `json:"tick_seconds"`
	SlowMinutes    int      `json:"slow_minutes"`
	LearnMinutes   int      `json:"learn_minutes"`
	Notify         Notify   `json:"notify"`
	BadPorts       []int    `json:"bad_ports"`
	TrustedCIDRs   []string `json:"trusted_cidrs"`
	SensitivePaths []string `json:"sensitive_paths"`
	// PasswordManagerPaths marks password-manager data (added to the
	// sensitive-path matching with its own "password manager" label).
	PasswordManagerPaths []string `json:"password_manager_paths"`
	QuietApps            []string `json:"quiet_apps"`
	NewEndpointBurst     int      `json:"new_endpoint_burst"`
	ProcessAllow         []string `json:"process_allowlist"`
	ProcessBad           []string `json:"process_bad_names"`
	BadTCCClient         []string `json:"tcc_bad_clients"`
}

type Notify struct {
	Desktop     bool   `json:"desktop"`
	Sound       bool   `json:"sound"`
	MinSeverity string `json:"min_severity"`
	// WebhookURL delivers alerts out-of-band (GUI compromise / headless box).
	// Formats: "json" (generic POST), "ntfy" (plain-text body), "telegram"
	// (bot API message; needs WebhookChatID).
	WebhookURL    string `json:"webhook_url"`
	WebhookFormat string `json:"webhook_format"`
	WebhookChatID string `json:"webhook_chat_id"`
}

func DefaultRules() *Rules {
	return &Rules{
		MonitorURL:   "http://127.0.0.1:8765",
		IntelURL:     "http://127.0.0.1:8770",
		IntelMatch:   "label",
		TickSeconds:  15,
		SlowMinutes:  5,
		LearnMinutes: 120,
		Notify: Notify{
			Desktop:     true,
			Sound:       true,
			MinSeverity: "medium",
		},
		// Remote-access / tunneller / C2 listener ports. The owning process
		// is always checked against the allowlist before alerting.
		BadPorts: []int{
			4444, 4445, 5555, 5556, // metasploit /meterpreter, five5
			12345, 12346, // NetBus
			31337, 31338, // Back Orifice, elite
			9001, 9002, // common reverse-shell / tunnel
			8888, 8081, // ngrok/chisel style tunnels (checked vs allowlist)
			5900, 5901, 5902, 5903, // VNC family
			3389,                    // RDP listener (flag unless allowlisted)
			14147,                   // FileZilla ftp admin
			7626, 40745, 5550, 6670, // legacy RATs (DeepThroat, SubSeven…)
		},
		// Networks that are "internal" — outbound there is not rogue.
		// Anything else public is watched; feeds can extend this.
		TrustedCIDRs: []string{
			"127.0.0.0/8", "::1/128",
			"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", // RFC1918 LAN
			"169.254.0.0/16", "fe80::/10", // link-local
			"224.0.0.0/4", "ff00::/8", // multicast
			"255.255.255.255/32",
		},
		// Paths whose access by a networked process is suspicious.
		SensitivePaths: []string{
			".ssh", ".gnupg", ".aws", ".kube", ".docker",
			"keychain-db", "/keychains/", "wallet", "keystore",
			"password", "credential", "cookie", "login data",
			"browser\\ data", "cookies.sqlite",
		},
		// Password-manager data/stores — the Live Access check reports any
		// process outside the manager family holding these open. Checked
		// before sensitive_paths, so keychains classify here.
		PasswordManagerPaths: []string{
			"1password", "bitwarden", "lastpass", "keepass", ".kdbx",
			".password-store", "password-store", "dashlane", "enpass",
			"kwallet", "gnome-keyring", "login.keyring", "user.keyring",
			"keyrings", "pwsafe", "apple passwords",
			// actual keychain store files — deliberately narrow, so a file
			// that merely lives in an app named "Keychain …" (localisation
			// tables etc.) is not a store hit
			"keychain-2", "keychain.db", ".keychain", "/keychains/",
		},
		// Known-good names that may legitimately hold these ports/abilities.
		ProcessAllow: []string{
			"sshd", "svnserv", "teamviewer", "anydesk", "rustdesk",
			"remotedesktop", "screensharingd", "vncserver", "splashdesktop",
			"ngrok", "cloudflared", "tailscaled", "wireguard", "openvpn",
			"com.docker.backend", "vmware", "vmnat", "parallels",
			"spacedesk", "parsec", "moonlight", "sunshine",
		},
		// Endpoint churn is these apps' nature (browsers, updaters) — they
		// are baselined and beacon-tracked but never alert on new_endpoint.
		QuietApps: []string{
			"brave", "chrome", "chromium", "firefox", "safari", "edge",
			"opera", "msedge", "softwareupdated", "mobileassetd",
		},
		NewEndpointBurst: 8,
		// Names that are always worth an alert when seen running. Plain
		// tokens are substrings; wrap one in slashes for regex ("/\bmsf\b/")
		// when it would otherwise swallow innocent names ("msfonts").
		ProcessBad: []string{
			"mimikatz", "meterpreter", "msfvenom", "msfconsole",
			"netcat", "ncat", "nc.exe", "cryptcat", "pwncat",
			"darkcomet", "njrat", "njworm", "remcos", "quasar", "venomrat",
			"asyncrat", "sharprat", "nano rat",
			"keylogger", "keylog", "logkeys", "kidlogger", "refog",
			"spytech", "actual spy",
			"chisel", "revshell", "shellcode", "cobaltstrike", "sliver",
			"beacon.exe", "empirestage",
		},
		// TCC clients (macOS) that are known-noisy when granted these
		// services; anything else new gets flagged by baseline diffing.
		BadTCCClient: []string{
			"unknown", "python", "osascript", "spectacle", "switchresx",
		},
	}
}

// LoadRules reads rules.user.json if present and overlays it on the defaults.
// Missing fields keep the default, so the file can stay minimal.
func LoadRules(dataDir string) *Rules {
	r := DefaultRules()
	raw, err := os.ReadFile(filepath.Join(dataDir, "rules.user.json"))
	if err != nil {
		return r
	}
	overlay := &Rules{}
	if err := json.Unmarshal(raw, overlay); err != nil {
		return r
	}
	if overlay.MonitorURL != "" {
		r.MonitorURL = strings.TrimRight(overlay.MonitorURL, "/")
	}
	if overlay.IntelURL != "" {
		r.IntelURL = strings.TrimRight(overlay.IntelURL, "/")
	}
	switch overlay.IntelMatch {
	case "label", "suppress", "autoack", "off":
		r.IntelMatch = overlay.IntelMatch
	case "":
		// keep default
	default:
		r.IntelMatch = "off" // unknown mode: fail safe, never silence
	}
	if overlay.TickSeconds > 0 {
		r.TickSeconds = overlay.TickSeconds
	}
	if overlay.SlowMinutes > 0 {
		r.SlowMinutes = overlay.SlowMinutes
	}
	if overlay.Notify.MinSeverity != "" {
		r.Notify.MinSeverity = overlay.Notify.MinSeverity
	}
	if overlay.Notify.Desktop || overlay.Notify.Sound {
		r.Notify.Desktop = overlay.Notify.Desktop
		r.Notify.Sound = overlay.Notify.Sound
	}
	if overlay.Notify.WebhookURL != "" {
		r.Notify.WebhookURL = overlay.Notify.WebhookURL
		if overlay.Notify.WebhookFormat != "" {
			r.Notify.WebhookFormat = overlay.Notify.WebhookFormat
		}
		if overlay.Notify.WebhookChatID != "" {
			r.Notify.WebhookChatID = overlay.Notify.WebhookChatID
		}
	}
	if overlay.LearnMinutes > 0 {
		r.LearnMinutes = overlay.LearnMinutes
	}
	if len(overlay.BadPorts) > 0 {
		r.BadPorts = overlay.BadPorts
	}
	if len(overlay.TrustedCIDRs) > 0 {
		r.TrustedCIDRs = overlay.TrustedCIDRs
	}
	if len(overlay.SensitivePaths) > 0 {
		r.SensitivePaths = overlay.SensitivePaths
	}
	if len(overlay.PasswordManagerPaths) > 0 {
		r.PasswordManagerPaths = overlay.PasswordManagerPaths
	}
	if len(overlay.ProcessAllow) > 0 {
		r.ProcessAllow = overlay.ProcessAllow
	}
	if len(overlay.QuietApps) > 0 {
		r.QuietApps = overlay.QuietApps
	}
	if overlay.NewEndpointBurst > 0 {
		r.NewEndpointBurst = overlay.NewEndpointBurst
	}
	if len(overlay.ProcessBad) > 0 {
		r.ProcessBad = overlay.ProcessBad
	}
	if len(overlay.BadTCCClient) > 0 {
		r.BadTCCClient = overlay.BadTCCClient
	}
	return r
}

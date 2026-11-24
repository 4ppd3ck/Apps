package main

// Verdict — the plain-English layer on top of findings: a one-word badge
// ("safe" / "suspicious" / "info") plus one sentence a non-technical reader
// can act on. Detectors keep writing precise findings; this layer only
// translates them, keyed off the detectors' own titles so the phrasing
// stays honest to what actually fired. Known-provider endpoints (wGrid)
// are the one "safe" story: a browser syncing to Google is normal life,
// not a compromise indicator, and deserves to read that way.

import "strings"

const (
	VerdictSafe       = "safe"
	VerdictSuspicious = "suspicious"
	VerdictInfo       = "info"
)

// verdictFor classifies a finding for the badge column. Known-provider
// endpoints win over severity (they are labelled info already); anything
// medium and above reads as suspicious; the rest is informational.
func verdictFor(f Finding) string {
	if FmtAny(f.Evidence["intel_known"]) != "" {
		return VerdictSafe
	}
	if f.Severity == SevInfo || f.Severity == SevLow {
		return VerdictInfo
	}
	return VerdictSuspicious
}

// plainFor is the one-sentence explanation shown under a finding and sent
// in desktop notifications. Detectors stamp findings with granular check
// names (proc_tmp, listen_backdoor, …) — those match first; the coarse
// names (processes, network, …) stay as a title-keyed fallback.
func plainFor(f Finding) string {
	intel := FmtAny(f.Evidence["intel_known"])
	if intel != "" {
		return "The app talked to a server run by a known provider (" + intel +
			"). Browsers, sync services and updaters do this constantly — nothing looks wrong."
	}
	switch f.Check {
	case "listen_backdoor":
		return "A program is waiting for connections on a port that remote-control and hacker tools commonly use. If you installed the app shown here, this is probably that tool working — if not, block it."
	case "conn_badport":
		return "A program is connected to a remote-control service over the internet. If you use a remote-access app this is it working; if not, someone may be controlling this machine."
	case "beacon":
		return "An app is checking in with a server on a fixed schedule — the way hidden surveillance tools phone home. Worth a look."
	case "new_endpoint", "endpoints":
		return "An app started talking to servers it never contacted before. New destinations can just be an app updating; a burst from something you don't recognize is worth a look."
	case "zombie":
		return "A leftover process is stuck. Harmless by itself, but it can hint at an app that crashed badly."
	case "proc_bad":
		return "A program whose name matches known hacking tools is running. This is rarely legitimate — review it now."
	case "proc_tmp":
		return "A program is running out of a temporary folder. Real apps install into proper locations; malware often doesn't bother."
	case "proc_orphan":
		return "Background processes lost the app that launched them. Sometimes just a crash — also how malware hides."
	case "gateway_mac", "gateway_ip":
		return "Your router's network identity changed. Normal after a router restart or swap — unexpected otherwise, because impersonating your router is how traffic gets intercepted."
	case "arp_conflict", "arp_spoof":
		return "Two devices on your network are fighting over the same address — a classic sign of an interception attempt, or a misbehaving gadget."
	case "dns_change":
		return "The machine's DNS settings — the internet's address book — were switched. Can be a VPN or a new router; also how traffic gets silently redirected."
	case "dns_rebind":
		return "An internet name now answers with a local address — a known trick (DNS rebinding) used to reach devices on your network from a web page."
	case "persistence":
		return "A new program set itself up to start automatically. If you just installed something this is expected — otherwise find out what it is."
	case "keylogger_name":
		return "A program that can watch everything typed on this keyboard is running. Keyloggers look exactly like this."
	case "tcc_grant", "tcc":
		return "An app was granted access to private hardware or data (camera, microphone, files…). macOS doesn't ask twice — confirm it matches something you installed."
	case "privacy_exfil":
		return "An app that can read private data is talking to the internet right now — the combination worth watching."
	case "file_exfil":
		return "An app has a sensitive file open (passwords, cookies…) while connected to the internet."
	}
	switch f.Check {
	case "network":
		switch {
		case strings.Contains(f.Title, "Listener on known remote-control port"):
			return "A program is waiting for connections on a port that remote-control and hacker tools commonly use. If you installed the app shown here, this is probably that tool working — if not, block it."
		case strings.Contains(f.Title, "Active connection to remote-control port"):
			return "A program is connected to a remote-control service over the internet. If you use a remote-access app this is it working; if not, someone may be controlling this machine."
		case strings.Contains(f.Title, "Clockwork callback"):
			return "An app is checking in with a server on a fixed schedule — the way hidden surveillance tools phone home. Worth a look."
		case strings.Contains(f.Title, "New outbound endpoints"):
			return "An app started talking to servers it never contacted before. New destinations can just be an app updating; a burst from something you don't recognize is worth a look."
		default:
			return "A network connection stood out from this machine's normal pattern."
		}
	case "processes":
		switch {
		case strings.Contains(f.Title, "Known attack tool"):
			return "A program whose name matches known hacking tools is running. This is rarely legitimate — review it now."
		case strings.Contains(f.Title, "temp directory"):
			return "A program is running out of a temporary folder. Real apps install into proper locations; malware often doesn't bother."
		case strings.Contains(f.Title, "Zombie process"):
			return "A leftover process is stuck. Harmless by itself, but it can hint at an app that crashed badly."
		case strings.Contains(f.Title, "lost their parent"):
			return "Several background processes lost the app that launched them, all at once. Sometimes just a crash — also how malware hides."
		default:
			return "Something about a running process looked unusual."
		}
	case "mitm":
		switch {
		case strings.Contains(f.Title, "gateway MAC"), strings.Contains(f.Title, "gateway IP"):
			return "Your router's network identity changed. Normal after a router restart or swap — unexpected otherwise, because impersonating your router is how traffic gets intercepted."
		case strings.Contains(f.Title, "ARP flapping"), strings.Contains(f.Title, "claims"):
			return "Two devices on your network are fighting over the same address — a classic sign of an interception attempt, or a misbehaving gadget."
		case strings.Contains(f.Title, "DNS resolvers fully replaced"):
			return "The machine's DNS settings — the internet's address book — were switched. Can be a VPN or a new router; also how traffic gets silently redirected."
		case strings.Contains(f.Title, "resolves into private address space"):
			return "An internet name now answers with a local address — a known trick (DNS rebinding) used to reach devices on your network from a web page."
		default:
			return "A network-level setting shifted; worth confirming it was you."
		}
	case "firewall":
		switch {
		case strings.Contains(f.Title, "turned off"), strings.Contains(f.Title, "is disabled"):
			return "Your firewall is off, so unsolicited connections are no longer filtered. Turn it back on unless you did this on purpose."
		case strings.Contains(f.Title, "default policy opened"):
			return "The firewall switched to allowing incoming connections by default."
		case strings.Contains(f.Title, "allows an app"):
			return "The firewall was told to let a specific app receive incoming connections."
		case strings.Contains(f.Title, "Stealth mode"), strings.Contains(f.Title, "Block-all"):
			return "A firewall protection was turned down a notch."
		default:
			return "The firewall's configuration changed."
		}
	case "exfil":
		switch {
		case strings.Contains(f.Title, "keystroke monitor"):
			return "A program that can watch everything typed on this keyboard is running. Keyloggers look exactly like this."
		case strings.Contains(f.Title, "New "), strings.Contains(f.Title, "grant"):
			return "An app was granted access to private hardware or data (camera, microphone, files…). macOS doesn't ask twice — confirm it matches something you installed."
		case strings.Contains(f.Title, "active in"):
			return "An app that can read private data is talking to the internet right now — the combination worth watching."
		case strings.Contains(f.Title, "Sensitive file"):
			return "An app has a sensitive file open (passwords, cookies…) while connected to the internet."
		default:
			return "An app touched private data or hardware in a way the watchdog found notable."
		}
	case "sensitive":
		switch {
		case strings.Contains(f.Title, "is using the"):
			return "An app is using the camera or microphone right now. If you can't tell which app, take it seriously."
		case strings.Contains(f.Title, "used the"):
			return "An app used the camera or microphone recently."
		case strings.Contains(f.Title, "password-manager"):
			return "An app is reading password-manager data. Only your password manager should ever do that."
		case strings.Contains(f.Title, "Sensitive file open"):
			return "An app has a sensitive file open while talking to the internet."
		default:
			return "An app touched private hardware or data."
		}
	default:
		if f.Detail != "" {
			return f.Detail
		}
		return f.Title
	}
}

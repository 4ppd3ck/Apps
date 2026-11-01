// Where a download may land, and which requests may ask for it.
//
// wScout saves files the user picks, so the destination is genuinely a path
// the client names. That makes two things worth pinning down:
//
//   - The destination must not be a place a *file write* becomes code
//     execution or persistence: shell startup files, dot-directories
//     (~/.ssh, ~/.config, ~/.local), macOS ~/Library (LaunchAgents), Windows
//     AppData/Startup, and the system roots. A downloaded asset belongs in
//     Downloads, Documents, Desktop or a project folder — never in one of
//     those.
//   - The listener is loopback-bound, but a web page can be pointed at
//     127.0.0.1 (DNS rebinding) and then the peer really is loopback. The Host
//     allowlist plus the same-origin checks on mutations are what stop a
//     random page from calling /api/save at all.
//
// Stdlib only, no build tags: filepath/path handling here works on darwin,
// linux and windows (volume names and backslashes included).
package main

import (
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// protectedSavePath reports whether p is a destination a download must never
// overwrite: a dot-path anywhere in the chain, a known startup/persistence
// directory, or a system root.
func protectedSavePath(p string) bool {
	if strings.TrimSpace(p) == "" {
		return true
	}
	clean := filepath.Clean(p)
	if base := filepath.Base(clean); base == "." || base == ".." || base == string(filepath.Separator) {
		return true
	}
	slash := filepath.ToSlash(clean)
	for _, seg := range strings.Split(slash, "/") {
		if seg == "" {
			continue
		}
		lower := strings.ToLower(seg)
		if strings.HasPrefix(lower, ".") && lower != "." && lower != ".." {
			return true // ~/.zshrc, ~/.ssh/authorized_keys, ~/.config/…
		}
		switch lower {
		case "library", "launchagents", "launchdaemons", // macOS persistence
			"appdata", "startup", "start menu", "start-menu": // Windows persistence
			return true
		}
	}
	// System roots, compared case-insensitively (Windows paths are). /var and
	// /tmp are deliberately absent: they are scratch space, not persistence
	// (and /var/folders is where macOS hands out temp dirs).
	lower := strings.ToLower(slash)
	for _, root := range []string{
		"/etc", "/usr", "/bin", "/sbin", "/system", "/library", "/private/etc",
	} {
		if lower == root || strings.HasPrefix(lower, root+"/") {
			return true
		}
	}
	if sys := strings.ToLower(strings.TrimSpace(os.Getenv("SystemRoot"))); sys != "" {
		sys = filepath.ToSlash(sys)
		if lower == sys || strings.HasPrefix(lower, sys+"/") {
			return true
		}
	}
	if vol := strings.ToLower(filepath.ToSlash(filepath.VolumeName(clean))); vol != "" {
		for _, root := range []string{"/program files", "/program files (x86)", "/programdata"} {
			if strings.HasPrefix(lower, vol+root) {
				return true
			}
		}
	}
	return false
}

// dotfileInHome reports whether saving finalName into dir would drop a
// hidden file straight into the home directory — the shell-startup spot
// (.zshrc, .gitconfig, …). Checked BEFORE uniquification: uniquePath's
// "stem (1).ext" fallback mangles a leading-dot name into a non-dot base
// (" (1).zshrc"), which would slip past a composed-path-only check.
func dotfileInHome(dir, finalName string) bool {
	if !strings.HasPrefix(finalName, ".") || finalName == "." || finalName == ".." {
		return false
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return true // cannot resolve home: refuse hidden files outright
	}
	return strings.EqualFold(filepath.Clean(dir), filepath.Clean(home))
}

// protectedSaveTarget is the composed-destination check for the dir+name flow:
// the directory rules from protectedSavePath on the containing folder, plus a
// dotfile rule for the home directory itself, where a hidden file would
// overwrite a shell startup script (.zshrc, .bashrc, .gitconfig). Dotfiles in
// ordinary folders (a repo's .gitignore, .npmrc) stay allowed.
func protectedSaveTarget(target string) bool {
	clean := filepath.Clean(target)
	if protectedSavePath(filepath.Dir(clean)) {
		return true
	}
	base := filepath.Base(clean)
	if strings.HasPrefix(base, ".") && base != "." && base != ".." {
		home, err := os.UserHomeDir()
		if err != nil {
			return true // cannot resolve home: refuse hidden files outright
		}
		if strings.EqualFold(filepath.Dir(clean), filepath.Clean(home)) {
			return true
		}
	}
	return false
}

// hostAllowed mirrors the launcher's rule: this server answers to loopback,
// its own bind host, and IP literals — never to a domain, which is what a
// rebinding attack needs.
func hostAllowed(hostPort, bindHost string) bool {
	if hostPort == "" { // HTTP/1.0: no Host to rebind
		return true
	}
	host := hostPort
	if h, _, err := net.SplitHostPort(hostPort); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" || host == "localhost" || (bindHost != "" && host == strings.ToLower(bindHost)) {
		return true
	}
	return net.ParseIP(host) != nil
}

func rejectCrossSite(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(msg))
}

// hostGuard fences the API off from rebound pages and cross-site posts.
func hostGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !hostAllowed(r.Host, "127.0.0.1") {
			rejectCrossSite(w, "rejected: Host header does not name this server (DNS-rebinding guard)\n")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" &&
				sfs != "same-origin" && sfs != "same-site" && sfs != "none" {
				rejectCrossSite(w, "rejected: cross-site request to a loopback API (Sec-Fetch-Site guard)\n")
				return
			}
			if org := r.Header.Get("Origin"); org != "" {
				u, err := url.Parse(org)
				if err != nil || org == "null" || !hostAllowed(u.Host, "127.0.0.1") {
					rejectCrossSite(w, "rejected: cross-origin request to a loopback API (Origin guard)\n")
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

package main

// Loopback hardening for the HTTP API: DNS-rebinding + cross-site POST guard.
//
// Binding to 127.0.0.1 alone does not stop a malicious web page:
//   - DNS rebinding: the page rebinds its domain to 127.0.0.1 so the browser
//     treats its requests as same-origin (and readable). Those requests carry
//     Host: <attacker-domain>, so rejecting non-loopback/non-IP Hosts closes it.
//   - direct cross-site POST: a page can still POST to http://127.0.0.1:port
//     without reading the reply. Browsers mark such requests Sec-Fetch-Site:
//     cross-site (or send a foreign/null Origin); non-GET requests carrying
//     those markers are rejected. Non-browser clients (curl, the peer Go
//     apps) send neither header and pass untouched.
//   - token fence: when the launcher injected APPDECK_TOKEN, /api/ requests
//     from non-loopback callers must carry it as X-AppDeck-Token (constant-
//     time compare). Defense in depth — the server binds 127.0.0.1, so today
//     no non-loopback caller can even connect; the fence is here for the day
//     the bind widens. Loopback (the operator's own machine) is exempt.
import (
	"crypto/subtle"
	"net"
	"net/http"
	"net/url"
	"strings"
)

func hostGuard(bindHost string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !hostAllowed(r.Host, bindHost) {
			reject(w, "rejected: Host header does not name this server (DNS-rebinding guard)\n")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" &&
				sfs != "same-origin" && sfs != "same-site" && sfs != "none" {
				reject(w, "rejected: cross-site request to a loopback API (Sec-Fetch-Site guard)\n")
				return
			}
			if org := r.Header.Get("Origin"); org != "" &&
				(org == "null" || !hostAllowed(urlHost(org), bindHost)) {
				reject(w, "rejected: cross-origin request to a loopback API (Origin guard)\n")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func reject(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte(msg))
}

// tokenFence enforces the launcher's non-loopback token rule: when
// APPDECK_TOKEN is set, /api/ requests from non-loopback callers must carry
// it as X-AppDeck-Token (constant-time compare). Loopback callers — the local
// browser, sibling apps — are always exempt; OPTIONS carries no data and
// passes.
func tokenFence(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token != "" && r.Method != http.MethodOptions &&
			strings.HasPrefix(r.URL.Path, "/api/") && !fromLoopback(r) &&
			subtle.ConstantTimeCompare([]byte(r.Header.Get("X-AppDeck-Token")), []byte(token)) != 1 {
			http.Error(w, "missing or wrong X-AppDeck-Token", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func fromLoopback(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func urlHost(origin string) string {
	u, err := url.Parse(origin)
	if err != nil {
		return origin
	}
	return u.Host
}

func hostAllowed(hostPort, bindHost string) bool {
	if hostPort == "" { // HTTP/1.0 request: no Host to rebind
		return true
	}
	host := hostPort
	if h, _, err := net.SplitHostPort(hostPort); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if host == "" || strings.EqualFold(host, "localhost") ||
		(bindHost != "" && strings.EqualFold(host, bindHost)) {
		return true
	}
	return net.ParseIP(host) != nil // any IP literal; a domain cannot be rebound into one
}

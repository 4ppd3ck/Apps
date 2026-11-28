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
//     apps) send neither header and pass untouched. The Origin check is the
//     stricter of the two: unlike Host it is attacker-chosen, so it must name
//     loopback (or the bind host / the addressed host:port) — not just any IP.
import (
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
				(org == "null" || !originAllowed(urlHost(org), r.Host, bindHost)) {
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

func urlHost(origin string) string {
	u, err := url.Parse(origin)
	if err != nil {
		return origin
	}
	return u.Host
}

// hostAllowed names the hosts a request may be addressed to: localhost, a
// loopback address, the configured bind host, or any IP literal.
func hostAllowed(hostPort, bindHost string) bool {
	if hostPort == "" { // HTTP/1.0 request: no Host to rebind
		return true
	}
	host := hostname(hostPort)
	return localHost(host, bindHost) ||
		net.ParseIP(host) != nil // any IP literal; a domain cannot be rebound into one
}

// originAllowed is the Origin test, stricter than hostAllowed: "some IP
// literal" must not be enough, or a page on http://192.168.1.50 could POST
// here whenever Sec-Fetch-Site is absent. The page must sit on loopback or
// the bind host, or on the very host:port it posts to (the app's own UI on
// a widened bind).
func originAllowed(originHost, reqHost, bindHost string) bool {
	return strings.EqualFold(originHost, reqHost) || localHost(hostname(originHost), bindHost)
}

func hostname(hostPort string) string {
	host := hostPort
	if h, _, err := net.SplitHostPort(hostPort); err == nil {
		host = h
	}
	return strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
}

// localHost: localhost, a loopback address, or the bind host — on any port,
// since sibling apps relay from other loopback ports.
func localHost(host, bindHost string) bool {
	if host == "" || strings.EqualFold(host, "localhost") ||
		(bindHost != "" && strings.EqualFold(host, bindHost)) {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

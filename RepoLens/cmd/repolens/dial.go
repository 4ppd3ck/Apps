package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Android's app sandbox has no /etc/resolv.conf for native processes, so the
// pure-Go resolver has no nameservers to use and lookups fail (observed as
// "lookup api.github.com on [::1]:53: read: connection refused"). Desktop and
// other platforms keep the default system resolver; Android gets an explicit
// resolver with fallback candidates.
var (
	androidDNSOnce sync.Once
	androidRes     *net.Resolver
)

func newHTTPClient(timeout time.Duration) *http.Client {
	client := &http.Client{Timeout: timeout}
	if runtime.GOOS == "android" {
		client.Transport = &http.Transport{
			DialContext:           androidDialContext,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			IdleConnTimeout:       60 * time.Second,
			MaxIdleConnsPerHost:   4,
		}
	}
	return client
}

func androidDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second, Resolver: getAndroidResolver()}
	return d.DialContext(ctx, network, address)
}

func getAndroidResolver() *net.Resolver {
	androidDNSOnce.Do(func() {
		servers := dnsCandidates()
		androidRes = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: 4 * time.Second}
				var lastErr error
				for _, s := range servers {
					c, err := d.DialContext(ctx, network, s)
					if err == nil {
						return c, nil
					}
					lastErr = err
				}
				if lastErr == nil {
					lastErr = &net.DNSError{Err: "no DNS servers available", Name: "dns"}
				}
				return nil, lastErr
			},
		}
	})
	return androidRes
}

func dnsCandidates() []string {
	seen := map[string]bool{}
	var out []string
	add := func(host string) {
		host = strings.TrimSpace(host)
		if host == "" || host == "0.0.0.0" || host == "::1" || host == "127.0.0.1" {
			return
		}
		s := net.JoinHostPort(host, "53")
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	// Prefer the device's own resolver config when present (some builds keep one).
	if raw, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[0] == "nameserver" {
				add(fields[1])
			}
		}
	}
	// Android rarely exposes DNS via properties, but try anyway.
	for _, key := range []string{"net.dns1", "net.dns2", "net.dns3", "dns1", "dns2"} {
		if v := getprop(key); v != "" {
			add(v)
		}
	}
	// Public fallbacks; at least one is reachable on virtually any network.
	add("1.1.1.1")
	add("8.8.8.8")
	add("9.9.9.9")
	add("208.67.222.222")
	return out
}

func getprop(key string) string {
	out, err := exec.Command("getprop", key).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

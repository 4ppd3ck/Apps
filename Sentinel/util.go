package main

// Shared helpers: safe command execution, IP classification, JSON file IO.

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

// RunOut executes a command and returns trimmed stdout; err on failure.
// A generous-but-bounded timeout keeps a wedged helper from stalling checks.
func RunOut(timeout time.Duration, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// IPClass mirrors AppScope Monitor's classify_ip so both apps speak the
// same vocabulary: loopback, linklocal, private, cgnat, multicast, public…
func IPClass(ipStr string) string {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return "invalid"
	}
	if ip.IsLoopback() {
		return "loopback"
	}
	if ip.IsLinkLocalUnicast() {
		return "linklocal"
	}
	if ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return "multicast"
	}
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] < 128 {
			return "cgnat"
		}
		if ip4[0] == 10 || (ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) ||
			(ip4[0] == 192 && ip4[1] == 168) {
			return "private"
		}
		if ip4[0] == 0 || ip4[0] == 255 || ip4[0] >= 240 {
			return "reserved"
		}
	}
	if ip.IsPrivate() {
		return "private"
	}
	return "public"
}

// InCIDRs reports whether ip falls inside any of the CIDR strings.
func InCIDRs(ipStr string, cidrs []string) bool {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false
	}
	for _, c := range cidrs {
		_, netw, err := net.ParseCIDR(c)
		if err != nil {
			continue
		}
		if netw.Contains(ip) {
			return true
		}
	}
	return false
}

// IsExternal is the "rogue candidate" test: public, or LAN when the user
// has not trusted that range (rules.trusted_cidrs).
func IsExternal(ipStr string, rules *Rules) bool {
	class := IPClass(ipStr)
	if class == "loopback" || class == "invalid" || class == "multicast" ||
		class == "reserved" || class == "linklocal" {
		return false
	}
	return !InCIDRs(ipStr, rules.TrustedCIDRs)
}

// NowF is the shared unix-seconds float timestamp (matches monitor events).
func NowF() float64 { return float64(time.Now().UnixNano()) / 1e9 }

func FmtErr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func SaveJSON(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func LoadJSON(path string, v any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

func F(size any) string {
	switch n := size.(type) {
	case int64:
		return fmt.Sprintf("%d", n)
	case int:
		return fmt.Sprintf("%d", n)
	case float64:
		return fmt.Sprintf("%.0f", n)
	default:
		return FmtAny(n)
	}
}

func AnyBool(v any) bool {
	b, _ := v.(bool)
	return b
}

//go:build !windows

package wtower

import (
	"bufio"
	"net"
	"os"
	"strings"
)

// systemUpstreams reads the machine's own resolver list for the DNS shield:
// the nameserver lines of /etc/resolv.conf. macOS keeps that file in sync
// with the active network service; Linux distros write it directly or via
// systemd-resolved's stub (whose 127.0.0.53 entry the caller's loopback
// filter drops). Only IPv4 nameservers are returned — the relay dials
// udp4/tcp4. Raw list: the caller applies the loopback policy.
func systemUpstreams() []string {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 2 && strings.EqualFold(fields[0], "nameserver") {
			if ip := net.ParseIP(fields[1]); ip != nil && ip.To4() != nil {
				out = append(out, ip.String())
			}
		}
	}
	return out
}

//go:build windows

package wtower

import (
	"net"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// systemUpstreams reads the DNS servers Windows is actually configured to
// use: the per-interface Tcpip parameters under HKLM carry the static
// NameServer list and the DHCP-learned DhcpNameServer list. Windows has no
// /etc/resolv.conf, so without this the shield would always fall back to
// its public resolvers and stop using the network's own ones. Only IPv4,
// non-loopback servers are returned (the relay dials udp4/tcp4); the
// caller applies the same loopback policy as on the other platforms.
func systemUpstreams() []string {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`,
		registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer key.Close()
	names, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return nil
	}
	var out []string
	for _, name := range names {
		iface, err := registry.OpenKey(key, name, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		for _, value := range []string{"NameServer", "DhcpNameServer"} {
			raw, _, err := iface.GetStringValue(value)
			if err != nil {
				continue
			}
			for _, part := range strings.FieldsFunc(raw, func(r rune) bool {
				return r == ',' || r == ' ' || r == '\t' || r == '\r' || r == '\n'
			}) {
				if ip := net.ParseIP(strings.TrimSpace(part)); ip != nil && ip.To4() != nil {
					out = append(out, ip.String())
				}
			}
		}
		iface.Close()
	}
	return out
}

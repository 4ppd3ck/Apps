package main

// MITM / network-compromise checks:
//   - default-gateway MAC change (ARP spoof / rogue AP / cable swap)
//   - ARP table anomalies (IP→MAC conflicts, one MAC claiming many IPs)
//   - DNS resolver change (silent redirect to a hostile resolver)
//   - DNS rebinding probe (known domains resolving into private space)
//
// All state is baseline-diffed, so first-run learns instead of alerting.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"time"
)

type GatewayInfo struct {
	Iface string `json:"iface"`
	IP    string `json:"ip"`
	MAC   string `json:"mac"`
}

type ArpEntry struct {
	IP  string `json:"ip"`
	MAC string `json:"mac"`
}

type NetBaseline struct {
	Gateway   GatewayInfo       `json:"gateway"`
	Resolvers []string          `json:"resolvers"`
	Arp       map[string]string `json:"arp"`
}

func getGateway() (GatewayInfo, error) {
	switch runtime.GOOS {
	case "darwin", "freebsd", "openbsd", "netbsd":
		return gwBSD()
	case "linux":
		return gwLinux()
	case "windows":
		return gwWin()
	}
	return GatewayInfo{}, fmt.Errorf("gateway detection unavailable on %s", runtime.GOOS)
}

func gwBSD() (GatewayInfo, error) {
	out, err := RunOut(5*time.Second, "route", "-n", "get", "default")
	if err != nil {
		return GatewayInfo{}, err
	}
	gw := GatewayInfo{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 {
			switch f[0] {
			case "gateway:":
				gw.IP = f[1]
			case "interface:":
				gw.Iface = f[1]
			}
		}
	}
	if gw.IP != "" {
		mac := arpLookupBSD(gw.IP)
		if mac == "" {
			// ARP entries time out; a cold table leaves the MAC empty and
			// disarms the strongest MITM signal. One ping re-populates it.
			_, _ = RunOut(2*time.Second, "ping", "-c", "1", "-W", "1000", gw.IP)
			mac = arpLookupBSD(gw.IP)
		}
		if mac == "" {
			// Some hotspots proxy ARP and age the v4 neighbour out in under
			// a second — the ping reply never leaves a readable entry. The
			// IPv6 side keeps state far longer: read the gateway MAC from
			// ndp, falling back to the EUI-64 encoding inside the link-local
			// default gateway address.
			mac = ndpGatewayMAC(gw.Iface)
		}
		gw.MAC = mac
	}
	return gw, nil
}

// ndpGatewayMAC finds the IPv6 default gateway's MAC: first from `ndp -an`,
// then by decoding the EUI-64 interface identifier in its link-local address
// (fe80::xx:xx:xx:ff:fe:xx:xx -> xx:xx:xx:xx:xx:xx with the U/L bit flipped).
func ndpGatewayMAC(iface string) string {
	out, err := RunOut(5*time.Second, "route", "-n", "get", "-inet6", "default")
	if err != nil {
		return ""
	}
	gw6 := ""
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "gateway:" {
			gw6 = f[1]
		}
	}
	if gw6 == "" {
		return ""
	}
	ll := strings.Split(gw6, "%")[0]
	if ip := net.ParseIP(ll); ip != nil {
		if mac := eui64ToMAC(ip); mac != "" {
			return mac
		}
	}
	// last resort: the live ndp table
	if out, err := RunOut(5*time.Second, "ndp", "-an"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 && strings.HasPrefix(f[0], "fe80:") &&
				strings.Count(f[1], ":") == 5 {
				return strings.ToLower(f[1])
			}
		}
	}
	return ""
}

// eui64ToMAC decodes a modified EUI-64 interface identifier (ff:fe marker in
// the middle) back into the 48-bit MAC, unflipping the U/L bit.
// fe80::ec46:d6ff:fe0d:edc3 -> ee:46:d6:0d:ed:c3.
func eui64ToMAC(ip net.IP) string {
	b := ip.To16()
	if b == nil || b[11] != 0xff || b[12] != 0xfe {
		return ""
	}
	return net.HardwareAddr{b[8] ^ 0x02, b[9], b[10], b[13], b[14], b[15]}.String()
}

func arpLookupBSD(ip string) string {
	out, err := RunOut(5*time.Second, "arp", "-n", ip)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		// macOS format: "? (10.221.143.33) at ee:46:d6:d:ed:c3 on en0 ifscope"
		// the IP sits in parens at field 1 (field 0 is "?" or the hostname)
		if len(f) < 4 {
			continue
		}
		lineIP := strings.Trim(f[1], "()")
		if lineIP != ip {
			continue
		}
		for _, cand := range f[2:] {
			if strings.Count(cand, ":") >= 5 {
				return strings.ToLower(cand)
			}
		}
	}
	return ""
}

func gwLinux() (GatewayInfo, error) {
	raw, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return GatewayInfo{}, err
	}
	gw := GatewayInfo{}
	for _, line := range strings.Split(string(raw), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 8 || f[1] != "00000000" {
			continue
		}
		gw.Iface = f[0]
		hexIP := f[2]
		var b [4]byte
		for j := 0; j < 4; j++ {
			var v int64
			fmt.Sscanf(hexIP[j*2:j*2+2], "%02x", &v)
			b[3-j] = byte(v)
		}
		gw.IP = net.IP(b[:]).String()
		break
	}
	if gw.IP != "" {
		if e, err := os.ReadFile("/proc/net/arp"); err == nil {
			for _, line := range strings.Split(string(e), "\n")[1:] {
				f := strings.Fields(line)
				if len(f) >= 6 && f[0] == gw.IP && f[3] != "00:00:00:00:00:00" {
					gw.MAC = strings.ToLower(f[3])
				}
			}
		}
		if gw.MAC == "" {
			// warm the neighbour cache, then re-read
			_, _ = RunOut(2*time.Second, "ping", "-c", "1", "-W", "1", gw.IP)
			if e, err := os.ReadFile("/proc/net/arp"); err == nil {
				for _, line := range strings.Split(string(e), "\n")[1:] {
					f := strings.Fields(line)
					if len(f) >= 6 && f[0] == gw.IP && f[3] != "00:00:00:00:00:00" {
						gw.MAC = strings.ToLower(f[3])
					}
				}
			}
		}
	}
	return gw, nil
}

func gwWin() (GatewayInfo, error) {
	ps := `$ErrorActionPreference='SilentlyContinue';` +
		`$r=Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1;` +
		`$n=Get-NetNeighbor -IPAddress $r.NextHop -ErrorAction SilentlyContinue | Select-Object -First 1;` +
		`[pscustomobject]@{iface=$r.InterfaceAlias;ip=$r.NextHop;mac=$n.LinkLayerAddress} | ConvertTo-Json -Compress`
	out, err := RunOut(20*time.Second, "powershell", "-NoProfile", "-Command", ps)
	if err != nil {
		return GatewayInfo{}, err
	}
	var g GatewayInfo
	if err := json.Unmarshal([]byte(out), &g); err != nil {
		return GatewayInfo{}, err
	}
	g.MAC = strings.ToLower(g.MAC)
	return g, nil
}

func getArpTable() []ArpEntry {
	entries := []ArpEntry{}
	switch runtime.GOOS {
	case "darwin", "freebsd", "openbsd", "netbsd":
		out, err := RunOut(5*time.Second, "arp", "-an")
		if err != nil {
			return entries
		}
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			ip := strings.Trim(f[1], "()")
			for _, cand := range f[2:] {
				if strings.Count(cand, ":") == 5 {
					entries = append(entries, ArpEntry{IP: ip, MAC: strings.ToLower(cand)})
					break
				}
			}
		}
	case "linux":
		raw, err := os.ReadFile("/proc/net/arp")
		if err != nil {
			return entries
		}
		for _, line := range strings.Split(string(raw), "\n")[1:] {
			f := strings.Fields(line)
			if len(f) >= 6 && f[3] != "00:00:00:00:00:00" {
				entries = append(entries, ArpEntry{IP: f[0], MAC: strings.ToLower(f[3])})
			}
		}
	case "windows":
		out, err := RunOut(15*time.Second, "arp", "-a")
		if err != nil {
			return entries
		}
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			if len(f) >= 3 && net.ParseIP(f[0]) != nil && strings.Count(f[1], "-") == 5 {
				entries = append(entries, ArpEntry{IP: f[0],
					MAC: strings.ToLower(strings.ReplaceAll(f[1], "-", ":"))})
			}
		}
	}
	return entries
}

func getResolvers() []string {
	out := []string{}
	switch runtime.GOOS {
	case "darwin":
		if outStr, err := RunOut(5*time.Second, "scutil", "--dns"); err == nil {
			// Only the FIRST resolver section is the system default; the
			// rest are per-domain scoped resolvers whose membership churns
			// with interface state (router DNS appearing/vanishing from
			// scoped entries). Watching the primary alone is both stable
			// and the right hijack signal.
			seen := map[string]bool{}
			for _, line := range strings.Split(outStr, "\n") {
				if strings.HasPrefix(line, "resolver #") && len(seen) > 0 {
					break // second section: stop
				}
				if strings.Contains(line, "nameserver[") {
					f := strings.Fields(line)
					if len(f) >= 3 && !seen[f[2]] {
						seen[f[2]] = true
						out = append(out, f[2])
					}
				}
			}
		}
	case "windows":
		if outStr, err := RunOut(20*time.Second, "powershell", "-NoProfile", "-Command",
			`(Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object {$_.ServerAddresses} | Select-Object -First 3).ServerAddresses -join ','`); err == nil {
			for _, s := range strings.Split(outStr, ",") {
				if s = strings.TrimSpace(s); s != "" {
					out = append(out, s)
				}
			}
		}
	default: // POSIX resolv.conf
		if f, err := os.Open("/etc/resolv.conf"); err == nil {
			defer f.Close()
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				flds := strings.Fields(sc.Text())
				if len(flds) >= 2 && flds[0] == "nameserver" {
					out = append(out, flds[1])
				}
			}
		}
	}
	return out
}

// ---------------------------------------------------------------- checks ----

func mitmFindings(store *Store, rules *Rules) []Finding {
	now := NowF()
	findings := []Finding{}
	gw, err := getGateway()
	if err != nil {
		return []Finding{{
			Check: "mitm", Severity: SevInfo, Title: "Network baseline unavailable",
			Detail: FmtErr(err),
		}}
	}

	// ---- gateway MAC change
	gwVal, existed := store.BaselineKey("gateway", gw)
	if existed {
		if prev, ok := gwVal.(map[string]any); ok {
			prevMAC, _ := prev["mac"].(string)
			prevIP, _ := prev["ip"].(string)
			if gw.MAC != "" && prevMAC != "" && !strings.EqualFold(prevMAC, gw.MAC) {
				findings = append(findings, Finding{
					Check:    "gateway_mac",
					Severity: SevCritical,
					Title:    "Default gateway MAC address changed",
					Detail: fmt.Sprintf("%s was %s, now answers at %s (iface %s). "+
						"A gateway MAC change with no router replacement is the "+
						"signature of ARP spoofing / a rogue access point / a "+
						"transparent MITM box on your path. Rebooting the router "+
						"or moving networks also explains it — verify which.",
						prevIP, prevMAC, gw.IP, gw.Iface),
					Evidence: map[string]any{
						"iface": gw.Iface, "ip": gw.IP,
						"old_mac": prevMAC, "new_mac": gw.MAC,
					},
					Fingerprint: FingerprintOf("gateway_mac",
						prevMAC+"->"+gw.MAC+"@"+gw.Iface),
				})
			} else if prevIP != gw.IP && gw.IP != "" {
				findings = append(findings, Finding{
					Check:    "gateway_ip",
					Severity: SevLow,
					Title:    "Default gateway IP changed",
					Detail: fmt.Sprintf("%s → %s (iface %s). Normal when switching "+
						"networks; unexpected on a static setup.", prevIP, gw.IP, gw.Iface),
					Evidence:    map[string]any{"old": prevIP, "new": gw.IP, "iface": gw.Iface},
					Fingerprint: FingerprintOf("gateway_ip", prevIP+"->"+gw.IP),
				})
			}
		}
	}

	// If the baseline learned an empty MAC (cold ARP table on first run),
	// adopt the first real MAC silently instead of staying disarmed.
	if gwVal2, ok := store.BaselineList()["gateway"].(map[string]any); ok {
		prevMAC, _ := gwVal2["mac"].(string)
		if prevMAC == "" && gw.MAC != "" {
			updated := map[string]any{
				"iface": gw.Iface, "ip": gw.IP, "mac": gw.MAC,
			}
			store.BaselineUpdate("gateway", updated)
		}
	}

	// ---- ARP anomalies
	arp := getArpTable()
	ip2mac := map[string]string{}
	macIPs := map[string][]string{}
	for _, e := range arp {
		if prev, ok := ip2mac[e.IP]; ok && prev != e.MAC {
			findings = append(findings, Finding{
				Check:    "arp_conflict",
				Severity: SevHigh,
				Title:    fmt.Sprintf("ARP flapping: %s claimed by two MACs", e.IP),
				Detail: fmt.Sprintf("%s answered from both %s and %s during one "+
					"scan — ARP spoofing behaves exactly like this. If this is "+
					"your gateway, treat the network as hostile.", e.IP, prev, e.MAC),
				Evidence:    map[string]any{"ip": e.IP, "mac_a": prev, "mac_b": e.MAC},
				Fingerprint: FingerprintOf("arp_conflict", e.IP),
			})
		}
		ip2mac[e.IP] = e.MAC
		macIPs[e.MAC] = append(macIPs[e.MAC], e.IP)
	}
	for mac, ips := range macIPs {
		if len(ips) >= 4 && !InCIDRs(ips[0], []string{"224.0.0.0/4", "255.255.255.255/32"}) {
			findings = append(findings, Finding{
				Check:    "arp_spoof",
				Severity: SevHigh,
				Title:    fmt.Sprintf("One MAC claims %d IPs", len(ips)),
				Detail: fmt.Sprintf("%s answers for %s — a machine claiming many "+
					"neighbours is either a router/VRRP setup or an ARP spoof "+
					"harvesting traffic.", mac, strings.Join(ips[:min(4, len(ips))], ", ")),
				Evidence:    map[string]any{"mac": mac, "ips": ips},
				Fingerprint: FingerprintOf("arp_spoof", mac),
			})
		}
	}

	// ---- DNS resolver change. A resolver must survive two consecutive scans
	// before alerting: scutil --dns output flaps with interface/service churn
	// (VPN connects, Wi-Fi handover), and requiring persistence kills the noise.
	resolvers := getResolvers()
	rVal, existed := store.BaselineKey("resolvers", resolvers)
	if existed && len(resolvers) > 0 {
		prev, _ := rVal.([]any)
		prevS := map[string]bool{}
		for _, v := range prev {
			prevS[FmtAny(v)] = true
		}
		pendingVal, _ := store.BaselineKey("dns_pending", map[string]any{})
		pending, _ := pendingVal.(map[string]any)
		if pending == nil {
			pending = map[string]any{}
		}
		newOnes := []string{}
		for _, r := range resolvers {
			if prevS[r] {
				delete(pending, r)
				continue
			}
			if first, seen := pending[r]; seen && now-AnyFloat(first) >= 10 {
				newOnes = append(newOnes, r)
			} else if !seen {
				pending[r] = now
			}
		}
		store.BaselineUpdate("dns_pending", pending)
		if len(newOnes) > 0 {
			// Full replacement (none of the previous resolvers remain) is the
			// hijack signature — VPN clients, MITM boxes, trojan resolvers all
			// take over the whole set. Partial churn (an old resolver still
			// present, e.g. IPv6 RA adding/removing a secondary entry) is
			// routine network life: learn it silently.
			if len(prevS) > 0 && !anyInSet(resolvers, prevS) {
				findings = append(findings, Finding{
					Check:    "dns_change",
					Severity: SevMedium,
					Title:    "DNS resolvers fully replaced",
					Detail: fmt.Sprintf("Now %s (was %s). A silent resolver swap "+
						"sends every name you look up through a third party — common "+
						"with VPNs and captive portals, and with MITM tooling.",
						strings.Join(resolvers, ", "), joinAny(prev)),
					Evidence: map[string]any{"new": newOnes, "previous": prev},
					Fingerprint: FingerprintOf("dns_change",
						strings.Join(newOnes, ",")),
				})
			}
			// adopt the current set either way so the diff doesn't re-fire
			store.BaselineUpdate("resolvers", resolvers)
		}
	}

	// ---- DNS rebinding probe: known domains must not resolve into private space
	probes := []string{"www.google.com", "www.microsoft.com", "www.apple.com"}
	for _, d := range probes {
		ips, err := net.LookupIP(d)
		if err != nil || len(ips) == 0 {
			continue
		}
		bad := []string{}
		for _, ip := range ips {
			class := IPClass(ip.String())
			if class == "private" || class == "cgnat" || class == "loopback" ||
				class == "linklocal" || class == "reserved" {
				bad = append(bad, ip.String()+" ("+class+")")
			}
		}
		if len(bad) > 0 {
			findings = append(findings, Finding{
				Check:    "dns_rebind",
				Severity: SevHigh,
				Title:    fmt.Sprintf("%s resolves into private address space", d),
				Detail: fmt.Sprintf("Resolver returned %s. Public sites never "+
					"sit in private ranges — this is DNS rebinding or a poisoned "+
					"resolver answer.", strings.Join(bad, ", ")),
				Evidence:    map[string]any{"domain": d, "answers": bad},
				Fingerprint: FingerprintOf("dns_rebind", d),
			})
		}
	}

	return findings
}

func anyInSet(cands []string, set map[string]bool) bool {
	for _, c := range cands {
		if set[c] {
			return true
		}
	}
	return false
}

func joinAny(v []any) string {
	out := []string{}
	for _, x := range v {
		out = append(out, FmtAny(x))
	}
	return strings.Join(out, ", ")
}

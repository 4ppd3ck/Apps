//go:build linux

package wtower

// Listening-port enumeration for wGrid endpoint relocation (see
// wgridport_darwin.go): /proc/net/tcp{,6} lists every LISTEN socket
// without external tools or connect attempts. Local address is hex
// "IP:PORT"; state 0A is LISTEN. Wildcard binds are included — they answer
// on 127.0.0.1 too.

import (
	"os"
	"strconv"
	"strings"
)

func listeningLoopbackPorts() []int {
	var ports []int
	seen := map[int]bool{}
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for i, line := range strings.Split(string(raw), "\n") {
			if i == 0 { // header
				continue
			}
			f := strings.Fields(line)
			if len(f) < 4 || f[3] != "0A" {
				continue
			}
			idx := strings.LastIndex(f[1], ":")
			if idx < 0 {
				continue
			}
			p, err := strconv.ParseInt(f[1][idx+1:], 16, 32)
			if err != nil || p <= 0 || seen[int(p)] {
				continue
			}
			seen[int(p)] = true
			ports = append(ports, int(p))
		}
	}
	return ports
}

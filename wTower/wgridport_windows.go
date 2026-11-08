//go:build windows

package wtower

// Listening-port enumeration for wGrid endpoint relocation (see
// wgridport_darwin.go): netstat's LISTENING lines, no connect attempts.
// The state word is not localized on Windows, so the line filter is safe;
// anything else here is best effort — an empty list just skips the scan
// stage of relocation.

import (
	"strconv"
	"strings"
	"time"
)

func listeningLoopbackPorts() []int {
	_, out, _ := Run([]string{"netstat", "-ano", "-p", "tcp"}, 10*time.Second)
	var ports []int
	seen := map[int]bool{}
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(strings.ToUpper(line), "LISTENING") {
			continue
		}
		f := strings.Fields(strings.TrimSpace(line))
		// Proto Local Foreign State PID
		if len(f) < 4 {
			continue
		}
		idx := strings.LastIndex(f[1], ":")
		if idx < 0 {
			continue
		}
		p, err := strconv.Atoi(f[1][idx+1:])
		if err != nil || p <= 0 || seen[p] {
			continue
		}
		seen[p] = true
		ports = append(ports, p)
	}
	return ports
}

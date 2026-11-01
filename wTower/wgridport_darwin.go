//go:build darwin

package wtower

// Listening-port enumeration for IPolice endpoint relocation: when the
// launcher is unreachable, every listening TCP port on the machine is a
// relocation candidate; the signature probe (see CountrySource.probeWGrid)
// tells IPolice apart from the other local servers. lsof — the same source
// the network collector uses — lists them without a single connect attempt.

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

func listeningLoopbackPorts() []int {
	_, out, _ := Run([]string{"/usr/sbin/lsof", "-a", "-iTCP", "-sTCP:LISTEN",
		"-n", "-P"}, 10*time.Second)
	return parseListenPorts(out)
}

// listenPortRe matches the local port of an lsof LISTEN line: the NAME
// column ends in "host:port (LISTEN)" — 127.0.0.1:9106, *:9106, [::1]:9106.
var listenPortRe = regexp.MustCompile(`:(\d+)\s+\(LISTEN\)\s*$`)

func parseListenPorts(out string) []int {
	var ports []int
	seen := map[int]bool{}
	for _, line := range strings.Split(out, "\n") {
		m := listenPortRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		p, err := strconv.Atoi(m[1])
		if err != nil || p <= 0 || seen[p] {
			continue
		}
		seen[p] = true
		ports = append(ports, p)
	}
	return ports
}

// Package monitor is a Go port of the AppScope Monitor daemon
// (python -m monitor): a cross-platform privacy (camera/mic/file) &
// network activity monitor with a local web dashboard.
//
// This file mirrors monitor/util.py: subprocess helpers, user lookup,
// port/service names, IP classification and reverse DNS.
package monitor

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Now returns the current unix epoch seconds (time.time()).
func Now() float64 {
	return float64(time.Now().UnixNano()) / 1e9
}

// Run executes a command and returns (returncode, stdout, stderr), mirroring
// util.run(): command not found -> (127, "", "cmd: not found"), timeout ->
// (124, "", "timeout"). Output is decoded with invalid bytes replaced
// (Python's errors="replace").
func Run(cmd []string, timeout time.Duration) (int, string, string) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return RunContext(ctx, cmd)
}

// RunContext is Run with a caller-supplied context.
func RunContext(ctx context.Context, cmd []string) (int, string, string) {
	if len(cmd) == 0 {
		return 127, "", "empty command"
	}
	c := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
	c.WaitDelay = 2 * time.Second
	var stdout, stderr bytes.Buffer
	c.Stdout = &stdout
	c.Stderr = &stderr
	err := c.Run()
	if ctx.Err() != nil {
		return 124, "", "timeout"
	}
	out := decodeReplace(stdout.Bytes())
	errOut := decodeReplace(stderr.Bytes())
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), out, errOut
		}
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, fs.ErrNotExist) {
			return 127, "", fmt.Sprintf("%s: not found", cmd[0])
		}
		if errors.Is(err, exec.ErrWaitDelay) {
			return 0, out, errOut
		}
		return 127, out, strings.TrimSpace(errOut + " " + err.Error())
	}
	return 0, out, errOut
}

// decodeReplace converts raw output to a string with invalid UTF-8 sequences
// replaced by U+FFFD (mirrors Python's errors="replace" text decoding).
func decodeReplace(b []byte) string {
	return strings.ToValidUTF8(string(b), "\uFFFD")
}

// PopenStream starts a long-running command with line-buffered stdout;
// the child's stderr goes to /dev/null (mirrors util.popen_stream with
// stderr=subprocess.DEVNULL). Call cmd.Wait() after consuming the reader.
func PopenStream(cmd []string) (*exec.Cmd, *bufio.Reader, error) {
	c := exec.Command(cmd[0], cmd[1:]...)
	c.Stderr = nil // child stderr -> /dev/null
	c.WaitDelay = time.Second
	stdout, err := c.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := c.Start(); err != nil {
		return nil, nil, err
	}
	return c, bufio.NewReaderSize(stdout, 1<<20), nil
}

// ---------------------------------------------------------------- users ----

// GetPassUser mirrors getpass.getuser(): environment first, then the OS user.
func GetPassUser() string {
	for _, k := range []string{"LOGNAME", "USER", "LNAME", "USERNAME"} {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return "?"
}

func currentUser() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return "?"
}

// ------------------------------------------------------------ services ----

var services = map[int]string{
	20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
	67: "dhcp", 68: "dhcp", 80: "http", 110: "pop3", 123: "ntp", 137: "netbios-ns",
	138: "netbios-dgm", 139: "netbios-ssn", 143: "imap", 161: "snmp", 389: "ldap",
	443: "https", 445: "smb", 465: "smtps", 514: "syslog", 515: "printer",
	548: "afp", 587: "smtp-submission", 631: "ipp", 636: "ldaps", 993: "imaps",
	995: "pop3s", 1080: "socks", 1194: "openvpn", 1433: "mssql", 1521: "oracle",
	1723: "pptp", 1900: "ssdp", 2049: "nfs", 2082: "cpanel", 2083: "cpanel-ssl",
	2181: "zookeeper", 2375: "docker", 2376: "docker-tls", 3000: "node-dev",
	3306: "mysql", 3389: "rdp", 5000: "upnp", 5060: "sip", 5061: "sips",
	5222: "xmpp", 5353: "mdns", 5432: "postgres", 5555: "adb", 5672: "amqp",
	5900: "vnc", 5984: "couchdb", 6379: "redis", 6443: "k8s-api", 6667: "irc",
	8000: "http-dev", 8080: "http-alt", 8443: "https-alt", 8888: "http-alt2",
	9000: "sonar/http", 9092: "kafka", 9200: "elasticsearch", 9418: "git",
	11211: "memcached", 27017: "mongodb", 50000: "db2",
}

var (
	servicesOnce  sync.Once
	servicesExtra map[int]string
)

// servicesFileFallback lazily parses the system services file (the same data
// source socket.getservbyport uses).
func servicesFileFallback() map[int]string {
	servicesOnce.Do(func() {
		servicesExtra = map[int]string{}
		path := "/etc/services"
		if runtime.GOOS == "windows" {
			sysRoot := os.Getenv("SystemRoot")
			if sysRoot == "" {
				sysRoot = `C:\Windows`
			}
			path = filepath.Join(sysRoot, "System32", "drivers", "etc", "services")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			portProto := strings.SplitN(fields[1], "/", 2)
			port, err := strconv.Atoi(portProto[0])
			if err != nil {
				continue
			}
			if _, exists := servicesExtra[port]; !exists {
				servicesExtra[port] = fields[0]
			}
		}
	})
	return servicesExtra
}

// ServiceName mirrors util.service_name(): built-in table first, then the
// system services database (socket.getservbyport), else "".
func ServiceName(port int) string {
	if port == 0 {
		return ""
	}
	if name, ok := services[port]; ok {
		return name
	}
	return servicesFileFallback()[port]
}

// ------------------------------------------------------------------ IPs ----

var classifyCache sync.Map // string -> string

// ClassifyIP mirrors util.classify_ip: 'loopback' | 'lan' | 'external' |
// 'multicast' | 'other'.
func ClassifyIP(ip string) string {
	if ip == "" || ip == "*" || ip == "0.0.0.0" || ip == "::" || ip == "[::]" {
		return "other"
	}
	if cached, ok := classifyCache.Load(ip); ok {
		return cached.(string)
	}
	res := classifyIPUncached(ip)
	classifyCache.Store(ip, res)
	return res
}

func classifyIPUncached(ip string) string {
	trimmed := strings.Trim(ip, "[]")
	if strings.HasPrefix(trimmed, "127.") || trimmed == "::1" {
		return "loopback"
	}
	if strings.HasPrefix(trimmed, "224.") || strings.HasPrefix(trimmed, "ff") ||
		strings.HasPrefix(trimmed, "239.") {
		return "multicast"
	}
	addr := net.ParseIP(trimmed)
	if addr == nil {
		return "other"
	}
	if addr.IsLoopback() {
		return "loopback"
	}
	if addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsPrivate() {
		return "lan"
	}
	return "external"
}

// RdnsCache is a non-blocking reverse DNS cache; lookups run in a small pool
// (mirrors util.RdnsCache).
type RdnsCache struct {
	mu      sync.Mutex
	cache   map[string]string // ip -> hostname ("" = failed/unknown)
	pending map[string]bool
	jobs    chan string
}

var rdns = newRdnsCache()

func newRdnsCache() *RdnsCache {
	c := &RdnsCache{
		cache:   map[string]string{},
		pending: map[string]bool{},
		jobs:    make(chan string, 256),
	}
	for i := 0; i < 6; i++ {
		go c.worker()
	}
	return c
}

func (c *RdnsCache) worker() {
	for ip := range c.jobs {
		host := ""
		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		names, err := net.DefaultResolver.LookupAddr(ctx, ip)
		cancel()
		if err == nil && len(names) > 0 {
			host = strings.TrimSuffix(names[0], ".")
		}
		c.mu.Lock()
		c.cache[ip] = host
		delete(c.pending, ip)
		c.mu.Unlock()
	}
}

// Get returns the hostname or "" (starts an async lookup on first sight).
func (c *RdnsCache) Get(ip string) string {
	if ip == "" || ip == "*" {
		return ""
	}
	c.mu.Lock()
	host, ok := c.cache[ip]
	if !ok && !c.pending[ip] && ClassifyIP(ip) == "external" {
		c.pending[ip] = true
		select {
		case c.jobs <- ip:
		default:
			delete(c.pending, ip)
		}
	}
	c.mu.Unlock()
	if !ok {
		return ""
	}
	return host
}

// ------------------------------------------------------------- windows ----

// FiletimeToEpoch converts a Windows FILETIME (100ns since 1601) to unix
// epoch seconds; ok=false for invalid input (mirrors util.filetime_to_epoch).
func FiletimeToEpoch(ft uint64) (float64, bool) {
	if ft == 0 {
		return 0, false
	}
	return float64(ft)/1e7 - 11644473600, true
}

// Which mirrors shutil.which.
func Which(name string) string {
	path, err := exec.LookPath(name)
	if err != nil {
		return ""
	}
	return path
}

// ------------------------------------------------------------- helpers ----

// ToInt converts a JSON-decoded value to int (Python int(x) semantics for
// numbers and numeric strings); ok=false when not convertible.
func ToInt(v any) (int, bool) {
	switch n := v.(type) {
	case nil:
		return 0, false
	case float64:
		return int(n), true
	case int:
		return n, true
	case int64:
		return int(n), true
	case uint64:
		return int(n), true
	case bool:
		if n {
			return 1, true
		}
		return 0, true
	case string:
		if n == "" {
			return 0, false
		}
		if f, err := strconv.ParseFloat(strings.TrimSpace(n), 64); err == nil {
			return int(f), true
		}
		return 0, false
	default:
		return 0, false
	}
}

// IntOr converts any to int with a fallback (mirrors the _int helpers).
func IntOr(v any, def int) int {
	if n, ok := ToInt(v); ok {
		return n
	}
	return def
}

// ToFloat converts a JSON-decoded value to float64.
func ToFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case nil:
		return 0, false
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case string:
		if f, err := strconv.ParseFloat(strings.TrimSpace(n), 64); err == nil {
			return f, true
		}
		return 0, false
	default:
		return 0, false
	}
}

// StrOf renders a JSON-decoded scalar the way Python's str() would for the
// values this program produces (integral floats lose the ".0").
func StrOf(v any) string {
	switch n := v.(type) {
	case nil:
		return ""
	case string:
		return n
	case float64:
		if n == float64(int64(n)) {
			return strconv.FormatInt(int64(n), 10)
		}
		return strconv.FormatFloat(n, 'g', -1, 64)
	case int:
		return strconv.Itoa(n)
	case int64:
		return strconv.FormatInt(n, 10)
	case bool:
		if n {
			return "True"
		}
		return "False"
	default:
		return fmt.Sprintf("%v", n)
	}
}

// Truthy mirrors Python bool(x) for JSON-decoded values.
func Truthy(v any) bool {
	switch n := v.(type) {
	case nil:
		return false
	case bool:
		return n
	case float64:
		return n != 0
	case int:
		return n != 0
	case int64:
		return n != 0
	case string:
		return n != ""
	case []any:
		return len(n) > 0
	case map[string]any:
		return len(n) > 0
	default:
		return true
	}
}

// FmtTime mirrors base.Collector.fmt_time: local "HH:MM:SS".
func FmtTime(ts float64) string {
	t := time.Now()
	if ts > 0 {
		t = time.Unix(int64(ts), 0)
	}
	return t.Format("15:04:05")
}

// FormatBytes mirrors android._fmt: B / KB / MB / GB / TB with one decimal.
func FormatBytes(n float64) string {
	for _, unit := range []string{"B", "KB", "MB", "GB"} {
		if n < 1024 {
			return fmt.Sprintf("%.1f%s", n, unit)
		}
		n /= 1024
	}
	return fmt.Sprintf("%.1fTB", n)
}

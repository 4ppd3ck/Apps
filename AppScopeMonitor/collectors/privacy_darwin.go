//go:build darwin

// macOS privacy collector.
//
// Sources:
//   - `log stream` on TCC subsystem -- who asks for / gets access to camera,
//     microphone, screen capture, location, contacts, photos, keyboard-listen
//     and related protected services (attributed to the responsible app).
//   - TCC.db (best-effort) -- inventory of which apps are granted/denied
//     permission for those services; changes emitted as events.
//
// Mirrors collectors/privacy_macos.py.
package collectors

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
	"monitor"
)

// SystemTCCDB / UserTCCDB paths.
const (
	SystemTCCDB = "/Library/Application Support/com.apple.TCC/TCC.db"
	UserTCCDB   = "~/Library/Application Support/com.apple.TCC/TCC.db"
)

// tccServices maps kTCCService -> short name used in event kinds.
var tccServices = []struct{ key, short string }{
	{"kTCCServiceCamera", "camera"},
	{"kTCCServiceMicrophone", "microphone"},
	{"kTCCServiceScreenCapture", "screen_capture"},
	{"kTCCServiceLocation", "location"},
	{"kTCCServiceAddressBook", "contacts"},
	{"kTCCServicePhotos", "photos"},
	{"kTCCServiceListenEvent", "keyboard_listen"},
	{"kTCCServicePostEvent", "input_injection"},
	{"kTCCServiceAppleEvents", "apple_events"},
	{"kTCCServiceReminders", "reminders"},
	{"kTCCServiceCalendar", "calendar"},
}

var (
	reTCCAny      = regexp.MustCompile(`kTCCService(\w+)`)
	reTargetToken = regexp.MustCompile(`target_token=\{pid:(\d+), auid:(\d+)`)
	reTimestamp   = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})`)
	reIdentifier  = regexp.MustCompile(`identifier=([\w.\-+]+), pid=(\d+), auid=(\d+)`)
	reSyslogProc  = regexp.MustCompile(`\s(\S+?)\[(\d+):\d+\]`)
)

var tccPredicate = func() string {
	var terms []string
	for _, s := range tccServices {
		terms = append(terms, fmt.Sprintf("eventMessage CONTAINS[c] %q", s.key))
	}
	return `subsystem == "com.apple.TCC" AND (` + strings.Join(terms, " OR ") + `)`
}()

// PrivacyMacOS tracks camera/microphone access via TCC.
type PrivacyMacOS struct {
	*BaseCollector

	fwdMu sync.Mutex
	fwd   *forwardState // (service_what, (pid, auid)) inside a FORWARD block
}

type forwardState struct {
	what   string
	target *[2]int
}

// NewPrivacyMacOS creates the collector.
func NewPrivacyMacOS(ctx *monitor.Ctx) *PrivacyMacOS {
	b := NewBase(ctx, "privacy-macos",
		"Camera / microphone access via TCC (unified log + TCC.db)", "privacy")
	c := &PrivacyMacOS{BaseCollector: b}
	b.setRun(c.run)
	return c
}

// newPrivacyCollector is the registry hook for the "privacy" category on darwin.
func newPrivacyCollector(ctx *monitor.Ctx) monitor.Collector {
	return NewPrivacyMacOS(ctx)
}

// Available: always available on darwin.
func (c *PrivacyMacOS) Available() (bool, string) { return true, "" }

func (c *PrivacyMacOS) run() {
	go c.tccDBLoop()
	c.logStream()
}

// -- live access requests -------------------------------------------------

func (c *PrivacyMacOS) logStream() {
	proc, reader, err := monitor.PopenStream([]string{"log", "stream",
		"--style", "syslog", "--predicate", tccPredicate})
	if err != nil {
		c.SetStatus("degraded", "cannot start log stream")
		return
	}
	c.registerProc(proc)
	c.SetStatus("active", "streaming TCC access events")
	for {
		line, readErr := reader.ReadString('\n')
		line = strings.TrimRight(line, "\r\n")
		if line != "" {
			fwd := c.getFwd()
			if !strings.Contains(line, "kTCCService") && fwd == nil &&
				!(strings.Contains(line, "FORWARD:") && strings.HasSuffix(line, "{")) {
				// skip noise
			} else {
				c.parseLine(line)
			}
		}
		if readErr != nil || c.Stopped() {
			break
		}
	}
	_ = proc.Wait() // reap the stream child (log dies on stop/shutdown)
}

func (c *PrivacyMacOS) getFwd() *forwardState {
	c.fwdMu.Lock()
	defer c.fwdMu.Unlock()
	return c.fwd
}

func (c *PrivacyMacOS) setFwd(f *forwardState) {
	c.fwdMu.Lock()
	c.fwd = f
	c.fwdMu.Unlock()
}

func (c *PrivacyMacOS) parseLine(line string) {
	fwd := c.getFwd()
	if strings.TrimSpace(line) == "}" && fwd != nil {
		if fwd.target != nil {
			app := psName(fwd.target[0])
			what := fwd.what
			if what == "" {
				what = "device"
			}
			c.emitAccess(what, app, fwd.target[0],
				monitor.UsernameForUID(fwd.target[1]),
				what+" access request (TCC)", 0)
		}
		c.setFwd(nil)
		return
	}
	if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
		// continuation line of a multi-line FORWARD block
		if fwd != nil {
			if svc := findTCCService(line); svc != "" {
				fwd.what = svc
			}
			if tt := reTargetToken.FindStringSubmatch(line); tt != nil {
				pid, _ := strconv.Atoi(tt[1])
				auid, _ := strconv.Atoi(tt[2])
				fwd.target = &[2]int{pid, auid}
			}
			c.setFwd(fwd)
		}
		return
	}

	c.setFwd(nil)
	if strings.Contains(line, "FORWARD:") && strings.HasSuffix(line, "{") {
		c.setFwd(&forwardState{})
		return
	}
	what := findTCCService(line)
	if what == "" {
		return
	}

	// timestamp from the syslog prefix
	ts := monitor.Now()
	if m := reTimestamp.FindStringSubmatch(line); m != nil {
		if t, err := time.ParseInLocation("2006-01-02 15:04:05", m[1], time.Local); err == nil {
			ts = float64(t.Unix())
		}
	}

	// best attribution: responsible/accessing TCCDProcess block
	if m := reIdentifier.FindStringSubmatch(line); m != nil {
		pid, _ := strconv.Atoi(m[2])
		auid, _ := strconv.Atoi(m[3])
		c.emitAccess(what, m[1], pid, monitor.UsernameForUID(auid),
			actionLabel(line), ts)
		return
	}
	// AUTHREQ_CTX preflight probes carry no client info -> skip the noise
	if strings.Contains(line, "AUTHREQ_CTX") && strings.Contains(line, "client_dict=(null)") {
		return
	}

	// fallback: emitting process from the syslog prefix
	if mp := reSyslogProc.FindStringSubmatch(line); mp != nil {
		pid, _ := strconv.Atoi(mp[2])
		c.emitAccess(what, mp[1], pid, "", actionLabel(line), ts)
	}
}

// findTCCService returns the short name of any known kTCCService in line.
func findTCCService(line string) string {
	for _, s := range tccServices {
		if strings.Contains(line, s.key) {
			return s.short
		}
	}
	if m := reTCCAny.FindStringSubmatch(line); m != nil {
		return strings.ToLower(m[1])
	}
	return ""
}

func (c *PrivacyMacOS) emitAccess(what string, app any, pid int, user, detail string, ts float64) {
	if detail == "" {
		detail = what + " access (TCC)"
	}
	var userVal any
	if user != "" {
		userVal = user
	}
	ev := &monitor.Event{
		Category: "privacy",
		Kind:     what + "_access",
		App:      app,
		Pid:      pid,
		User:     userVal,
		Detail:   detail,
	}
	if ts > 0 {
		ev.Ts = ts
	}
	c.Emit(ev)
}

// psName resolves a pid to its short process name.
func psName(pid int) string {
	_, out, _ := monitor.Run([]string{"ps", "-p", strconv.Itoa(pid), "-o", "ucomm="},
		3*time.Second)
	out = strings.TrimSpace(out)
	if out == "" {
		return ""
	}
	return out
}

func actionLabel(line string) string {
	if strings.Contains(line, "Prompting policy") {
		return "access attempt (TCC entitlement check)"
	}
	if strings.Contains(line, "AUTHRESULTS") || strings.Contains(strings.ToLower(line), "auth") {
		return "access result (TCC)"
	}
	if strings.Contains(line, "FORWARD") {
		return "access request (TCC)"
	}
	return "access request/grant (TCC)"
}

// -- permission inventory ---------------------------------------------------

func (c *PrivacyMacOS) tccDBLoop() {
	seen := map[string]any{}
	dbs := []struct {
		path  string
		label string
	}{
		{SystemTCCDB, "system"},
		{expandTilde(UserTCCDB), "user"},
	}
	for !c.Stopped() {
		for _, db := range dbs {
			rows, err := readTCC(db.path)
			if err != nil {
				continue
			}
			for _, row := range rows {
				key := db.path + "\x00" + row.service + "\x00" + row.client
				if !seenHas(seen, key, row.auth) {
					var what string
					for _, s := range tccServices {
						if s.key == row.service {
							what = s.short
							break
						}
					}
					if what == "" {
						continue
					}
					state := authState(row.auth)
					c.Emit(&monitor.Event{
						Category: "privacy",
						Kind:     "permission",
						App:      row.client,
						Detail: fmt.Sprintf("%s permission %s [%s TCC.db]",
							what, state, db.label),
					})
				}
				seen[key] = row.auth
			}
		}
		c.Sleep(60)
	}
}

func seenHas(seen map[string]any, key string, auth any) bool {
	v, ok := seen[key]
	if !ok {
		return false
	}
	return fmt.Sprintf("%v", v) == fmt.Sprintf("%v", auth)
}

func authState(auth any) string {
	if n, ok := auth.(int64); ok {
		switch n {
		case 2:
			return "allowed"
		case 0:
			return "denied"
		default:
			return fmt.Sprintf("auth=%d", n)
		}
	}
	return fmt.Sprintf("auth=%v", auth)
}

func expandTilde(path string) string {
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

type tccRow struct {
	service, client string
	auth            any
}

func readTCC(path string) ([]tccRow, error) {
	uri := "file:" + url.PathEscape(path) + "?mode=ro"
	db, err := sql.Open("sqlite", uri)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	var placeholders []string
	for range tccServices {
		placeholders = append(placeholders, "?")
	}
	args := make([]any, 0, len(tccServices))
	for _, s := range tccServices {
		args = append(args, s.key)
	}
	rows, err := db.Query(
		"SELECT service, client, auth_value, last_modified FROM access"+
			" WHERE service IN ("+strings.Join(placeholders, ",")+")",
		args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []tccRow
	for rows.Next() {
		var r tccRow
		var modified sql.NullFloat64
		var auth sql.NullInt64
		if err := rows.Scan(&r.service, &r.client, &auth, &modified); err != nil {
			return nil, err
		}
		if auth.Valid {
			r.auth = auth.Int64
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

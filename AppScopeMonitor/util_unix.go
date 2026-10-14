//go:build !windows

// Unix-only user helpers (mirrors util.username_for_uid / util.proc_user).
package monitor

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// intCache is a tiny memo (approximates functools.lru_cache).
type intCache struct {
	mu sync.Map
}

func (c *intCache) load(k int) (string, bool) {
	if v, ok := c.mu.Load(k); ok {
		return v.(string), true
	}
	return "", false
}

func (c *intCache) store(k int, v string) { c.mu.Store(k, v) }

var uidNameCache intCache // lru_cache(maxsize=1024) approximation

// UsernameForUID mirrors util.username_for_uid: pwd name or str(uid).
func UsernameForUID(uid int) string {
	if cached, ok := uidNameCache.load(uid); ok {
		return cached
	}
	name := strconv.Itoa(uid)
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil && u.Username != "" {
		name = u.Username
	}
	uidNameCache.store(uid, name)
	return name
}

var procUserCache intCache

// ProcUser is the best-effort username owning a pid (macOS/Linux).
func ProcUser(pid int) string {
	if cached, ok := procUserCache.load(pid); ok {
		return cached
	}
	user := ""
	rc, out, _ := Run([]string{"ps", "-o", "user=", "-p", strconv.Itoa(pid)},
		3*time.Second)
	if rc == 0 {
		if fields := strings.Fields(out); len(fields) > 0 {
			user = fields[len(fields)-1]
		}
	}
	if user == "" {
		if st, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); err == nil {
			if stat, ok := st.Sys().(*syscall.Stat_t); ok {
				user = UsernameForUID(int(stat.Uid))
			}
		}
	}
	procUserCache.store(pid, user)
	return user
}

// Shared line-oriented reader and string helpers for collectors.
package collectors

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"

	"monitor"
)

// newLineReader wraps r with a buffered reader sized for long snapshot lines
// (mirrors Python's line-buffered text pipes with errors="replace").
func newLineReader(r io.Reader) *bufio.Reader {
	return bufio.NewReaderSize(r, 1<<20)
}

// startsWithAny mirrors str.startswith(tuple).
func startsWithAny(s string, prefixes []string) bool {
	if len(prefixes) == 0 {
		return false // Python: "".startswith(()) is False
	}
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// isAllDigits mirrors str.isdigit (ASCII digits only).
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

// pyStr renders a value in an f-string the way Python would (None -> "None").
func pyStr(v any) string {
	if v == nil {
		return "None"
	}
	return monitor.StrOf(v)
}

// pyJoinAddr renders f"{ip}:{port}" with Python's str(None) -> "None".
func pyJoinAddr(ip, port any) string {
	return monitor.StrOf(ip) + ":" + pyStr(port)
}

// rpartition mirrors Python str.rpartition.
func rpartition(s, sep string) (string, string) {
	if idx := strings.LastIndex(s, sep); idx >= 0 {
		return s[:idx], s[idx+len(sep):]
	}
	return "", s
}

// intOrNil mirrors the _int() helpers: number or numeric string -> int,
// else nil.
func intOrNil(v any) any {
	if n, ok := monitor.ToInt(v); ok {
		return n
	}
	return nil
}

// intOrNilSS parses a port token, mirroring _int(): int or None.
func intOrNilSS(v string) any {
	if n, err := strconv.Atoi(v); err == nil {
		return n
	}
	return nil
}

func maxI64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// panicString renders a recovered panic like Python's
// f"{type(exc).__name__}: {exc}".
func panicString(r any) string {
	switch v := r.(type) {
	case error:
		return v.Error()
	case string:
		return v
	default:
		return fmt.Sprintf("%v", v)
	}
}

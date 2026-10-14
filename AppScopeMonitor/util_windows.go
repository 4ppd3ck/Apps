//go:build windows

// Windows stub for the unix user helpers: there is no uid -> username
// mapping in the win32 build (Python has the same gap: `import pwd` fails).
package monitor

import "strconv"

// UsernameForUID returns the uid as its string form.
func UsernameForUID(uid int) string { return strconv.Itoa(uid) }

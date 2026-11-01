//go:build linux

// Disk-space helper for Linux: block size via f_frsize (matches Python's
// os.statvfs usage).
package collectors

import "syscall"

func statVolume(path string) (total, avail uint64, ok bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, false
	}
	return st.Blocks * uint64(st.Frsize), st.Bavail * uint64(st.Frsize), true
}

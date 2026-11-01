//go:build openbsd

// Disk-space helper for OpenBSD: statfs fields carry an F_ prefix there.
package collectors

import "syscall"

func statVolume(path string) (total, avail uint64, ok bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, false
	}
	return st.F_blocks * uint64(st.F_bsize),
		uint64(st.F_bavail) * uint64(st.F_bsize), true
}

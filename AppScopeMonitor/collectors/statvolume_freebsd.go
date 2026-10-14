//go:build freebsd

// Disk-space helper for FreeBSD: statfs with f_bsize semantics.
package collectors

import "syscall"

func statVolume(path string) (total, avail uint64, ok bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, false
	}
	return st.Blocks * uint64(st.Bsize),
		uint64(st.Bavail) * uint64(st.Bsize), true
}

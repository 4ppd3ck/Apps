//go:build netbsd

// Disk-space helper for NetBSD: its syscall package exposes no statfs/statvfs
// wrapper, so this uses golang.org/x/sys/unix.Statvfs (f_frsize semantics).
package collectors

import "golang.org/x/sys/unix"

func statVolume(path string) (total, avail uint64, ok bool) {
	var st unix.Statvfs_t
	if err := unix.Statvfs(path, &st); err != nil {
		return 0, 0, false
	}
	return st.Blocks * st.Bsize, st.Bavail * st.Bsize, true
}

//go:build darwin

// Disk-space helper for macOS: block size via f_bsize (darwin statfs has no
// f_frsize).
package collectors

import "syscall"

func statVolume(path string) (total, avail uint64, ok bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, false
	}
	return st.Blocks * uint64(st.Bsize), st.Bavail * uint64(st.Bsize), true
}

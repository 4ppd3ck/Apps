//go:build !windows

package main

import "syscall"

// diskFree returns bytes available to this user on the volume holding path.
func diskFree(path string) uint64 {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0
	}
	// Bavail is signed on some platforms (FreeBSD) and unsigned on others
	// (Linux); convert both sides explicitly. A negative value (impossible
	// in practice) clamps to a huge number via uint64 — guard it.
	free := uint64(0)
	if st.Bavail > 0 {
		free = uint64(st.Bavail) * uint64(st.Bsize)
	}
	return free
}

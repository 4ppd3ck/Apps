//go:build !windows

package main

import "syscall"

// diskFree returns bytes available to this user on the volume holding path.
func diskFree(path string) uint64 {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0
	}
	return st.Bavail * uint64(st.Bsize)
}

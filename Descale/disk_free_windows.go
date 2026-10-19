//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

var (
	kernel32                = syscall.NewLazyDLL("kernel32.dll")
	procGetDiskFreeSpaceExW = kernel32.NewProc("GetDiskFreeSpaceExW")
)

// diskFree returns bytes available to THIS user on the volume holding path
// (GetDiskFreeSpaceExW's *avail form, the quota-aware one — the unix build
// answers the same question from statfs Bavail). v0.3 returned a stub 0.
func diskFree(path string) uint64 {
	// LazyProc.Call panics when the DLL/proc cannot be resolved; probe first
	if err := procGetDiskFreeSpaceExW.Find(); err != nil {
		return 0
	}
	ptr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0
	}
	var avail, total, free uint64
	r1, _, _ := procGetDiskFreeSpaceExW.Call(
		uintptr(unsafe.Pointer(ptr)),
		uintptr(unsafe.Pointer(&avail)),
		uintptr(unsafe.Pointer(&total)),
		uintptr(unsafe.Pointer(&free)),
	)
	if r1 == 0 {
		return 0
	}
	return avail
}

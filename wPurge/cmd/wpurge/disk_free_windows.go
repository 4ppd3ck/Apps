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

// diskSpaceQuery is the one GetDiskFreeSpaceExW call both helpers share;
// 0s on any failure.
func diskSpaceQuery(path string) (avail, total uint64) {
	// LazyProc.Call panics when the DLL/proc cannot be resolved; probe first
	if err := procGetDiskFreeSpaceExW.Find(); err != nil {
		return 0, 0
	}
	ptr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, 0
	}
	var free uint64
	r1, _, _ := procGetDiskFreeSpaceExW.Call(
		uintptr(unsafe.Pointer(ptr)),
		uintptr(unsafe.Pointer(&avail)),
		uintptr(unsafe.Pointer(&total)),
		uintptr(unsafe.Pointer(&free)),
	)
	if r1 == 0 {
		return 0, 0
	}
	return avail, total
}

// diskFree returns bytes available to THIS user on the volume holding path
// (GetDiskFreeSpaceExW's *avail form, the quota-aware one — the unix build
// answers the same question from statfs Bavail). v0.3 returned a stub 0.
func diskFree(path string) uint64 {
	avail, _ := diskSpaceQuery(path)
	return avail
}

// diskTotal returns the volume's total size (GetDiskFreeSpaceExW's total form).
func diskTotal(path string) uint64 {
	_, total := diskSpaceQuery(path)
	return total
}

//go:build windows

// Disk-space helper for Windows (GetDiskFreeSpaceExW). The POSIX vitals
// code path never runs on Windows, but it is compiled there, so statVolume
// must exist on every platform.
package collectors

import (
	"syscall"
	"unsafe"
)

var (
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	procGetDiskFreeSpaceEx = kernel32.NewProc("GetDiskFreeSpaceExW")
)

func statVolume(path string) (total, avail uint64, ok bool) {
	ptr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, 0, false
	}
	var freeBytes, totalBytes, availBytes uint64
	r1, _, _ := procGetDiskFreeSpaceEx.Call(uintptr(unsafe.Pointer(ptr)),
		uintptr(unsafe.Pointer(&freeBytes)),
		uintptr(unsafe.Pointer(&totalBytes)),
		uintptr(unsafe.Pointer(&availBytes)))
	if r1 == 0 {
		return 0, 0, false
	}
	return totalBytes, availBytes, true
}

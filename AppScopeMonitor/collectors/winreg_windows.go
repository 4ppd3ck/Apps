//go:build windows

// Minimal Windows-registry access via advapi32 (stdlib syscall only), used by
// the privacy collector to read the CapabilityAccessManager ConsentStore.
// Equivalent to Python's winreg usage in collectors/privacy_windows.py.
package collectors

import (
	"encoding/binary"
	"syscall"
	"unsafe"
)

// Registry hive roots.
const (
	regHKCU = syscall.Handle(0x80000001)
	regHKLM = syscall.Handle(0x80000002)
	regHKU  = syscall.Handle(0x80000003)
)

const regKeyRead = 0x20019 // KEY_READ

const (
	regSZ       = 1
	regExpandSZ = 2
	regBinary   = 3
	regDWORD    = 4
	regQWORD    = 11
)

var (
	advapi32             = syscall.NewLazyDLL("advapi32.dll")
	procRegOpenKeyExW    = advapi32.NewProc("RegOpenKeyExW")
	procRegCloseKeyW     = advapi32.NewProc("RegCloseKey")
	procRegEnumKeyExW    = advapi32.NewProc("RegEnumKeyExW")
	procRegQueryInfoKeyW = advapi32.NewProc("RegQueryInfoKeyW")
	procRegQueryValueExW = advapi32.NewProc("RegQueryValueExW")
)

// regOpenKey opens a registry key (winreg.OpenKey with KEY_READ).
func regOpenKey(root syscall.Handle, path string) (syscall.Handle, bool) {
	ptr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, false
	}
	var h syscall.Handle
	r1, _, _ := procRegOpenKeyExW.Call(uintptr(root),
		uintptr(unsafe.Pointer(ptr)), 0, regKeyRead, uintptr(unsafe.Pointer(&h)))
	if r1 != 0 {
		return 0, false
	}
	return h, true
}

// regCloseKey closes a key.
func regCloseKey(h syscall.Handle) {
	if h != 0 {
		procRegCloseKeyW.Call(uintptr(h))
	}
}

// regEnumKeyName returns the i-th subkey name (winreg.EnumKey).
func regEnumKeyName(h syscall.Handle, index int) (string, bool) {
	var name [257]uint16
	nameLen := uint32(len(name))
	r1, _, _ := procRegEnumKeyExW.Call(uintptr(h), uintptr(index),
		uintptr(unsafe.Pointer(&name[0])), uintptr(unsafe.Pointer(&nameLen)),
		0, 0, 0, 0)
	if r1 != 0 {
		return "", false
	}
	return syscall.UTF16ToString(name[:nameLen]), true
}

// regSubKeyCount returns the number of subkeys (winreg.QueryInfoKey[0]).
func regSubKeyCount(h syscall.Handle) (int, bool) {
	var subKeys uint32
	r1, _, _ := procRegQueryInfoKeyW.Call(uintptr(h), 0, 0, 0,
		uintptr(unsafe.Pointer(&subKeys)), 0, 0, 0, 0, 0, 0, 0)
	if r1 != 0 {
		return 0, false
	}
	return int(subKeys), true
}

// regQueryValue reads a value (winreg.QueryValueEx): string for REG_SZ,
// uint64 for REG_QWORD/8-byte binary, []byte for other binary data.
func regQueryValue(h syscall.Handle, name string) (any, bool) {
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return nil, false
	}
	var typ uint32
	var buf [4096]byte
	size := uint32(len(buf))
	r1, _, _ := procRegQueryValueExW.Call(uintptr(h),
		uintptr(unsafe.Pointer(namePtr)), 0, uintptr(unsafe.Pointer(&typ)),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if r1 != 0 {
		return nil, false
	}
	data := buf[:size]
	switch typ {
	case regSZ, regExpandSZ:
		return utf16ToString(data), true
	case regDWORD:
		if len(data) >= 4 {
			return uint64(binary.LittleEndian.Uint32(data)), true
		}
		return nil, false
	case regQWORD:
		if len(data) >= 8 {
			return leUint64(data), true
		}
		return nil, false
	default: // REG_BINARY and friends
		out := make([]byte, len(data))
		copy(out, data)
		return out, true
	}
}

func leUint64(b []byte) uint64 { return binary.LittleEndian.Uint64(b) }

func utf16ToString(b []byte) string {
	u := make([]uint16, 0, len(b)/2+1)
	for i := 0; i+1 < len(b); i += 2 {
		u = append(u, uint16(b[i])|uint16(b[i+1])<<8)
	}
	return syscall.UTF16ToString(u)
}

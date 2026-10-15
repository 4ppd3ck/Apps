//go:build windows

package main

// diskFree is not implemented on Windows in v0.3; the field is informational.
func diskFree(path string) uint64 { return 0 }

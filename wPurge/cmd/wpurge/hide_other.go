//go:build !windows

package main

import "os/exec"

// hideWindow is a Windows-only concern; POSIX child processes do not
// allocate console windows.
func hideWindow(_ *exec.Cmd) {}

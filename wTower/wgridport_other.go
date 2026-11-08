//go:build !darwin && !linux && !windows

package wtower

// No listening-port enumeration on this platform: the scan stage of wGrid
// endpoint relocation is skipped and discovery relies on the launcher
// registry (see CountrySource.relocate).

func listeningLoopbackPorts() []int { return nil }

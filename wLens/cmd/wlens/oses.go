package main

import (
	"regexp"
	"strings"
)

// Maps a release-asset filename to the OS it targets.
// Order matters: e.g. "darwin" contains "win", so macOS is tested before Windows.
var (
	skipRE    = regexp.MustCompile(`(?i)\.(sha256|sha512|sha1|md5|sig|asc|pem|sbom|json|txt|ya?ml|blockmap|zsync|ds_store)$`)
	androidRE = regexp.MustCompile(`(?i)\.apk$|[-._]android[-._=\d]`)
	iosRE     = regexp.MustCompile(`(?i)\.ipa$`)
	macosRE   = regexp.MustCompile(`(?i)\.(dmg|pkg)$|darwin|macos|[-._]mac[-._=\d]|[-._]osx[-._=\d]|\.app\.zip$|universal\.zip$`)
	windowsRE = regexp.MustCompile(`(?i)\.(exe|msi|msix|appx|appxbundle)$|[-._]win(dows|32|64)?[-._=\d]`)
	linuxRE   = regexp.MustCompile(`(?i)\.(appimage|deb|rpm|snap|flatpak)$|[-._]linux[-._=\d]|[-._]musl|[-._]manylinux|[-._]gnu[0-9]|aarch64[-._]linux|armv[67][-._]linux`)
)

func detectOS(assetName string) string {
	n := strings.ToLower(assetName)
	switch {
	case skipRE.MatchString(n):
		return ""
	case androidRE.MatchString(n):
		return "android"
	case iosRE.MatchString(n):
		return "ios"
	case macosRE.MatchString(n):
		return "macos"
	case windowsRE.MatchString(n):
		return "windows"
	case linuxRE.MatchString(n):
		return "linux"
	}
	return ""
}

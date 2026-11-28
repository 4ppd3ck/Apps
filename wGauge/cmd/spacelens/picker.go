package main

// picker — native "choose folder" dialog so scan roots (folders or whole
// volumes) can be picked in the OS file manager instead of being typed.
// Multi-selection where the OS supports it (macOS, Linux/zenity); Windows'
// FolderBrowserDialog is single-select — pick repeatedly to add more.

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

func (s *server) handlePick(w http.ResponseWriter, r *http.Request) {
	paths, err := pickFolders()
	if err != nil {
		s.fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.json(w, map[string]any{"ok": true, "paths": paths})
}

func pickFolders() ([]string, error) {
	switch runtime.GOOS {
	case "darwin":
		return pickDarwin()
	case "windows":
		return pickWindows()
	default:
		return pickLinux()
	}
}

func pickDarwin() ([]string, error) {
	script := `set picks to choose folder with multiple selections allowed
set out to ""
repeat with f in picks
	set out to out & (POSIX path of f) & linefeed
end repeat
return out`
	out, err := exec.Command("osascript", "-e", script).Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && strings.Contains(string(ee.Stderr), "User canceled") {
			return nil, nil // dialog dismissed — not an error
		}
		return nil, fmt.Errorf("folder picker failed: %v", err)
	}
	return splitPaths(out), nil
}

func pickWindows() ([]string, error) {
	script := `Add-Type -AssemblyName System.Windows.Forms | Out-Null
$f = New-Object System.Windows.Forms.FolderBrowserDialog
$f.Description = 'Choose a folder or drive to scan'
if ($f.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { Write-Output $f.SelectedPath }`
	out, err := exec.Command("powershell", "-NoProfile", "-STA", "-Command", script).Output()
	if err != nil {
		return nil, fmt.Errorf("folder picker failed: %v", err)
	}
	return splitPaths(out), nil
}

func pickLinux() ([]string, error) {
	if z, err := exec.LookPath("zenity"); err == nil {
		return runPicker(exec.Command(z, "--file-selection", "--directory", "--multiple",
			"--separator=\n", "--title", "Choose folders or volumes to scan"))
	}
	if k, err := exec.LookPath("kdialog"); err == nil {
		start := "/"
		if home, e := os.UserHomeDir(); e == nil && home != "" {
			start = home
		}
		return runPicker(exec.Command(k, "--getexistingdirectory", start,
			"--title", "Choose a folder to scan"))
	}
	return nil, errors.New("no folder picker found — install zenity or kdialog to choose folders")
}

// runPicker runs a dialog and splits its output; no output means it was
// dismissed rather than failed.
func runPicker(cmd *exec.Cmd) ([]string, error) {
	out, err := cmd.Output()
	if err != nil {
		if len(out) == 0 {
			return nil, nil // dialog canceled
		}
		return nil, fmt.Errorf("folder picker failed: %v", err)
	}
	return splitPaths(out), nil
}

func splitPaths(out []byte) []string {
	var paths []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			paths = append(paths, line)
		}
	}
	return paths
}

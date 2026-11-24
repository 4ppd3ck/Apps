package main

/* Native folder picker for the "Folders to scan" settings section.
 *
 * A localhost web page cannot get a real path from the browser's file
 * picker (the File System Access API returns a handle, deliberately
 * without a path), so the SERVER opens the OS dialog instead — the same
 * shell-out pattern /api/reveal uses (open -R / explorer / xdg-open):
 *
 *   - macOS:    osascript "choose folder" (StandardAdditions, no other
 *               app targeted, so no automation-permission prompt)
 *   - Windows:  PowerShell FolderBrowserDialog under -STA (the dialog
 *               needs a single-threaded apartment)
 *   - Linux:    zenity --file-selection --directory, else kdialog
 *
 * The handler runs the dialog with a timeout, one at a time. Cancelling
 * the dialog is a normal outcome, not an error; a refused folder (the
 * guardrails) is — the same validation the manual path input runs.
 */

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"
)

const pickFolderTimeout = 3 * time.Minute

var pickInUse atomic.Bool

// pickFolderFunc is the indirection the tests stub out.
var pickFolderFunc = pickFolder

// pickFolder runs the OS folder picker and returns the chosen absolute
// path, "" when the user cancelled.
func pickFolder() (string, error) {
	switch runtime.GOOS {
	case "darwin":
		return pickFolderDarwin()
	case "windows":
		return pickFolderWindows()
	default:
		return pickFolderLinux()
	}
}

func pickFolderDarwin() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), pickFolderTimeout)
	defer cancel()
	script := `POSIX path of (choose folder with prompt "Choose a folder for wPurge to scan")`
	cmd := exec.CommandContext(ctx, "osascript", "-e", script)
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", errors.New("the folder dialog timed out — try again")
		}
		// "User canceled" (error -128) is a normal outcome
		if strings.Contains(string(out), "User canceled") || strings.Contains(string(out), "-128") {
			return "", nil
		}
		return "", fmt.Errorf("folder dialog: %v", err)
	}
	return filepath.Clean(strings.TrimSpace(string(out))), nil
}

func pickFolderWindows() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), pickFolderTimeout)
	defer cancel()
	script := `Add-Type -AssemblyName System.Windows.Forms; ` +
		`$f = New-Object System.Windows.Forms.FolderBrowserDialog; ` +
		`$f.Description = 'Choose a folder for wPurge to scan'; ` +
		`$f.ShowNewFolderButton = $false; ` +
		`if ($f.ShowDialog() -eq 'OK') { Write-Output $f.SelectedPath }`
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-STA", "-Command", script)
	hideWindow(cmd)
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", errors.New("the folder dialog timed out — try again")
		}
		return "", fmt.Errorf("folder dialog: %v", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// pickFolderLinux probes the two common dialog tools; a desktop without
// either falls back to the manual path input (the settings field stays).
func pickFolderLinux() (string, error) {
	var bin string
	var args []string
	if _, err := exec.LookPath("zenity"); err == nil {
		bin = "zenity"
		args = []string{"--file-selection", "--directory", "--title", "Choose a folder for wPurge to scan"}
	} else if _, err := exec.LookPath("kdialog"); err == nil {
		bin = "kdialog"
		args = []string{"--getexistingdirectory", homeDir(), "--title", "Choose a folder for wPurge to scan"}
	} else {
		return "", errors.New("no folder picker on this desktop (install zenity or kdialog) — paste the path instead")
	}
	ctx, cancel := context.WithTimeout(context.Background(), pickFolderTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", errors.New("the folder dialog timed out — try again")
		}
		return "", nil // cancel exits non-zero with no output
	}
	return strings.TrimSpace(string(out)), nil
}

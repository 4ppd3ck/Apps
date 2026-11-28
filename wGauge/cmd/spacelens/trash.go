package main

// trash — the delete feature moves paths to the OS trash (Recycle Bin on
// Windows, Trash on macOS/Linux) instead of unlinking them, so every delete
// stays recoverable. macOS prefers a plain rename into ~/.Trash (fast, no
// permission prompts) and falls back to Finder for other volumes; Windows
// uses the VisualBasic recycle-bin API via PowerShell; Linux uses gio.

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const maxDeleteBatch = 500

type deleteResult struct {
	Path  string `json:"path"`
	Ok    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func (s *server) handleDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Paths []string `json:"paths"`
	}
	if !s.decodeJSON(w, r, &req) {
		return
	}
	if len(req.Paths) == 0 || len(req.Paths) > maxDeleteBatch {
		s.fail(w, http.StatusBadRequest, fmt.Sprintf("paths (1..%d entries) required", maxDeleteBatch))
		return
	}
	results := make([]deleteResult, 0, len(req.Paths))
	for _, p := range req.Paths {
		p = strings.TrimSpace(p)
		if err := guardTrashPath(p); err != nil {
			results = append(results, deleteResult{Path: p, Error: err.Error()})
			continue
		}
		if err := trashPath(p); err != nil {
			results = append(results, deleteResult{Path: p, Error: err.Error()})
			continue
		}
		results = append(results, deleteResult{Path: p, Ok: true})
	}
	s.json(w, map[string]any{"results": results})
}

// guardTrashPath refuses non-absolute paths and volume/drive roots: a
// misfired bulk delete must never be able to target "/" or "C:\".
func guardTrashPath(p string) error {
	if p == "" {
		return errors.New("empty path")
	}
	// Clean before testing: "//", "/.", "/Users/.." and "C:/" all name a root
	// yet differ from it as strings, so uncleaned they slip past the checks.
	p = filepath.Clean(p)
	if !filepath.IsAbs(p) {
		return errors.New("absolute path required")
	}
	if p == filepath.Dir(p) {
		return fmt.Errorf("refusing to trash a filesystem or drive root: %s", p)
	}
	return nil
}

func trashPath(p string) error {
	switch runtime.GOOS {
	case "darwin":
		if err := trashByRename(p); err == nil {
			return nil
		}
		return trashViaFinder(p)
	case "windows":
		return trashWindows(p)
	default:
		gio, err := exec.LookPath("gio")
		if err != nil {
			return errors.New("no trash tool found — install gio (gvfs)")
		}
		out, err := exec.Command(gio, "trash", "--", p).CombinedOutput()
		if err != nil {
			return fmt.Errorf("gio trash failed: %s", strings.TrimSpace(string(out)))
		}
		return nil
	}
}

// trashByRename moves into the user's Trash on the same volume; cross-volume
// moves fail and the caller falls back to Finder.
func trashByRename(p string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	trash := filepath.Join(home, ".Trash")
	if err := os.MkdirAll(trash, 0o700); err != nil {
		return err
	}
	base := filepath.Base(p)
	// "name.ext" is split so the counter lands before the extension; a
	// dotfile (".hidden") has none, or it would come back as " (2).hidden".
	stem, ext := base, ""
	if i := strings.LastIndexByte(base, '.'); i > 0 {
		stem, ext = base[:i], base[i:]
	}
	dest := filepath.Join(trash, base)
	for i := 2; ; i++ {
		if _, err := os.Lstat(dest); err != nil {
			break // name free
		}
		if i > 9999 {
			return errors.New("no free name in Trash")
		}
		dest = filepath.Join(trash, fmt.Sprintf("%s (%d)%s", stem, i, ext))
	}
	return os.Rename(p, dest)
}

func trashViaFinder(p string) error {
	esc := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(p)
	script := fmt.Sprintf(`set f to POSIX file "%s" as alias
tell application "Finder" to delete f`, esc)
	out, err := exec.Command("osascript", "-e", script).CombinedOutput()
	if err != nil {
		return fmt.Errorf("Finder delete failed: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func trashWindows(p string) error {
	fn := "DeleteFile"
	// Lstat, not Stat: a directory link is recycled as the link itself,
	// never resolved to (and emptied into) its target
	if info, err := os.Lstat(p); err == nil && info.IsDir() {
		fn = "DeleteDirectory"
	}
	esc := strings.ReplaceAll(p, "'", "''")
	script := fmt.Sprintf(`Add-Type -AssemblyName Microsoft.VisualBasic | Out-Null
[Microsoft.VisualBasic.FileIO.FileSystem]::%s('%s', 'OnlyErrorDialogs', 'SendToRecycleBin')`, fn, esc)
	out, err := exec.Command("powershell", "-NoProfile", "-STA", "-Command", script).CombinedOutput()
	if err != nil {
		return fmt.Errorf("recycle bin move failed: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

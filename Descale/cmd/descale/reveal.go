package main

/* Reveal: the 📂 button next to every trace and exclusion — shows the
 * location in the system file manager (Finder on macOS with the item
 * selected, Explorer on Windows, xdg-open elsewhere).
 *
 * Non-destructive, but validated like every path-taking endpoint: the path
 * must be absolute, exist on disk, and sit strictly inside one of the roots
 * whose contents the Traces tab manages — so the client can never make the
 * server pop open arbitrary system locations.
 */

import (
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// revealAllowed reports whether p is strictly inside home or, on Windows,
// one of the extra roots the traces scan walks (AppData, ProgramData).
func revealAllowed(p string) bool {
	roots := []string{homeDir()}
	if runtime.GOOS == "windows" {
		roots = append(roots, os.Getenv("LOCALAPPDATA"), os.Getenv("APPDATA"), os.Getenv("ProgramData"))
	}
	lp := strings.ToLower(filepath.Clean(p))
	for _, root := range roots {
		if root == "" {
			continue
		}
		rel, err := filepath.Rel(strings.ToLower(filepath.Clean(root)), lp)
		if err == nil && rel != "." && !strings.HasPrefix(rel, "..") {
			return true
		}
	}
	return false
}

func (s *server) handleReveal(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil || req.Path == "" {
		fail(w, http.StatusBadRequest, "expected {\"path\": \"/absolute/location\"}")
		return
	}
	p := filepath.Clean(req.Path)
	if !filepath.IsAbs(p) {
		fail(w, http.StatusBadRequest, "path must be absolute")
		return
	}
	if !revealAllowed(p) {
		fail(w, http.StatusBadRequest, "path is outside the folders Descale manages")
		return
	}
	if _, err := os.Stat(p); err != nil {
		fail(w, http.StatusNotFound, "not found: "+p)
		return
	}
	if err := revealInFileManager(p); err != nil {
		fail(w, http.StatusInternalServerError, "cannot open the file manager: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "path": p})
}

// revealInFileManager asks the OS file manager to show p, selected where
// the platform supports it. Explorer exits nonzero even on success, so its
// exit status is ignored; Run() also reaps the child process.
func revealInFileManager(p string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", "-R", p)
	case "windows":
		cmd = exec.Command("explorer", "/select,"+p)
	default:
		dir := p
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			dir = filepath.Dir(p)
		}
		cmd = exec.Command("xdg-open", dir)
	}
	if err := cmd.Run(); err != nil && runtime.GOOS != "windows" {
		return err
	}
	return nil
}

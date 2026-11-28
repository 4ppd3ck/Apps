package main

// reveal — open a scanned path in the OS file manager, pre-selected.
// wGauge stays read-only: this is its only hand-off to the outside.
import (
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

func (s *server) handleReveal(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path string `json:"path"`
	}
	if !s.decodeJSON(w, r, &req) {
		return
	}
	p := req.Path
	// IsAbs, not a length test: on Windows "abc" is three characters and yet
	// a relative path
	if !filepath.IsAbs(p) {
		s.fail(w, http.StatusBadRequest, "absolute path required")
		return
	}
	if _, err := os.Stat(p); err != nil {
		s.fail(w, http.StatusNotFound, "path no longer exists: "+p)
		return
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", "-R", p) // reveal in Finder
	case "windows":
		cmd = exec.Command("explorer", "/select,", p)
	default:
		cmd = exec.Command("xdg-open", filepath.Dir(p))
	}
	if err := cmd.Start(); err != nil {
		s.fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	go func() { _ = cmd.Wait() }()
	s.json(w, map[string]any{"ok": true})
}

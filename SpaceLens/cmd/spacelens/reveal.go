package main

// reveal — open a scanned path in the OS file manager, pre-selected.
// SpaceLens stays read-only: this is its only hand-off to the outside.
import (
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

func (s *server) handleReveal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.fail(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		s.fail(w, http.StatusBadRequest, "bad request body")
		return
	}
	p := req.Path
	if !strings.HasPrefix(p, "/") && runtime.GOOS != "windows" ||
		runtime.GOOS == "windows" && len(p) < 3 {
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
		cmd = exec.Command("xdg-open", parentDir(p))
	}
	if err := cmd.Start(); err != nil {
		s.fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	go func() { _ = cmd.Wait() }()
	s.json(w, map[string]any{"ok": true})
}

func parentDir(p string) string {
	for i := len(p) - 1; i > 0; i-- {
		if p[i] == '/' && i > 0 {
			return p[:i]
		}
	}
	return p
}

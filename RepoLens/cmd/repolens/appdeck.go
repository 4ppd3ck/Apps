package main

// AppDeck install bridge — the plumbing behind the frontend's "Install on
// AppDeck" button. A page served inside AppDeck cannot call the launcher's
// POST /api/import itself (the dashboard rejects cross-origin POSTs), but
// RepoLens's own process is a loopback client of the launcher, so it installs
// on the page's behalf: it either downloads a GitHub release artifact and
// pushes the bytes through the same import endpoint the dashboard's 📥
// button uses, or hands over the repo URL for AppDeck to git-import. Installs
// run as background jobs the frontend polls, with the launcher's import log
// relayed as live status notes.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// launcherURL returns the dashboard URL AppDeck injects into the app
// environment ("" when RepoLens runs standalone — the install UI hides
// itself).
func launcherURL() string {
	return strings.TrimRight(strings.TrimSpace(os.Getenv("APPDECK_LAUNCHER_URL")), "/")
}

// repoURLRE matches the git-import forms AppDeck accepts: owner/repo and the
// monorepo owner/repo/tree/branch/folder.
var repoURLRE = regexp.MustCompile(`^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(/tree/[^?#]+)?/?$`)

// installClient talks to the launcher over loopback. Git imports can run for
// minutes, so the per-request context (not a client timeout) bounds the wait.
var installClient = &http.Client{}

// progressClient only ever polls the launcher's read-only progress endpoint.
var progressClient = &http.Client{Timeout: 4 * time.Second}

type installRequest struct {
	URL  string `json:"url"`  // GitHub release artifact — downloaded here, bytes imported
	Repo string `json:"repo"` // github.com/owner/repo — AppDeck git-imports the source
	Name string `json:"name"` // display name (the repo name)
}

type installResult struct {
	ID        string `json:"id,omitempty"`
	Name      string `json:"name,omitempty"`
	Note      string `json:"note,omitempty"`
	Dashboard string `json:"dashboard"`
}

// installJob tracks one install from RepoLens's side. phase moves
// downloading → importing → done/error; percent is the artifact download
// progress, note a human-readable status line (for imports, the newest line
// of the launcher's import log, filled in by the poll).
type installJob struct {
	mu       sync.Mutex
	id       string // handle given to the frontend
	importID string // jobid handed to the launcher — its /api/import/progress handle
	phase    string
	percent  int
	note     string
	err      string
	result   *installResult
	cancel   context.CancelFunc
	deadline time.Time
}

func (j *installJob) finished() bool {
	return j.phase == "done" || j.phase == "error"
}

var (
	installMu       sync.Mutex
	installJobs     = map[string]*installJob{}
	maxKeptInstalls = 30
)

// registerInstall stores the job and drops the oldest finished ones so a
// long-lived run cannot accumulate them.
func registerInstall(j *installJob) {
	installMu.Lock()
	installJobs[j.id] = j
	for len(installJobs) > maxKeptInstalls {
		oldestID, oldest := "", time.Time{}
		for id, other := range installJobs {
			other.mu.Lock()
			fin, dl := other.finished(), other.deadline
			other.mu.Unlock()
			if fin && (oldest.IsZero() || dl.Before(oldest)) {
				oldestID, oldest = id, dl
			}
		}
		if oldestID == "" {
			break
		}
		delete(installJobs, oldestID)
	}
	installMu.Unlock()
}

func (s *server) handleAppDeckInstall(w http.ResponseWriter, r *http.Request) {
	launcher := launcherURL()
	if launcher == "" {
		writeJSON(w, 503, errResp{Error: "RepoLens is not running under AppDeck."})
		return
	}
	var body installRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, 400, errResp{Error: "Expected JSON body: {url? | repo?, name?}."})
		return
	}
	body.URL = strings.TrimSpace(body.URL)
	body.Repo = strings.TrimSpace(body.Repo)
	body.Name = strings.TrimSpace(body.Name)
	switch {
	case body.URL != "":
		if u, err := url.Parse(body.URL); err != nil || !allowedDownloadHost(u.Hostname()) {
			writeJSON(w, 400, errResp{Error: "Only github.com download URLs can be installed."})
			return
		}
	case body.Repo != "":
		if !repoURLRE.MatchString(body.Repo) {
			writeJSON(w, 400, errResp{Error: "Only github.com repository URLs can be installed."})
			return
		}
	default:
		writeJSON(w, 400, errResp{Error: "Nothing to install: pass a release asset url or a repo."})
		return
	}
	if body.Name == "" {
		// path.Base covers both forms: owner/repo → "repo", and a monorepo
		// .../tree/main/Folder → "Folder" (the folder is what gets installed).
		body.Name = path.Base(body.Repo)
	}

	j := &installJob{
		id:       "inst-" + randToken(),
		importID: "imp-" + randToken(),
		phase:    "downloading",
		note:     "Starting…",
		deadline: time.Now().Add(time.Hour),
	}
	if body.URL == "" {
		j.phase = "importing" // source mode: the launcher does all the work
	}
	registerInstall(j)

	go s.runInstall(launcher, j, body)
	writeJSON(w, 200, map[string]any{"job": j.id})
}

// runInstall drives one install to completion. The 30-minute context is a
// backstop — the launcher's own no-progress watchdog ends stuck imports long
// before that.
func (s *server) runInstall(launcher string, j *installJob, body installRequest) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	j.mu.Lock()
	j.cancel = cancel
	j.mu.Unlock()

	if err := s.runInstallSteps(ctx, launcher, j, body); err != nil {
		j.mu.Lock()
		j.phase = "error"
		if ctx.Err() != nil {
			j.err = "Install canceled."
		} else {
			j.err = err.Error()
		}
		j.mu.Unlock()
	}
	cancel()
}

func (s *server) runInstallSteps(ctx context.Context, launcher string, j *installJob, body installRequest) error {
	var importBody io.Reader
	contentLength := int64(-1)
	assetName := ""

	if body.URL != "" {
		f, n, name, err := s.downloadArtifact(ctx, j, body.URL)
		if err != nil {
			return err
		}
		defer func() { f.Close(); os.Remove(f.Name()) }()
		importBody, contentLength, assetName = f, n, name
		j.mu.Lock()
		j.phase = "importing"
		j.note = "Handing to AppDeck…"
		j.mu.Unlock()
	}

	q := url.Values{}
	if assetName != "" {
		q.Set("name", assetName)
	}
	q.Set("appname", body.Name)
	q.Set("jobid", j.importID)
	if body.URL == "" {
		q.Set("url", body.Repo)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, launcher+"/api/import?"+q.Encode(), importBody)
	if err != nil {
		return fmt.Errorf("Could not reach the AppDeck dashboard: %s", err)
	}
	if contentLength >= 0 {
		req.ContentLength = contentLength
	}
	res, err := installClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return err
		}
		return fmt.Errorf("Could not reach the AppDeck dashboard: %s", err)
	}
	defer res.Body.Close()

	var out struct {
		OK    bool   `json:"ok"`
		ID    string `json:"id"`
		Name  string `json:"name"`
		Note  string `json:"note"`
		Error string `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&out); err != nil {
		return fmt.Errorf("AppDeck import answered HTTP %d", res.StatusCode)
	}
	if out.Error != "" {
		return fmt.Errorf("AppDeck: %s", out.Error)
	}
	j.mu.Lock()
	j.phase = "done"
	j.note = ""
	j.result = &installResult{ID: out.ID, Name: out.Name, Note: out.Note, Dashboard: launcher}
	j.mu.Unlock()
	return nil
}

// downloadArtifact streams the release asset into a temp file inside the app
// data dir (writable under AppDeck, unlike the binary's folder), reporting
// progress into the job, and rewinds the file for the import upload.
func (s *server) downloadArtifact(ctx context.Context, j *installJob, rawURL string) (*os.File, int64, string, error) {
	req, err := newDownloadRequest(ctx, rawURL, s.gh.token)
	if err != nil {
		return nil, 0, "", err
	}
	res, err := downloadClient().Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, 0, "", fmt.Errorf("Install canceled.")
		}
		return nil, 0, "", fmt.Errorf("Could not reach the download URL: %s", err)
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		status := "Download failed"
		if res.StatusCode == 404 {
			status = "Artifact not found"
		}
		return nil, 0, "", fmt.Errorf("%s (HTTP %d)", status, res.StatusCode)
	}

	name := ""
	if cd := filenameFromDisposition(res.Header.Get("Content-Disposition")); cd != "" {
		name = sanitizeFilename(cd)
	} else if u, perr := url.Parse(rawURL); perr == nil && path.Base(u.Path) != "" && path.Base(u.Path) != "/" {
		name = sanitizeFilename(path.Base(u.Path))
	}

	if err := os.MkdirAll(s.dataDir, 0o755); err != nil {
		return nil, 0, "", fmt.Errorf("No writable data dir: %s", err)
	}
	f, err := os.Create(filepath.Join(s.dataDir, ".repolens-install-"+randToken()))
	if err != nil {
		return nil, 0, "", fmt.Errorf("Could not buffer the download: %s", err)
	}

	total := res.ContentLength
	var done int64
	var lastNote time.Time
	counting := &countingReader{r: res.Body, onRead: func(n int) {
		done += int64(n)
		// Throttle the status writes: Read hands out small buffers, and the
		// poll only needs fresh text a couple of times a second.
		if time.Since(lastNote) < 200*time.Millisecond && (total <= 0 || done < total) {
			return
		}
		lastNote = time.Now()
		j.mu.Lock()
		if total > 0 {
			pct := int(float64(done) / float64(total) * 100)
			if pct > 99 {
				pct = 99
			}
			j.percent = pct
			j.note = fmt.Sprintf("Downloading %s… %d%%", name, pct)
		} else {
			// GitHub zipballs stream chunked — no Content-Length to percent
			// against, so count bytes out loud instead.
			j.note = fmt.Sprintf("Downloading %s… %s", name, humanBytes(done))
		}
		j.mu.Unlock()
	}}
	_, copyErr := io.Copy(f, counting)
	if copyErr != nil {
		f.Close()
		os.Remove(f.Name())
		if ctx.Err() != nil {
			return nil, 0, "", fmt.Errorf("Install canceled.")
		}
		return nil, 0, "", fmt.Errorf("Download interrupted: %s", copyErr)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		os.Remove(f.Name())
		return nil, 0, "", fmt.Errorf("Could not buffer the download: %s", err)
	}
	return f, done, name, nil
}

// countingReader feeds download progress to the install job.
type countingReader struct {
	r      io.Reader
	onRead func(int)
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		c.onRead(n)
	}
	return n, err
}

// humanBytes renders a byte count the way the UI's fmtBytes does.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

// handleAppDeckInstallStatus answers the frontend's poll. While the import
// runs, the newest line of the launcher's import log is surfaced as the note.
func (s *server) handleAppDeckInstallStatus(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	installMu.Lock()
	j, ok := installJobs[id]
	if ok && time.Now().After(j.deadline) {
		delete(installJobs, id)
		ok = false
	}
	installMu.Unlock()
	if !ok {
		writeJSON(w, 404, errResp{Error: "Unknown install job."})
		return
	}
	j.mu.Lock()
	phase, percent, note, jerr, result, importID := j.phase, j.percent, j.note, j.err, j.result, j.importID
	j.mu.Unlock()
	if phase == "importing" {
		if line := s.launcherImportNote(importID); line != "" {
			note = line
		}
	}
	out := map[string]any{
		"phase":   phase,
		"percent": percent,
		"note":    note,
		"done":    phase == "done" || phase == "error",
		"ok":      phase == "done",
	}
	if jerr != "" {
		out["error"] = jerr
	}
	if result != nil {
		out["result"] = result
	}
	writeJSON(w, 200, out)
}

// launcherImportNote polls the launcher's import progress endpoint and
// returns its newest log line ("" when unreachable or nothing logged yet).
func (s *server) launcherImportNote(importID string) string {
	launcher := launcherURL()
	if launcher == "" {
		return ""
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		launcher+"/api/import/progress?id="+url.QueryEscape(importID), nil)
	if err != nil {
		return ""
	}
	res, err := progressClient.Do(req)
	if err != nil {
		return ""
	}
	defer res.Body.Close()
	var out struct {
		Lines []string `json:"lines"`
	}
	if json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&out) != nil {
		return ""
	}
	for i := len(out.Lines) - 1; i >= 0; i-- {
		if line := strings.TrimSpace(out.Lines[i]); line != "" {
			if len(line) > 160 {
				line = line[:157] + "…"
			}
			return line
		}
	}
	return ""
}

// handleAppDeckInstallCancel cancels the artifact download locally and asks
// the launcher to abort its import (git clone / extraction) as well.
func (s *server) handleAppDeckInstallCancel(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil || body.ID == "" {
		writeJSON(w, 400, errResp{Error: "Expected JSON body: {id}."})
		return
	}
	installMu.Lock()
	j, ok := installJobs[body.ID]
	installMu.Unlock()
	if !ok {
		writeJSON(w, 404, errResp{Error: "Unknown install job."})
		return
	}
	j.mu.Lock()
	cancel, importID, running := j.cancel, j.importID, !j.finished()
	j.mu.Unlock()
	if running {
		if cancel != nil {
			cancel()
		}
		if launcher := launcherURL(); launcher != "" {
			payload, _ := json.Marshal(map[string]string{"id": importID})
			req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
				launcher+"/api/import/cancel", strings.NewReader(string(payload)))
			if err == nil {
				req.Header.Set("Content-Type", "application/json")
				res, err := progressClient.Do(req)
				if err == nil {
					res.Body.Close()
				}
			}
		}
	}
	writeJSON(w, 200, okResp{OK: true})
}

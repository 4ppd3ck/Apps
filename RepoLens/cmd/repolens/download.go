package main

// Download handling: proxying release assets with a proper filename, saving
// straight into a user-chosen folder, native "save as" / "choose folder"
// dialogs, and batch downloads of many repos with a progress job.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

// ---------- shared download transport ----------

var (
	dlClientOnce sync.Once
	dlClientInst *http.Client
)

// downloadClient streams large files with no global timeout (per-request
// contexts bound the wait) and re-validates every redirect hop so the proxy
// can only ever talk to GitHub hosts.
func downloadClient() *http.Client {
	dlClientOnce.Do(func() {
		c := newHTTPClient(0)
		c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if !allowedDownloadHost(req.URL.Hostname()) {
				return fmt.Errorf("redirect to a host outside GitHub: %s", req.URL.Hostname())
			}
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		}
		dlClientInst = c
	})
	return dlClientInst
}

func allowedDownloadHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return false
	}
	for _, suffix := range []string{"github.com", "githubusercontent.com", "githubassets.com"} {
		if h == suffix || strings.HasSuffix(h, "."+suffix) {
			return true
		}
	}
	return false
}

func newDownloadRequest(ctx context.Context, rawURL, token string) (*http.Request, error) {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || !allowedDownloadHost(u.Hostname()) {
		return nil, &GitHubError{Status: 400, Message: "Only github.com download URLs are supported."}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, &GitHubError{Status: 502, Message: err.Error()}
	}
	req.Header.Set("User-Agent", "RepoLens/0.3")
	req.Header.Set("Accept", "application/octet-stream")
	host := u.Hostname()
	if token != "" && (host == "api.github.com" || strings.HasSuffix(host, ".api.github.com")) {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req, nil
}

// filenameFromDisposition pulls filename / filename* out of a
// Content-Disposition header, preferring the RFC 5987 form.
func filenameFromDisposition(cd string) string {
	if cd == "" {
		return ""
	}
	var plain, ext string
	for _, part := range strings.Split(cd, ";") {
		part = strings.TrimSpace(part)
		eq := strings.Index(part, "=")
		if eq <= 0 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(part[:eq]))
		val := strings.TrimSpace(part[eq+1:])
		if len(val) >= 2 && strings.HasPrefix(val, `"`) && strings.HasSuffix(val, `"`) {
			val = val[1 : len(val)-1]
		}
		switch name {
		case "filename":
			plain = val
		case "filename*":
			// charset'lang'percent-encoded-value
			if i := strings.IndexByte(val, '\''); i >= 0 {
				if j := strings.IndexByte(val[i+1:], '\''); j >= 0 {
					val = val[i+1+j+1:]
				}
			}
			if dec, err := url.QueryUnescape(val); err == nil {
				ext = dec
			} else {
				ext = val
			}
		}
	}
	if ext != "" {
		return ext
	}
	return plain
}

var filenameSanitizer = strings.NewReplacer(
	"/", "-", `\`, "-", ":", "-", "*", "-", "?", "", `"`, "'",
	"<", "(", ">", ")", "|", "-", "\x00", "", "\n", "", "\r", "",
)

func sanitizeFilename(name string) string {
	name = path.Base(strings.TrimSpace(name))
	name = filenameSanitizer.Replace(name)
	name = strings.TrimSpace(name)
	if len(name) > 150 {
		ext := path.Ext(name)
		if len(ext) > 20 {
			ext = ""
		}
		name = name[:150-len(ext)] + ext
	}
	name = strings.TrimRight(name, ". ")
	if name == "" || name == "." || name == ".." {
		return "download"
	}
	return name
}

func randToken() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ---------- GET /api/download — browser-mode proxy ----------

func (s *server) handleDownloadProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSON(w, 405, errResp{Error: "Method not allowed"})
		return
	}
	raw := r.URL.Query().Get("url")
	name := sanitizeFilename(r.URL.Query().Get("name"))
	if raw == "" {
		writeJSON(w, 400, errResp{Error: "Missing url parameter."})
		return
	}
	req, err := newDownloadRequest(r.Context(), raw, s.gh.token)
	if err != nil {
		s.writeGHErr(w, err)
		return
	}
	res, err := downloadClient().Do(req)
	if err != nil {
		if r.Context().Err() != nil {
			return // client hung up
		}
		writeJSON(w, 502, errResp{Error: "Could not reach the download URL: " + err.Error()})
		return
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		status := 502
		if res.StatusCode == 404 {
			status = 404
		}
		writeJSON(w, status, errResp{Error: fmt.Sprintf("Download failed (HTTP %d)", res.StatusCode)})
		return
	}

	if name == "" || name == "download" {
		if cd := filenameFromDisposition(res.Header.Get("Content-Disposition")); cd != "" {
			name = sanitizeFilename(cd)
		} else if u, perr := url.Parse(raw); perr == nil && path.Base(u.Path) != "" && path.Base(u.Path) != "zipball" && path.Base(u.Path) != "tarball" {
			name = sanitizeFilename(path.Base(u.Path))
		} else {
			name = "download"
		}
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q; filename*=UTF-8''%s", name, url.PathEscape(name)))
	if res.ContentLength > 0 {
		w.Header().Set("Content-Length", fmt.Sprint(res.ContentLength))
	}
	w.WriteHeader(200)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = io.Copy(w, res.Body)
}

// ---------- shared save-to-disk ----------

type saveResult struct {
	Path  string `json:"path"`
	Name  string `json:"name"`
	Dir   string `json:"dir"`
	Bytes int64  `json:"bytes"`
}

// fetchToFile streams rawURL to a temp file next to the destination, then
// renames it into place. When destFile is set it is used verbatim ("save as");
// otherwise the file lands in dir under name (or the upstream-provided name),
// uniquified if it already exists.
func (s *server) fetchToFile(ctx context.Context, rawURL, destFile, dir, name string) (saveResult, error) {
	req, err := newDownloadRequest(ctx, rawURL, s.gh.token)
	if err != nil {
		return saveResult{}, err
	}
	res, err := downloadClient().Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return saveResult{}, &GitHubError{Status: 499, Message: "canceled"}
		}
		return saveResult{}, &GitHubError{Status: 502, Message: "Could not reach the download URL: " + err.Error()}
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		status := 502
		msg := fmt.Sprintf("Download failed (HTTP %d)", res.StatusCode)
		if res.StatusCode == 404 {
			status = 404
		}
		return saveResult{}, &GitHubError{Status: status, Message: msg}
	}

	finalName := sanitizeFilename(name)
	if finalName == "download" {
		if cd := filenameFromDisposition(res.Header.Get("Content-Disposition")); cd != "" {
			finalName = sanitizeFilename(cd)
		} else if u, perr := url.Parse(rawURL); perr == nil {
			finalName = sanitizeFilename(path.Base(u.Path))
		}
	}

	target := destFile
	if target == "" {
		if !filepath.IsAbs(dir) {
			return saveResult{}, &GitHubError{Status: 400, Message: "Save folder must be an absolute path."}
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return saveResult{}, &GitHubError{Status: 400, Message: "Could not create folder: " + err.Error()}
		}
		target = uniquePath(dir, finalName)
		finalName = filepath.Base(target)
	} else {
		if !filepath.IsAbs(target) {
			return saveResult{}, &GitHubError{Status: 400, Message: "Save path must be absolute."}
		}
		parent := filepath.Dir(target)
		if info, err := os.Stat(parent); err != nil || !info.IsDir() {
			return saveResult{}, &GitHubError{Status: 400, Message: "Folder does not exist: " + parent}
		}
		finalName = filepath.Base(target)
	}

	tmp := filepath.Join(filepath.Dir(target), ".repolens-part-"+randToken())
	f, err := os.Create(tmp)
	if err != nil {
		return saveResult{}, &GitHubError{Status: 400, Message: "Could not write to the destination: " + err.Error()}
	}
	n, copyErr := io.Copy(f, res.Body)
	closeErr := f.Close()
	if copyErr == nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		_ = os.Remove(tmp)
		if ctx.Err() != nil {
			return saveResult{}, &GitHubError{Status: 499, Message: "canceled"}
		}
		return saveResult{}, &GitHubError{Status: 502, Message: "Download interrupted: " + copyErr.Error()}
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		return saveResult{}, &GitHubError{Status: 500, Message: "Could not move the file into place: " + err.Error()}
	}
	return saveResult{Path: target, Name: finalName, Dir: filepath.Dir(target), Bytes: n}, nil
}

func uniquePath(dir, name string) string {
	cand := filepath.Join(dir, name)
	if _, err := os.Stat(cand); os.IsNotExist(err) {
		return cand
	}
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	for i := 1; i <= 999; i++ {
		cand = filepath.Join(dir, fmt.Sprintf("%s (%d)%s", stem, i, ext))
		if _, err := os.Stat(cand); os.IsNotExist(err) {
			return cand
		}
	}
	return filepath.Join(dir, name)
}

// ---------- POST /api/save — save a single URL to disk ----------

func (s *server) handleSave(w http.ResponseWriter, r *http.Request) {
	var body struct {
		URL  string `json:"url"`
		Name string `json:"name"`
		Dir  string `json:"dir"`
		File string `json:"file"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil || body.URL == "" {
		writeJSON(w, 400, errResp{Error: "Expected JSON body: {url, name?, dir? | file?}."})
		return
	}
	if body.File == "" && body.Dir == "" {
		writeJSON(w, 400, errResp{Error: "Provide either dir (folder to save into) or file (exact save-as path)."})
		return
	}
	res, err := s.fetchToFile(r.Context(), body.URL, body.File, body.Dir, body.Name)
	if err != nil {
		if ge, ok := err.(*GitHubError); ok && ge.Status == 499 {
			writeJSON(w, 200, map[string]any{"canceled": true})
			return
		}
		s.writeGHErr(w, err)
		return
	}
	writeJSON(w, 200, res)
}

// ---------- native pickers (macOS / Windows) ----------

func dialogsSupported() bool {
	return runtime.GOOS == "darwin" || runtime.GOOS == "windows"
}

func isUserCanceled(err error) bool {
	if ee, ok := err.(*exec.ExitError); ok {
		msg := strings.ToLower(string(ee.Stderr))
		return strings.Contains(msg, "cancel") || ee.ExitCode() == 128
	}
	return false
}

func appleEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}

const psFolderPicker = `Add-Type -AssemblyName System.Windows.Forms | Out-Null
$d = New-Object System.Windows.Forms.FolderBrowserDialog
$d.Description = 'RepoLens - choose a download folder'
$d.ShowNewFolderButton = $true
if ($d.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { Write-Output $d.SelectedPath }`

func runPicker(ctx context.Context, name string, args ...string) (string, bool /*canceled*/, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	if err != nil {
		if isUserCanceled(err) {
			return "", true, nil
		}
		return "", false, err
	}
	p := strings.TrimSpace(string(out))
	if p == "" {
		return "", true, nil
	}
	return p, false, nil
}

func pickerCtx(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), 15*time.Minute)
}

func (s *server) handlePickFolder(w http.ResponseWriter, r *http.Request) {
	if !dialogsSupported() {
		writeJSON(w, 200, map[string]any{"unsupported": true})
		return
	}
	ctx, cancel := pickerCtx(r)
	defer cancel()
	var (
		p   string
		c   bool
		err error
	)
	switch runtime.GOOS {
	case "darwin":
		script := "tell application \"System Events\" to activate\n" +
			"POSIX path of (choose folder with prompt \"RepoLens — choose a download folder\")"
		p, c, err = runPicker(ctx, "osascript", "-e", script)
	case "windows":
		p, c, err = runPicker(ctx, "powershell", "-NoProfile", "-STA", "-Command", psFolderPicker)
	}
	if ctx.Err() != nil {
		return // client went away or the dialog timed out
	}
	if err != nil {
		writeJSON(w, 500, errResp{Error: "Folder picker failed: " + err.Error()})
		return
	}
	if c {
		writeJSON(w, 200, map[string]any{"canceled": true})
		return
	}
	if runtime.GOOS == "darwin" {
		p = strings.TrimRight(p, "/")
		if p == "" {
			p = "/"
		}
	}
	writeJSON(w, 200, map[string]any{"path": p})
}

func (s *server) handlePickFile(w http.ResponseWriter, r *http.Request) {
	if !dialogsSupported() {
		writeJSON(w, 200, map[string]any{"unsupported": true})
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
	name := sanitizeFilename(body.Name)

	ctx, cancel := pickerCtx(r)
	defer cancel()
	var (
		p   string
		c   bool
		err error
	)
	switch runtime.GOOS {
	case "darwin":
		script := "tell application \"System Events\" to activate\n" +
			"POSIX path of (choose file name with prompt \"RepoLens — save as\" default name \"" + appleEscape(name) + "\")"
		p, c, err = runPicker(ctx, "osascript", "-e", script)
	case "windows":
		script := strings.ReplaceAll(`Add-Type -AssemblyName System.Windows.Forms | Out-Null
$d = New-Object System.Windows.Forms.SaveFileDialog
$d.Title = 'RepoLens - save as'
$d.FileName = '__NAME__'
if ($d.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { Write-Output $d.FileName }`, "__NAME__", strings.ReplaceAll(name, "'", "''"))
		p, c, err = runPicker(ctx, "powershell", "-NoProfile", "-STA", "-Command", script)
	}
	if ctx.Err() != nil {
		return
	}
	if err != nil {
		writeJSON(w, 500, errResp{Error: "Save dialog failed: " + err.Error()})
		return
	}
	if c {
		writeJSON(w, 200, map[string]any{"canceled": true})
		return
	}
	writeJSON(w, 200, map[string]any{"path": p})
}

func (s *server) handleOpen(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil || body.Path == "" {
		writeJSON(w, 400, errResp{Error: "Expected JSON body: {path}."})
		return
	}
	info, err := os.Stat(body.Path)
	if err != nil || !info.IsDir() {
		writeJSON(w, 400, errResp{Error: "Not an existing folder: " + body.Path})
		return
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", body.Path)
	case "windows":
		cmd = exec.Command("explorer", strings.ReplaceAll(body.Path, "/", `\`))
	default:
		cmd = exec.Command("xdg-open", body.Path)
	}
	if err := cmd.Start(); err != nil {
		writeJSON(w, 500, errResp{Error: err.Error()})
		return
	}
	go func() { _ = cmd.Wait() }()
	writeJSON(w, 200, okResp{OK: true})
}

// ---------- POST /api/batch + job status — bulk repo downloads ----------

type batchItem struct {
	URL  string `json:"url"`
	Name string `json:"name"`
}

type jobError struct {
	Name  string `json:"name"`
	URL   string `json:"url"`
	Error string `json:"error"`
}

type dlJob struct {
	mu       sync.Mutex
	id       string
	items    []batchItem
	dir      string
	total    int
	done     int
	failed   int
	current  string
	bytes    int64
	state    string // running | done | canceled
	cancel   context.CancelFunc
	errors   []jobError
	deadline time.Time
}

type jobSnapshot struct {
	ID      string     `json:"id"`
	State   string     `json:"state"`
	Total   int        `json:"total"`
	Done    int        `json:"done"`
	Failed  int        `json:"failed"`
	Current string     `json:"current"`
	Bytes   int64      `json:"bytes"`
	Dir     string     `json:"dir"`
	Errors  []jobError `json:"errors"`
}

const (
	maxBatchItems = 500
	batchWorkers  = 3
	maxKeptJobs   = 20
)

var jobsMu sync.Mutex
var jobs = map[string]*dlJob{}

var zipballRE = regexp.MustCompile(`^/repos/([^/]+)/([^/]+)/zipball$`)

func itemLabel(it batchItem) string {
	if it.Name != "" {
		return it.Name
	}
	if u, err := url.Parse(it.URL); err == nil {
		if m := zipballRE.FindStringSubmatch(u.Path); m != nil {
			return m[1] + "/" + m[2]
		}
		if b := path.Base(u.Path); b != "" && b != "/" {
			return b
		}
	}
	return it.URL
}

func (j *dlJob) snapshot() jobSnapshot {
	j.mu.Lock()
	defer j.mu.Unlock()
	errs := j.errors
	if errs == nil {
		errs = []jobError{}
	}
	return jobSnapshot{
		ID: j.id, State: j.state, Total: j.total, Done: j.done, Failed: j.failed,
		Current: j.current, Bytes: j.bytes, Dir: j.dir, Errors: errs,
	}
}

func (s *server) handleBatch(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Dir   string      `json:"dir"`
		Items []batchItem `json:"items"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&body); err != nil {
		writeJSON(w, 400, errResp{Error: "Expected JSON body: {items: [{url, name?}], dir}."})
		return
	}
	if len(body.Items) == 0 {
		writeJSON(w, 400, errResp{Error: "No items to download."})
		return
	}
	if len(body.Items) > maxBatchItems {
		writeJSON(w, 400, errResp{Error: fmt.Sprintf("Too many items (max %d).", maxBatchItems)})
		return
	}
	if !filepath.IsAbs(body.Dir) {
		writeJSON(w, 400, errResp{Error: "dir must be an absolute path."})
		return
	}
	for _, it := range body.Items {
		if u, err := url.Parse(it.URL); err != nil || !allowedDownloadHost(u.Hostname()) {
			writeJSON(w, 400, errResp{Error: "Item URL is not a github.com download URL: " + it.URL})
			return
		}
	}

	j := &dlJob{
		id:       "job-" + randToken(),
		items:    body.Items,
		dir:      body.Dir,
		total:    len(body.Items),
		state:    "running",
		deadline: time.Now().Add(24 * time.Hour),
	}
	jobsMu.Lock()
	jobs[j.id] = j
	// prune finished jobs beyond the kept window
	if len(jobs) > maxKeptJobs {
		for id, other := range jobs {
			if len(jobs) <= maxKeptJobs {
				break
			}
			other.mu.Lock()
			st := other.state
			other.mu.Unlock()
			if st != "running" {
				delete(jobs, id)
			}
		}
	}
	jobsMu.Unlock()

	go s.runJob(j)
	writeJSON(w, 200, map[string]any{"jobId": j.id})
}

func (s *server) runJob(j *dlJob) {
	ctx, cancel := context.WithCancel(context.Background())
	j.mu.Lock()
	j.cancel = cancel
	j.mu.Unlock()
	defer cancel()

	sem := make(chan struct{}, batchWorkers)
	var wg sync.WaitGroup
	for _, it := range j.items {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(it batchItem) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			label := itemLabel(it)
			j.mu.Lock()
			j.current = label
			j.mu.Unlock()
			res, err := s.fetchToFile(ctx, it.URL, "", j.dir, it.Name)
			j.mu.Lock()
			if err != nil {
				if ctx.Err() != nil {
					j.mu.Unlock()
					return
				}
				j.failed++
				j.errors = append(j.errors, jobError{Name: label, URL: it.URL, Error: err.Error()})
			} else {
				j.done++
				j.bytes += res.Bytes
			}
			j.current = ""
			j.mu.Unlock()
		}(it)
	}
	wg.Wait()

	j.mu.Lock()
	j.state = "done"
	if ctx.Err() != nil {
		j.state = "canceled"
	}
	j.current = ""
	j.mu.Unlock()
}

func (s *server) handleJobStatus(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	jobsMu.Lock()
	j, ok := jobs[id]
	if ok && time.Now().After(j.deadline) {
		delete(jobs, id)
		ok = false
	}
	jobsMu.Unlock()
	if !ok {
		writeJSON(w, 404, errResp{Error: "Unknown job id."})
		return
	}
	writeJSON(w, 200, j.snapshot())
}

func (s *server) handleJobCancel(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil || body.ID == "" {
		writeJSON(w, 400, errResp{Error: "Expected JSON body: {id}."})
		return
	}
	jobsMu.Lock()
	j, ok := jobs[body.ID]
	jobsMu.Unlock()
	if !ok {
		writeJSON(w, 404, errResp{Error: "Unknown job id."})
		return
	}
	j.mu.Lock()
	cancel := j.cancel
	st := j.state
	j.mu.Unlock()
	if st == "running" && cancel != nil {
		cancel()
	}
	writeJSON(w, 200, okResp{OK: true})
}

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type errResp struct {
	Error string `json:"error"`
}

type okResp struct {
	OK bool `json:"ok"`
}

func (s *server) handleTrending(w http.ResponseWriter) {
	s.histMu.Lock()
	defer s.histMu.Unlock()
	searches := make([]trendQuery, 0, 8)
	for _, q := range topN(s.hist.Searches, 8) {
		searches = append(searches, trendQuery{Query: q, Hits: s.hist.Searches[q]})
	}
	repos := make([]trendRepo, 0, 8)
	for _, r := range topN(s.hist.Repos, 8) {
		repos = append(repos, trendRepo{Repo: r, Hits: s.hist.Repos[r]})
	}
	writeJSON(w, 200, map[string]any{"searches": searches, "repos": repos})
}

// unusedTrendingResp removes the old placeholder shape.
type searchResp struct {
	Query      string         `json:"query"`
	TotalCount int            `json:"totalCount"`
	Page       int            `json:"page"`
	PerPage    int            `json:"perPage"`
	OS         *string        `json:"os"`
	Sort       string         `json:"sort"`
	Binaries   bool           `json:"binaries"`
	Active     bool           `json:"active"`
	MinStars   int            `json:"minStars"`
	OSCounts   map[string]int `json:"osCounts"`
	Warning    *string        `json:"warning"`
	Results    []EnrichedRepo `json:"results"`
}

var validOS = map[string]bool{"windows": true, "macos": true, "linux": true, "android": true, "ios": true}

var mimeTypes = map[string]string{
	".html": "text/html; charset=utf-8",
	".js":   "text/javascript; charset=utf-8",
	".css":  "text/css; charset=utf-8",
	".svg":  "image/svg+xml",
	".png":  "image/png",
	".ico":  "image/x-icon",
	".json": "application/json",
}

type server struct {
	gh        *ghClient
	publicDir string
	now       func() time.Time
	// dataDir hosts history.json (the local trending source).
	dataDir string
	histMu  sync.Mutex
	hist    history
}

// history is the local trending source: search-query and repo-open hit
// counts, persisted to <dataDir>/history.json. Purely local — the former
// SQLite analytics stayed server-side; this never leaves the machine.
type history struct {
	Searches map[string]int `json:"searches"`
	Repos    map[string]int `json:"repos"`
}

// trendQuery/trendRepo mirror what the frontend's trending chips render.
type trendQuery struct {
	Query string `json:"query"`
	Hits  int    `json:"hits"`
}
type trendRepo struct {
	Repo string `json:"repo"`
	Hits int    `json:"hits"`
}

// maxHistoryEntries bounds each map so a long-lived run cannot grow it
// forever; pruning keeps the most-used entries.
const maxHistoryEntries = 200

func (s *server) loadHistory() {
	s.hist = history{Searches: map[string]int{}, Repos: map[string]int{}}
	data, err := os.ReadFile(filepath.Join(s.dataDir, "history.json"))
	if err == nil {
		_ = json.Unmarshal(data, &s.hist)
	}
	if s.hist.Searches == nil {
		s.hist.Searches = map[string]int{}
	}
	if s.hist.Repos == nil {
		s.hist.Repos = map[string]int{}
	}
}

func (s *server) saveHistory() {
	data, err := json.Marshal(s.hist)
	if err != nil {
		return
	}
	_ = os.MkdirAll(s.dataDir, 0o755)
	tmp := filepath.Join(s.dataDir, "history.json.tmp")
	if os.WriteFile(tmp, data, 0o644) == nil {
		_ = os.Rename(tmp, filepath.Join(s.dataDir, "history.json"))
	}
}

// recordHit bumps a counter map and prunes it to the top N when it overflows.
func recordHit(m map[string]int, key string) {
	if key == "" {
		return
	}
	m[key]++
	if len(m) <= maxHistoryEntries*2 {
		return
	}
	type kv struct {
		k string
		v int
	}
	all := make([]kv, 0, len(m))
	for k, v := range m {
		all = append(all, kv{k, v})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].v > all[j].v })
	clear(m)
	for _, e := range all[:maxHistoryEntries] {
		m[e.k] = e.v
	}
}

// topN returns the most-hit keys, descending.
func topN(m map[string]int, n int) []string {
	type kv struct {
		k string
		v int
	}
	all := make([]kv, 0, len(m))
	for k, v := range m {
		all = append(all, kv{k, v})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].v != all[j].v {
			return all[i].v > all[j].v
		}
		return all[i].k < all[j].k
	})
	out := make([]string, 0, n)
	for _, e := range all {
		if len(out) >= n {
			break
		}
		out = append(out, e.k)
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *server) handler(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/api/search":
		s.handleSearch(w, r)
	case r.URL.Path == "/api/track" && r.Method == http.MethodPost:
		s.handleTrack(w, r)
	case r.URL.Path == "/api/trending":
		s.handleTrending(w)
	case r.URL.Path == "/api/health":
		writeJSON(w, 200, okResp{OK: true})
	case r.URL.Path == "/api/platform":
		writeJSON(w, 200, map[string]any{
			"os": runtime.GOOS, "dialogs": dialogsSupported(),
			"appdeck": launcherURL() != "", "launcher": launcherURL(),
		})
	case r.URL.Path == "/api/appdeck/install" && r.Method == http.MethodPost:
		s.handleAppDeckInstall(w, r)
	case r.URL.Path == "/api/appdeck/install" && r.Method == http.MethodGet:
		s.handleAppDeckInstallStatus(w, r)
	case r.URL.Path == "/api/appdeck/install/cancel" && r.Method == http.MethodPost:
		s.handleAppDeckInstallCancel(w, r)
	case r.URL.Path == "/api/user-repos":
		s.handleUserRepos(w, r)
	case r.URL.Path == "/api/download":
		s.handleDownloadProxy(w, r)
	case r.URL.Path == "/api/save" && r.Method == http.MethodPost:
		s.handleSave(w, r)
	case r.URL.Path == "/api/pick-folder" && r.Method == http.MethodPost:
		s.handlePickFolder(w, r)
	case r.URL.Path == "/api/pick-file" && r.Method == http.MethodPost:
		s.handlePickFile(w, r)
	case r.URL.Path == "/api/open" && r.Method == http.MethodPost:
		s.handleOpen(w, r)
	case r.URL.Path == "/api/batch" && r.Method == http.MethodPost:
		s.handleBatch(w, r)
	case r.URL.Path == "/api/job":
		s.handleJobStatus(w, r)
	case r.URL.Path == "/api/job/cancel" && r.Method == http.MethodPost:
		s.handleJobCancel(w, r)
	default:
		s.serveStatic(w, r)
	}
}

type userRepoResp struct {
	User      string     `json:"user"`
	Total     int        `json:"total"`
	Truncated bool       `json:"truncated"`
	Repos     []userRepo `json:"repos"`
}

type userRepo struct {
	Name          string `json:"name"`
	FullName      string `json:"fullName"`
	DefaultBranch string `json:"defaultBranch"`
	Description   string `json:"description"`
	HTMLURL       string `json:"htmlUrl"`
	Stars         int    `json:"stars"`
	Fork          bool   `json:"fork"`
	Archived      bool   `json:"archived"`
	PushedAt      string `json:"pushedAt"`
	SizeKB        int    `json:"sizeKb"`
}

func (s *server) handleUserRepos(w http.ResponseWriter, req *http.Request) {
	user := strings.TrimSpace(req.URL.Query().Get("user"))
	repos, truncated, err := s.gh.listUserRepos(user, 3)
	if err != nil {
		s.writeGHErr(w, err)
		return
	}
	out := make([]userRepo, 0, len(repos))
	for _, r := range repos {
		out = append(out, userRepo{
			Name:          r.Name,
			FullName:      r.FullName,
			DefaultBranch: r.DefaultBranch,
			Description:   r.Description,
			HTMLURL:       r.HTMLURL,
			Stars:         r.Stars,
			Fork:          r.Fork,
			Archived:      r.Archived,
			PushedAt:      r.PushedAt,
			SizeKB:        r.SizeKB,
		})
	}
	writeJSON(w, 200, userRepoResp{User: user, Total: len(out), Truncated: truncated, Repos: out})
}

func (s *server) writeGHErr(w http.ResponseWriter, err error) {
	status := 500
	if ge, ok := err.(*GitHubError); ok {
		status = ge.Status
		if status == 0 {
			status = 500
		}
	}
	if status == 500 {
		fmt.Fprintln(os.Stderr, err.Error())
	}
	writeJSON(w, status, errResp{Error: err.Error()})
}

const perPage = 25

func (s *server) handleSearch(w http.ResponseWriter, req *http.Request) {
	q := strings.TrimSpace(req.URL.Query().Get("q"))
	osParam := req.URL.Query().Get("os")
	osFilter := osParam
	if osParam == "all" {
		osFilter = "" // 'all' is the UI's "no OS filter"
	}
	sortParam := req.URL.Query().Get("sort")
	if sortParam == "" {
		sortParam = "best"
	}
	page := 1
	if p, err := strconv.Atoi(req.URL.Query().Get("page")); err == nil && p > page {
		page = p
	}
	binaries := isTruthy(req.URL.Query().Get("binaries"))
	active := isTruthy(req.URL.Query().Get("active"))
	minStars := 0
	if n, err := strconv.Atoi(req.URL.Query().Get("stars")); err == nil && n > minStars {
		minStars = n
	}

	if q == "" {
		writeJSON(w, 400, errResp{Error: "Missing search query (?q=)."})
		return
	}
	if osFilter != "" && !validOS[osFilter] {
		writeJSON(w, 400, errResp{Error: "Invalid os filter: " + osFilter})
		return
	}

	data, err := s.gh.searchRepos(q+" in:name,description,topics", page, perPage)
	if err != nil {
		s.writeGHErr(w, err)
		return
	}
	if len(data.Items) == 0 {
		// Broaden the match into READMEs before giving up.
		if data2, err2 := s.gh.searchRepos(q+" in:name,description,topics,readme", page, perPage); err2 == nil {
			data = data2
		}
	}

	items := data.Items
	// Quality filters run BEFORE enrichment (stars/activity come with the
	// search response), so filtered-out repos cost zero extra API calls.
	if minStars > 0 {
		var kept []ghRepo
		for _, it := range items {
			if it.StargazersCount >= minStars {
				kept = append(kept, it)
			}
		}
		items = kept
	}
	if active {
		var kept []ghRepo
		cutoff := s.now().Add(-365 * 24 * time.Hour)
		for _, it := range items {
			if !it.Archived && it.PushedAt != "" && parseTime(it.PushedAt).After(cutoff) {
				kept = append(kept, it)
			}
		}
		items = kept
	}

	results := enrichRepos(s.gh, items)

	shown := results
	if binaries {
		var withBins []EnrichedRepo
		for _, r := range results {
			if len(r.OSes) > 0 {
				withBins = append(withBins, r)
			}
		}
		if len(withBins) > 0 { // fall back to all rather than a blank page
			shown = withBins
		}
	}

	// Per-OS availability counts over the binaries-filtered set, so the chips
	// describe exactly the list the user sees.
	osCounts := map[string]int{}
	for _, r := range shown {
		for _, o := range r.OSes {
			osCounts[o]++
		}
	}

	if osFilter != "" {
		var withOs []EnrichedRepo
		for _, r := range shown {
			if containsStr(r.OSes, osFilter) {
				withOs = append(withOs, r)
			}
		}
		if len(withOs) > 0 {
			shown = withOs
		}
	}

	switch sortParam {
	case "downloads":
		sort.SliceStable(shown, func(i, j int) bool {
			return downloadKey(shown[i], osFilter) > downloadKey(shown[j], osFilter)
		})
	case "stars":
		sort.SliceStable(shown, func(i, j int) bool { return shown[i].Stars > shown[j].Stars })
	case "activity":
		sort.SliceStable(shown, func(i, j int) bool {
			return parseTime(shown[i].PushedAt).After(parseTime(shown[j].PushedAt))
		})
	} // 'best' keeps GitHub's relevance order

	degraded := 0
	for _, r := range results {
		if r.EnrichError != "" {
			degraded++
		}
	}
	var warning *string
	if degraded == len(results) && len(results) > 0 {
		msg := "Release stats are unavailable right now (GitHub API limit). Showing results without download data — try again soon or set GITHUB_TOKEN."
		warning = &msg
	} else if degraded > 0 {
		msg := "Some release stats are unavailable (GitHub API limit)."
		warning = &msg
	}

	var osResp *string
	if osFilter != "" {
		osResp = &osFilter
	}

	writeJSON(w, 200, searchResp{
		Query:      q,
		TotalCount: data.TotalCount,
		Page:       page,
		PerPage:    perPage,
		OS:         osResp,
		Sort:       sortParam,
		Binaries:   binaries,
		Active:     active,
		MinStars:   minStars,
		OSCounts:   osCounts,
		Warning:    warning,
		Results:    shown,
	})
}

func (s *server) handleTrack(w http.ResponseWriter, req *http.Request) {
	body, err := io.ReadAll(io.LimitReader(req.Body, 10240+1))
	if err != nil || len(body) > 10240 {
		writeJSON(w, 400, errResp{Error: "Invalid tracking payload"})
		return
	}
	var payload struct {
		Type   string `json:"type"`
		Repo   string `json:"repo"`
		Action string `json:"action"`
		Query  string `json:"query"`
	}
	if json.Unmarshal(body, &payload) != nil {
		writeJSON(w, 400, errResp{Error: "Invalid tracking payload"})
		return
	}
	// Local history only: powers the trending chips ("from your recent
	// searches"). Nothing leaves the machine; counts persist in history.json.
	s.histMu.Lock()
	recordHit(s.hist.Repos, payload.Repo)
	recordHit(s.hist.Searches, payload.Query)
	s.saveHistory()
	s.histMu.Unlock()
	writeJSON(w, 200, okResp{OK: true})
}

func (s *server) serveStatic(w http.ResponseWriter, req *http.Request) {
	rel := req.URL.Path
	if rel == "" || rel == "/" {
		rel = "/index.html"
	}
	clean := strings.TrimPrefix(path.Clean(rel), "/")
	full := filepath.Join(s.publicDir, filepath.FromSlash(clean))
	if full != s.publicDir && !strings.HasPrefix(full, s.publicDir+string(os.PathSeparator)) {
		writeJSON(w, 403, errResp{Error: "Forbidden"})
		return
	}
	data, err := os.ReadFile(full)
	if err != nil {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(404)
		_, _ = w.Write([]byte("Not found"))
		return
	}
	ct := mimeTypes[strings.ToLower(filepath.Ext(full))]
	if ct == "" {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(data)
}

func containsStr(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func isTruthy(v string) bool {
	return v == "1" || v == "true"
}

func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func downloadKey(r EnrichedRepo, osFilter string) int64 {
	if osFilter != "" {
		return r.DownloadsByOS[osFilter]
	}
	return r.TotalDownloads
}

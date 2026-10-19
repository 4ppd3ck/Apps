package main

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultSearchTTL   = 10 * time.Minute
	defaultReleasesTTL = 30 * time.Minute
	maxDiskEntries     = 400
	apiTimeout         = 15 * time.Second
)

// GitHubError mirrors the Node GitHubError: a message plus an HTTP status to
// relay to the client (404/429/502/...).
type GitHubError struct {
	Status  int
	Message string
}

func (e *GitHubError) Error() string { return e.Message }

type cacheEntry struct {
	Path    string          `json:"path"`
	Etag    string          `json:"etag"`
	Data    json.RawMessage `json:"data"`
	SavedAt int64           `json:"savedAt"`
}

type ghClient struct {
	apiRoot     string
	token       string
	cacheDir    string
	searchTTL   time.Duration
	releasesTTL time.Duration
	hc          *http.Client

	mu  sync.Mutex
	mem map[string]*cacheEntry
}

func newGHClient(dataDir, token string) *ghClient {
	apiRoot := os.Getenv("GITHUB_API_ROOT")
	if apiRoot == "" {
		apiRoot = "https://api.github.com"
	}
	searchTTL := defaultSearchTTL
	if v := os.Getenv("SEARCH_TTL_MS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			searchTTL = time.Duration(n) * time.Millisecond
		}
	}
	releasesTTL := defaultReleasesTTL
	if v := os.Getenv("RELEASES_TTL_MS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			releasesTTL = time.Duration(n) * time.Millisecond
		}
	}
	return &ghClient{
		apiRoot:     strings.TrimRight(apiRoot, "/"),
		token:       token,
		cacheDir:    filepath.Join(dataDir, "cache"),
		searchTTL:   searchTTL,
		releasesTTL: releasesTTL,
		hc:          newHTTPClient(apiTimeout),
		mem:         map[string]*cacheEntry{},
	}
}

func (c *ghClient) cacheFile(p string) string {
	sum := sha1.Sum([]byte(p))
	return filepath.Join(c.cacheDir, hex.EncodeToString(sum[:])+".json")
}

func (c *ghClient) readEntry(p string) *cacheEntry {
	c.mu.Lock()
	if e, ok := c.mem[p]; ok {
		c.mu.Unlock()
		return e
	}
	c.mu.Unlock()

	raw, err := os.ReadFile(c.cacheFile(p))
	if err != nil {
		return nil
	}
	var e cacheEntry
	if json.Unmarshal(raw, &e) != nil || len(e.Data) == 0 {
		return nil
	}
	c.mu.Lock()
	c.mem[p] = &e
	c.mu.Unlock()
	return &e
}

func (c *ghClient) writeEntry(e *cacheEntry) {
	c.mu.Lock()
	c.mem[e.Path] = e
	c.mu.Unlock()

	if err := os.MkdirAll(c.cacheDir, 0o755); err != nil {
		return
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return
	}
	file := c.cacheFile(e.Path)
	tmp := file + ".tmp"
	if os.WriteFile(tmp, raw, 0o644) == nil {
		_ = os.Rename(tmp, file)
	}
	c.evictOld()
}

func (c *ghClient) evictOld() {
	entries, err := os.ReadDir(c.cacheDir)
	if err != nil {
		return
	}
	type f struct {
		path string
		mod  time.Time
	}
	var files []f
	for _, de := range entries {
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".json") {
			continue
		}
		info, err := de.Info()
		if err != nil {
			continue
		}
		files = append(files, f{filepath.Join(c.cacheDir, de.Name()), info.ModTime()})
	}
	if len(files) <= maxDiskEntries {
		return
	}
	sort.Slice(files, func(i, j int) bool { return files[i].mod.Before(files[j].mod) })
	for _, x := range files[:len(files)-maxDiskEntries] {
		_ = os.Remove(x.path)
	}
}

func (c *ghClient) ghGet(p string, ttl time.Duration, dst any) error {
	entry := c.readEntry(p)
	if entry != nil && time.Since(time.UnixMilli(entry.SavedAt)) < ttl {
		return json.Unmarshal(entry.Data, dst)
	}

	req, err := http.NewRequest(http.MethodGet, c.apiRoot+p, nil)
	if err != nil {
		return &GitHubError{Status: 502, Message: err.Error()}
	}
	req.Header.Set("User-Agent", "RepoLens/0.2")
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if entry != nil && entry.Etag != "" {
		req.Header.Set("If-None-Match", entry.Etag)
	}

	res, err := c.hc.Do(req)
	if err != nil {
		if entry != nil {
			return json.Unmarshal(entry.Data, dst)
		}
		return &GitHubError{Status: 502, Message: "Could not reach the GitHub API: " + err.Error()}
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusNotModified && entry != nil {
		entry.SavedAt = time.Now().UnixMilli()
		c.writeEntry(entry)
		return json.Unmarshal(entry.Data, dst)
	}

	if res.StatusCode == 403 || res.StatusCode == 429 {
		if res.Header.Get("x-ratelimit-remaining") == "0" && entry != nil {
			return json.Unmarshal(entry.Data, dst)
		}
		waitMin := 1
		if reset := res.Header.Get("x-ratelimit-reset"); reset != "" {
			if secs, err := strconv.ParseInt(reset, 10, 64); err == nil {
				waitMin = int(math.Ceil(float64(secs*1000-time.Now().UnixMilli()) / 60000.0))
				if waitMin < 1 {
					waitMin = 1
				}
			}
		}
		msg := fmt.Sprintf("GitHub API rate limit reached — resets in ~%d min. ", waitMin)
		if c.token == "" {
			msg += "Set GITHUB_TOKEN (see .env.example) for 5,000 requests/hour."
		}
		return &GitHubError{Status: 429, Message: msg}
	}

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		if entry != nil && res.StatusCode >= 500 {
			return json.Unmarshal(entry.Data, dst)
		}
		status := 502
		if res.StatusCode == 404 {
			status = 404
		}
		return &GitHubError{Status: status, Message: fmt.Sprintf("GitHub API error %d", res.StatusCode)}
	}

	body, err := io.ReadAll(io.LimitReader(res.Body, 32<<20))
	if err != nil {
		return &GitHubError{Status: 502, Message: "Could not read GitHub API response: " + err.Error()}
	}

	e := &cacheEntry{Path: p, Etag: res.Header.Get("etag"), Data: json.RawMessage(body), SavedAt: time.Now().UnixMilli()}
	c.writeEntry(e)
	return json.Unmarshal(e.Data, dst)
}

type ghOwner struct {
	Login     string `json:"login"`
	AvatarURL string `json:"avatar_url"`
}

type ghLicense struct {
	SPDXID string `json:"spdx_id"`
	Name   string `json:"name"`
}

type ghRepo struct {
	FullName        string     `json:"full_name"`
	Name            string     `json:"name"`
	Owner           ghOwner    `json:"owner"`
	Description     string     `json:"description"`
	HTMLURL         string     `json:"html_url"`
	Homepage        string     `json:"homepage"`
	StargazersCount int        `json:"stargazers_count"`
	ForksCount      int        `json:"forks_count"`
	Language        string     `json:"language"`
	License         *ghLicense `json:"license"`
	PushedAt        string     `json:"pushed_at"`
	OpenIssuesCount int        `json:"open_issues_count"`
	Topics          []string   `json:"topics"`
	Archived        bool       `json:"archived"`
}

type searchResponse struct {
	TotalCount int      `json:"total_count"`
	Items      []ghRepo `json:"items"`
}

type ReleaseAsset struct {
	Name               string `json:"name"`
	Size               int64  `json:"size"`
	DownloadCount      int64  `json:"download_count"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

type Release struct {
	TagName     string         `json:"tag_name"`
	Name        string         `json:"name"`
	PublishedAt string         `json:"published_at"`
	Prerelease  bool           `json:"prerelease"`
	Draft       bool           `json:"draft"`
	HTMLURL     string         `json:"html_url"`
	Assets      []ReleaseAsset `json:"assets"`
}

func (c *ghClient) searchRepos(q string, page, perPage int) (*searchResponse, error) {
	p := fmt.Sprintf("/search/repositories?q=%s&per_page=%d&page=%d", url.QueryEscape(q), perPage, page)
	var out searchResponse
	if err := c.ghGet(p, c.searchTTL, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *ghClient) listReleases(owner, repo string) ([]Release, error) {
	p := fmt.Sprintf("/repos/%s/%s/releases?per_page=100", url.PathEscape(owner), url.PathEscape(repo))
	var out []Release
	if err := c.ghGet(p, c.releasesTTL, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ghUserRepo is the trimmed repo shape used by the bulk-download list.
type ghUserRepo struct {
	Name          string `json:"name"`
	FullName      string `json:"full_name"`
	DefaultBranch string `json:"default_branch"`
	Description   string `json:"description"`
	Fork          bool   `json:"fork"`
	Stars         int    `json:"stargazers_count"`
	PushedAt      string `json:"pushed_at"`
	Archived      bool   `json:"archived"`
	SizeKB        int    `json:"size"`
	HTMLURL       string `json:"html_url"`
}

var userLoginRE = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$`)

// listUserRepos pages through a user's (or org's) public repos, sorted by
// last push, up to maxPages×100 entries.
func (c *ghClient) listUserRepos(user string, maxPages int) ([]ghUserRepo, bool, error) {
	user = strings.ToLower(strings.TrimSpace(user))
	if !userLoginRE.MatchString(user) {
		return nil, false, &GitHubError{Status: 400, Message: "That doesn't look like a GitHub username."}
	}
	fetch := func(root string) ([]ghUserRepo, bool, error) {
		var all []ghUserRepo
		for page := 1; page <= maxPages; page++ {
			p := fmt.Sprintf("%s/%s/repos?per_page=100&sort=pushed&page=%d", root, url.PathEscape(user), page)
			var batch []ghUserRepo
			if err := c.ghGet(p, c.searchTTL, &batch); err != nil {
				return nil, false, err
			}
			all = append(all, batch...)
			if len(batch) < 100 {
				return all, false, nil
			}
		}
		return all, true, nil
	}
	repos, truncated, err := fetch("/users")
	if err != nil {
		// usernames resolve via /users, orgs only via /orgs
		if ge, ok := err.(*GitHubError); ok && ge.Status == 404 {
			repos, truncated, err = fetch("/orgs")
		}
	}
	if err != nil {
		return nil, false, err
	}
	sort.Slice(repos, func(i, j int) bool {
		return parseTime(repos[i].PushedAt).After(parseTime(repos[j].PushedAt))
	})
	return repos, truncated, nil
}

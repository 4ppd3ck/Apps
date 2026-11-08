package main

// Git-backed intel-feed sources: shallow-clone a repository once and keep it
// current, then read the list file out of the working tree. Uses the git CLI
// (like wPurge shells out to plutil/pgrep) to keep the stdlib-only build.
// Ported from the former wGrid app.

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const gitTimeout = 60 * time.Second

func gitAvailable() bool {
	_, err := exec.LookPath("git")
	return err == nil
}

// repoSlug maps a source to a stable clone directory under data/repos/.
func repoSlug(s Source) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s.Name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	h := sha256.Sum256([]byte(s.kind() + "|" + s.URL))
	slug := strings.Trim(b.String(), "-")
	if len(slug) > 40 {
		slug = slug[:40]
	}
	return fmt.Sprintf("%s-%x", slug, h[:4])
}

func within(root, p string) bool {
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// gitRepoFile ensures the shallow clone of s.URL exists and is current, then
// returns the bytes of s.Path inside the working tree.
func gitRepoFile(s Source, reposDir string) ([]byte, error) {
	if !gitAvailable() {
		return nil, fmt.Errorf("git not found in PATH — install git to use git-backed sources")
	}
	if strings.TrimSpace(s.URL) == "" {
		return nil, fmt.Errorf("git source %q: url (repository) required", s.Name)
	}
	if strings.TrimSpace(s.Path) == "" {
		return nil, fmt.Errorf("git source %q: path (list file inside the repo) required", s.Name)
	}
	if err := os.MkdirAll(reposDir, 0o755); err != nil {
		return nil, err
	}
	repo := filepath.Join(reposDir, repoSlug(s))
	if _, err := os.Stat(filepath.Join(repo, ".git")); err != nil {
		args := []string{"clone", "--depth", "1", "--quiet"}
		if s.Branch != "" {
			args = append(args, "--branch", s.Branch, "--single-branch")
		}
		args = append(args, s.URL, repo)
		if out, err := runGit(args, s.URL); err != nil {
			os.RemoveAll(repo) // a partial clone must not poison the next attempt
			// Some transports (plain local paths, restricted hosts) refuse
			// shallow clones — retry once with full history.
			if out2, err2 := runGit([]string{"clone", "--quiet", s.URL, repo}, s.URL); err2 != nil {
				os.RemoveAll(repo)
				return nil, fmt.Errorf("clone %s: %s: %s", s.URL, err2, tailOut(out2))
			}
			_ = out
		}
	} else {
		ref := "HEAD"
		if s.Branch != "" {
			ref = s.Branch
		}
		if out, err := runGit([]string{"-C", repo, "fetch", "--depth", "1", "--quiet", "origin", ref}, s.URL); err != nil {
			return nil, fmt.Errorf("fetch %s: %s: %s", s.URL, err, tailOut(out))
		}
		if out, err := runGit([]string{"-C", repo, "reset", "--hard", "--quiet", "FETCH_HEAD"}, s.URL); err != nil {
			return nil, fmt.Errorf("update %s: %s: %s", s.URL, err, tailOut(out))
		}
	}
	target := filepath.Join(repo, s.Path)
	if !within(repo, target) {
		return nil, fmt.Errorf("git source %q: path %q escapes the repository", s.Name, s.Path)
	}
	raw, err := os.ReadFile(target)
	if err != nil {
		return nil, fmt.Errorf("read %s in %s: %w", s.Path, s.URL, err)
	}
	return raw, nil
}

func runGit(args []string, url string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), gitTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", args...)
	// Belt and braces beside the https-only validation: whatever URL slips
	// through, git may only speak the transport the configured URL itself
	// names — never run an ext:: helper, never stop to ask for credentials
	// (this process has no terminal). In practice that is always https;
	// file:// is the one extra admission (see gitProtocolLock).
	cmd.Env = append(os.Environ(),
		"GIT_TERMINAL_PROMPT=0",
		gitProtocolLock(url),
	)
	out, err := cmd.CombinedOutput()
	return tailOut(string(out)), err
}

// gitProtocolLock pins GIT_ALLOW_PROTOCOL to the scheme of the configured
// URL. validateSource admits only https:// git sources through the API, so
// dashboard-added sources are always locked to https. A file:// URL can
// only arrive via a hand-edited sources.json — the same trust level as a
// "file"-type source, which already reads arbitrary local paths — and
// allowing the file transport there keeps local repos (and the TestGitSource
// coverage of the clone/read path) working. Anything else stays https-only,
// so ssh can never probe the LAN and ext:: helpers can never run.
func gitProtocolLock(url string) string {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(url)), "file://") {
		return "GIT_ALLOW_PROTOCOL=file"
	}
	return "GIT_ALLOW_PROTOCOL=https"
}

func tailOut(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 400 {
		s = s[:400] + "…"
	}
	return s
}

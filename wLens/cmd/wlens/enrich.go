package main

import (
	"sync"
)

type LatestRelease struct {
	Tag         string `json:"tag"`
	URL         string `json:"url"`
	PublishedAt string `json:"publishedAt"`
	Prerelease  bool   `json:"prerelease"`
}

type LatestAsset struct {
	Name      string `json:"name"`
	OS        string `json:"os"`
	Size      int64  `json:"size"`
	Downloads int64  `json:"downloads"`
	URL       string `json:"url"`
}

type EnrichedRepo struct {
	FullName       string           `json:"fullName"`
	Name           string           `json:"name"`
	Owner          string           `json:"owner"`
	AvatarURL      string           `json:"avatarUrl"`
	Description    string           `json:"description"`
	HTMLURL        string           `json:"htmlUrl"`
	Homepage       string           `json:"homepage"`
	Stars          int              `json:"stars"`
	Forks          int              `json:"forks"`
	Language       string           `json:"language"`
	License        string           `json:"license"`
	PushedAt       string           `json:"pushedAt"`
	OpenIssues     int              `json:"openIssues"`
	Topics         []string         `json:"topics"`
	Archived       bool             `json:"archived"`
	LatestTag      string           `json:"latestTag,omitempty"`
	TotalDownloads int64            `json:"totalDownloads"`
	DownloadsByOS  map[string]int64 `json:"downloadsByOs"`
	OSes           []string         `json:"oses"`
	LatestRelease  *LatestRelease   `json:"latestRelease"`
	LatestAssets   []LatestAsset    `json:"latestAssets"`
	ReleasesCount  int              `json:"releasesCount"`
	EnrichError    string           `json:"enrichError,omitempty"`
}

// enrichRepos runs enrichOne over items with bounded concurrency (6), keeping
// result order.
func enrichRepos(c *ghClient, items []ghRepo) []EnrichedRepo {
	out := make([]EnrichedRepo, len(items))
	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	for i := range items {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i] = enrichOne(c, items[i])
		}(i)
	}
	wg.Wait()
	return out
}

func enrichOne(c *ghClient, repo ghRepo) EnrichedRepo {
	r := EnrichedRepo{
		FullName:      repo.FullName,
		Name:          repo.Name,
		Owner:         repo.Owner.Login,
		AvatarURL:     repo.Owner.AvatarURL,
		Description:   repo.Description,
		HTMLURL:       repo.HTMLURL,
		Homepage:      repo.Homepage,
		Stars:         repo.StargazersCount,
		Forks:         repo.ForksCount,
		Language:      repo.Language,
		PushedAt:      repo.PushedAt,
		OpenIssues:    repo.OpenIssuesCount,
		Archived:      repo.Archived,
		DownloadsByOS: map[string]int64{},
		OSes:          []string{},
		LatestAssets:  []LatestAsset{},
	}
	r.Topics = repo.Topics
	if r.Topics == nil {
		r.Topics = []string{}
	}
	if repo.License != nil {
		if repo.License.SPDXID != "" && repo.License.SPDXID != "NOASSERTION" {
			r.License = repo.License.SPDXID
		} else {
			r.License = repo.License.Name
		}
	}

	releases, err := c.listReleases(repo.Owner.Login, repo.Name)
	if err != nil {
		r.EnrichError = err.Error()
		return r
	}

	var visible []Release
	for _, rel := range releases {
		if !rel.Draft {
			visible = append(visible, rel)
		}
	}
	r.ReleasesCount = len(visible)

	for _, rel := range visible {
		for _, a := range rel.Assets {
			osName := detectOS(a.Name)
			r.TotalDownloads += a.DownloadCount
			if osName != "" {
				r.DownloadsByOS[osName] += a.DownloadCount
				if !containsStr(r.OSes, osName) {
					r.OSes = append(r.OSes, osName)
				}
			}
		}
	}

	var latest *Release
	for i := range visible {
		if !visible[i].Prerelease {
			latest = &visible[i]
			break
		}
	}
	if latest == nil && len(visible) > 0 {
		latest = &visible[0]
	}
	if latest != nil {
		r.LatestTag = latest.TagName
		r.LatestRelease = &LatestRelease{
			Tag:         latest.TagName,
			URL:         latest.HTMLURL,
			PublishedAt: latest.PublishedAt,
			Prerelease:  latest.Prerelease,
		}
		for _, a := range latest.Assets {
			osName := detectOS(a.Name)
			if osName == "" {
				continue
			}
			r.LatestAssets = append(r.LatestAssets, LatestAsset{
				Name:      a.Name,
				OS:        osName,
				Size:      a.Size,
				Downloads: a.DownloadCount,
				URL:       a.BrowserDownloadURL,
			})
		}
	}
	return r
}

package main

// sources.json persistence and the add/remove-source operations behind the
// dashboard. Two file shapes are understood:
//
//	[ …sources ]                      legacy array: replaces the defaults
//	{"replace":bool,"sources":[…]}    object form; replace=false merges with
//	                                  the code defaults (deduped by name+url)
//
// The object form also carries a "removed" list: defaults the user deleted
// in the dashboard, filtered back out on load so defaults stay code-owned
// yet deletable. The dashboard writes object form with replace=false
// containing only user-added sources.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const maxSources = 64

type sourcesFile struct {
	Replace bool     `json:"replace"`
	Sources []Source `json:"sources"`
	Removed []Source `json:"removed,omitempty"`
	legacy  bool     `json:"-"`
}

func (it *Intel) sourcesPath() string { return filepath.Join(it.dataDir, "sources.json") }

func (it *Intel) loadSources() {
	raw, err := os.ReadFile(it.sourcesPath())
	if err != nil {
		return
	}
	obj := parseSourcesFile(raw)
	if obj == nil || (len(obj.Sources) == 0 && len(obj.Removed) == 0) {
		return
	}
	list := dedupeSources(obj.Sources)
	if obj.Replace {
		it.mu.Lock()
		it.sources = list
		it.mu.Unlock()
		return
	}
	it.mu.Lock()
	it.sources = dedupeSources(append(DefaultSources(), list...))
	for _, r := range obj.Removed { // user-deleted defaults stay deleted
		kept := make([]Source, 0, len(it.sources))
		for _, s := range it.sources {
			if !sameSource(s, r) {
				kept = append(kept, s)
			}
		}
		it.sources = kept
	}
	it.mu.Unlock()
}

// parseSourcesFile decodes both shapes; nil when the file holds nothing usable.
func parseSourcesFile(raw []byte) *sourcesFile {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil
	}
	var obj sourcesFile
	if json.Unmarshal(raw, &obj) == nil && (obj.Sources != nil || obj.Removed != nil) {
		return &obj
	}
	var arr []Source
	if json.Unmarshal(raw, &arr) == nil && len(arr) > 0 {
		return &sourcesFile{Replace: true, Sources: arr, legacy: true}
	}
	return nil
}

// SourceView is one effective source as shown in the dashboard.
type SourceView struct {
	Source
	Default bool   `json:"default"`
	Error   string `json:"error,omitempty"`
}

func (it *Intel) SourceViews() []SourceView {
	defs := DefaultSources()
	it.mu.Lock()
	defer it.mu.Unlock()
	out := make([]SourceView, 0, len(it.sources))
	for _, s := range it.sources {
		v := SourceView{Source: s}
		for _, d := range defs {
			if sameSource(d, s) {
				v.Default = true
				break
			}
		}
		v.Error = it.cache.Errors[s.Name+" "+s.displayURL()]
		out = append(out, v)
	}
	return out
}

func validateSource(s Source) error {
	s.Name = strings.TrimSpace(s.Name)
	if s.Name == "" {
		return fmt.Errorf("name is required")
	}
	if len(s.Name) > 80 {
		return fmt.Errorf("name too long (max 80 characters)")
	}
	switch s.Format {
	case "goog", "text", "aws", "csv", "ms365", "github-meta", "fastly":
	default:
		return fmt.Errorf("unknown format %q (supported: goog, text, aws, csv, ms365, github-meta, fastly)", s.Format)
	}
	switch s.kind() {
	case "file":
		if strings.TrimSpace(s.Path) == "" {
			return fmt.Errorf("local file sources need a path")
		}
	case "git":
		if strings.TrimSpace(s.URL) == "" {
			return fmt.Errorf("git sources need a repository url")
		}
		// https only: git's other transports are a liability here. `ext::`
		// runs a shell command (disabled by default in modern git, but one
		// config line re-enables it), `file://` reaches the local filesystem,
		// and ssh:// probes the internal network. This endpoint answers the
		// LAN, so none of those may be reachable from a request.
		if !strings.HasPrefix(s.URL, "https://") {
			return fmt.Errorf("git sources must be an https:// repository url")
		}
		if strings.TrimSpace(s.Path) == "" {
			return fmt.Errorf("git sources need the path of the list inside the repo")
		}
	default:
		if !strings.HasPrefix(s.URL, "http://") && !strings.HasPrefix(s.URL, "https://") {
			return fmt.Errorf("http sources need an http(s) url")
		}
	}
	return nil
}

// AddSource validates a source, persists it to sources.json, then activates
// it in memory. Callers kick off a Refresh afterwards.
func (it *Intel) AddSource(s Source) error {
	if err := validateSource(s); err != nil {
		return err
	}
	it.mu.Lock()
	for _, e := range it.sources {
		if sameSource(e, s) {
			it.mu.Unlock()
			return fmt.Errorf("source %q is already configured", s.Name)
		}
	}
	if len(it.sources) >= maxSources {
		it.mu.Unlock()
		return fmt.Errorf("too many sources (max %d)", maxSources)
	}
	it.mu.Unlock()
	if err := it.persistSourceChange(&s, Source{}); err != nil {
		return err
	}
	it.mu.Lock()
	it.sources = append(it.sources, s)
	it.mu.Unlock()
	return nil
}

// RemoveSource drops a source from memory and sources.json. If no remaining
// source feeds that provider name, the fetched provider is removed from the
// cache so lookups stop matching immediately.
func (it *Intel) RemoveSource(s Source) error {
	it.mu.Lock()
	kept := make([]Source, 0, len(it.sources))
	removed := false
	for _, e := range it.sources {
		if sameSource(e, s) {
			removed = true
			continue
		}
		kept = append(kept, e)
	}
	if removed {
		it.sources = kept
	}
	stillFed := false
	for _, e := range it.sources {
		if e.Name == s.Name {
			stillFed = true
			break
		}
	}
	it.mu.Unlock()
	if !removed {
		return fmt.Errorf("no such source %q", s.Name)
	}
	if err := it.persistSourceChange(nil, s); err != nil {
		it.mu.Lock()
		it.sources = append(it.sources, s)
		it.mu.Unlock()
		return err
	}
	if !stillFed {
		it.mu.Lock()
		out := make([]Provider, 0, len(it.cache.Providers))
		for _, p := range it.cache.Providers {
			if p.Origin == "fetch" && p.Name == s.Name {
				continue
			}
			out = append(out, p)
		}
		it.cache.Providers = out
		delete(it.cache.Errors, s.Name+" "+s.displayURL())
		it.rebuildNetsLocked()
		it.mu.Unlock()
		it.saveCache()
	}
	return nil
}

// persistSourceChange rewrites sources.json, honouring the shape already on
// disk (legacy arrays stay arrays; object form keeps its replace flag; a
// fresh managed file is object form with replace=false). Deleted defaults
// are recorded in the object form's "removed" list so they stay gone across
// restarts while remaining code-owned.
func (it *Intel) persistSourceChange(add *Source, remove Source) error {
	raw, _ := os.ReadFile(it.sourcesPath())
	obj := parseSourcesFile(raw)
	if obj == nil {
		obj = &sourcesFile{}
	}
	if obj.legacy {
		// A hand-written replace-style file: materialise the full effective
		// list so add/remove still works. One-time migration.
		it.mu.Lock()
		obj = &sourcesFile{Replace: true, Sources: append([]Source(nil), it.sources...)}
		it.mu.Unlock()
	}
	if add != nil {
		for _, e := range obj.Sources {
			if sameSource(e, *add) {
				return fmt.Errorf("source %q is already in sources.json", add.Name)
			}
		}
		obj.Sources = append(obj.Sources, *add)
		kept := make([]Source, 0, len(obj.Removed)) // re-adding un-deletes
		for _, r := range obj.Removed {
			if !sameSource(r, *add) {
				kept = append(kept, r)
			}
		}
		obj.Removed = kept
	} else {
		kept := make([]Source, 0, len(obj.Sources))
		removed := false
		for _, e := range obj.Sources {
			if sameSource(e, remove) {
				removed = true
				continue
			}
			kept = append(kept, e)
		}
		if removed {
			obj.Sources = kept
		}
		isDefault := false
		for _, d := range DefaultSources() {
			if sameSource(d, remove) {
				isDefault = true
				break
			}
		}
		if isDefault {
			already := false
			for _, r := range obj.Removed {
				if sameSource(r, remove) {
					already = true
				}
			}
			if !already {
				obj.Removed = append(obj.Removed, remove)
			}
		}
	}
	var out []byte
	var err error
	if obj.legacy {
		out, err = json.MarshalIndent(obj.Sources, "", "  ")
	} else {
		out, err = json.MarshalIndent(obj, "", "  ")
	}
	if err != nil {
		return err
	}
	writeFileAtomic(it.dataDir, "sources.json", out)
	return nil
}

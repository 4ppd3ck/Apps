package main

// Feed data layout + one-time migration from the wTower merge.
//
// Everything the feed persists lives in <APPDECK_DATA>/feed/: cache.json
// (last good provider tables), sources.json (user adds + deleted defaults)
// and repos/ (the shallow git clones of git-backed sources).
//
// MigrateFeedState copies that state from the appdata folders of the apps
// the feed used to live inside — the merged wTower install
// (<APPDECK_DATA>/../wtower/watchdog) and, before that, the standalone
// wHawk app (<APPDECK_DATA>/../whawk) — once, never overwriting. The
// user's sources and the learned cache never move silently: every copied
// file is logged, the originals stay in place, and a partially readable
// source never truncates what already exists here.

import (
	_ "embed"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// feedMigrateFiles is the feed state that carries user intent or learned
// data. Everything else is regenerated.
var feedMigrateFiles = []string{
	"cache.json",   // intel feed's last good provider tables
	"sources.json", // intel feed sources (adds + deleted defaults)
}

// migrateDirs lists the old homes of the feed state, most recent first:
// the wTower merge kept it under watchdog/, the standalone wHawk kept it
// top-level in its appdata folder.
func migrateDirs() []string {
	home := os.Getenv("APPDECK_DATA")
	if home == "" {
		return nil
	}
	// the launcher lays out <data>/appdata/<app-id>; the peers are siblings
	base := filepath.Dir(home)
	return []string{
		filepath.Join(base, "wtower", "watchdog"),
		filepath.Join(base, "whawk"),
	}
}

// MigrateFeedState imports the feed state from the old installs into dir
// (the feed data folder). Idempotent: existing destination files are never
// overwritten, so a partially migrated install keeps whatever it already
// has and a second run is a no-op. Returns the copied file names.
func MigrateFeedState(dir string) []string {
	if dir == "" {
		return nil
	}
	var moved []string
	for _, src := range migrateDirs() {
		if src == dir || src == filepath.Dir(dir) {
			continue // never import from this app's own data dir
		}
		info, err := os.Stat(src)
		if err != nil || !info.IsDir() {
			continue
		}
		for _, name := range feedMigrateFiles {
			dstPath := filepath.Join(dir, name)
			if _, err := os.Stat(dstPath); err == nil {
				continue // already migrated (or in use) — never overwrite
			}
			raw, err := os.ReadFile(filepath.Join(src, name))
			if err != nil {
				continue // absent in the old install, or unreadable: skip
			}
			if err := os.MkdirAll(dir, 0o755); err != nil {
				fmt.Printf("[wgrid] migrate: cannot create %s: %v\n", dir, err)
				return moved
			}
			if err := os.WriteFile(dstPath, raw, 0o644); err != nil {
				fmt.Printf("[wgrid] migrate: %s: %v\n", name, err)
				continue
			}
			moved = append(moved, name)
		}
		// the feed's shallow git clones: wholesale directory copy
		if entries, err := os.ReadDir(filepath.Join(src, "repos")); err == nil &&
			len(entries) > 0 {
			dstRepos := filepath.Join(dir, "repos")
			if _, err := os.Stat(dstRepos); err != nil {
				if err := copyTree(filepath.Join(src, "repos"), dstRepos); err != nil {
					fmt.Printf("[wgrid] migrate: repos: %v\n", err)
				} else {
					moved = append(moved, "repos/")
				}
			}
		}
	}
	if len(moved) > 0 {
		fmt.Printf("[wgrid] migrated feed state: %v\n", moved)
	}
	return moved
}

// copyTree copies a directory recursively (contents only).
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.Create(target)
		if err != nil {
			return err
		}
		defer out.Close()
		_, err = io.Copy(out, in)
		return err
	})
}

// intelSeedJSON is the shipped feed seed (data/intel/sources.json): the
// FireHOL level1 git source ("Block ads (IP)") alongside the code defaults.
// It is written into a fresh feed data folder so a new install keeps
// seeding the same source the merged app shipped.
//
// (embed is imported for this directive only.)
//
//go:embed data/intel/sources.json
var intelSeedJSON []byte

// SeedIntelSources writes the shipped sources.json into dir when the folder
// has none yet (first run). A user-managed sources.json is never touched.
func SeedIntelSources(dir string) {
	if dir == "" {
		return
	}
	path := filepath.Join(dir, "sources.json")
	if _, err := os.Stat(path); err == nil {
		return
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	if err := os.WriteFile(path, intelSeedJSON, 0o644); err != nil {
		fmt.Printf("[wgrid] intel seed: %v\n", err)
	}
}

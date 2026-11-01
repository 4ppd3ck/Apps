package main

// JSON cache persistence (stdlib only) — mirrors wHawk's store.go style.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

func NowF() float64 { return float64(time.Now().UnixNano()) / 1e9 }

func FmtErr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// writeFileAtomic writes dir/name via a .tmp + rename so readers never see a
// torn file.
func writeFileAtomic(dir, name string, raw []byte) {
	_ = os.MkdirAll(dir, 0o755)
	tmp := filepath.Join(dir, name+".tmp")
	if os.WriteFile(tmp, raw, 0o644) == nil {
		_ = os.Rename(tmp, filepath.Join(dir, name))
	}
}

// loadCache reads data/cache.json; true when a usable cache existed.
func (it *Intel) loadCache() bool {
	raw, err := os.ReadFile(filepath.Join(it.dataDir, "cache.json"))
	if err != nil {
		return false
	}
	var c Cache
	if json.Unmarshal(raw, &c) != nil || len(c.Providers) == 0 {
		return false
	}
	it.mu.Lock()
	it.cache = c
	it.mu.Unlock()
	return true
}

func (it *Intel) saveCache() {
	it.mu.Lock()
	c := it.cache
	it.mu.Unlock()
	raw, err := json.MarshalIndent(c, "", " ")
	if err != nil {
		return
	}
	writeFileAtomic(it.dataDir, "cache.json", raw)
}

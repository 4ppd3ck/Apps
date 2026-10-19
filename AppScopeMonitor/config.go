// Configuration loading with platform defaults (mirrors monitor/config.py).
package monitor

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Version mirrors monitor/__init__.py __version__.
const Version = "1.0.1"

var defaultPoll = map[string]any{
	"privacy": 2.0, "network": 3.0, "files": 2.0, "android": 12.0,
	"devices": 5.0, "logins": 5.0, "appfocus": 2.0, "battery": 10.0,
}

// DefaultCollectors mirrors the DEFAULTS["collectors"] section.
// "auto" (android only) -> enabled when adb + a device are present.
var DefaultCollectors = map[string]any{
	"privacy": true, "files": true, "network": true, "devices": true,
	"logins": true, "appfocus": true, "battery": true, "android": "auto",
}

func platformDefaultDirs() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = ""
	}
	join := func(name string) string { return filepath.Join(home, name) }
	dirs := []string{join("Documents"), join("Downloads"), join("Desktop")}
	switch runtime.GOOS {
	case "darwin":
		dirs = append(dirs, "/Volumes")
	case "linux":
		dirs = append(dirs, "/media", "/mnt")
	}
	return dirs
}

// Config mirrors config.Config: a dynamic dict of settings loaded from
// config.json over the built-in defaults.
type Config struct {
	Path string
	Data map[string]any
}

func deepCopyMap(src map[string]any) map[string]any {
	out := make(map[string]any, len(src))
	for k, v := range src {
		if m, ok := v.(map[string]any); ok {
			out[k] = deepCopyMap(m)
		} else {
			out[k] = v
		}
	}
	return out
}

// NewConfig loads (or re-loads) configuration from path.
func NewConfig(path string) *Config {
	c := &Config{Path: path}
	c.Data = map[string]any{
		"host":           "127.0.0.1",
		"port":           8765,
		"data_dir":       "data", // resolved relative to the config file
		"retention_days": 7,
		"watched_dirs":   []any{}, // empty -> platform defaults
		"poll":           deepCopyMap(defaultPoll),
		"collectors":     deepCopyMap(DefaultCollectors),
		"open_browser":   false,
	}
	c.load()
	return c
}

func (c *Config) load() {
	if data, err := os.ReadFile(c.Path); err == nil {
		var fileData map[string]any
		if err := json.Unmarshal(data, &fileData); err != nil {
			fmt.Printf("[config] ignoring bad config %s: %v\n", c.Path, err)
		} else {
			// dict.update(): shallow, top-level replace
			for k, v := range fileData {
				c.Data[k] = v
			}
		}
	}
	if wd := c.WatchedDirs(); len(wd) == 0 {
		c.Data["watched_dirs"] = platformDefaultDirs()
	}
	if poll, ok := c.Data["poll"].(map[string]any); ok {
		for key, val := range defaultPoll {
			if _, exists := poll[key]; !exists {
				poll[key] = val
			}
		}
	}
}

// Save writes the config back as pretty-printed JSON.
func (c *Config) Save() error {
	if dir := filepath.Dir(c.Path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	b, err := json.MarshalIndent(c.Data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(c.Path, b, 0o644)
}

// Get returns a raw setting (mirrors cfg.get(key)).
func (c *Config) Get(key string) (any, bool) {
	v, ok := c.Data[key]
	return v, ok
}

// GetOr returns a raw setting or a default (mirrors cfg.get(key, default)).
func (c *Config) GetOr(key string, def any) any {
	if v, ok := c.Data[key]; ok && v != nil {
		return v
	}
	return def
}

// GetString returns a setting coerced to string (str(cfg.get(key, def))).
func (c *Config) GetString(key, def string) string {
	if v, ok := c.Data[key]; ok && v != nil {
		return StrOf(v)
	}
	return def
}

// GetBool returns a boolean setting (truthiness like Python).
func (c *Config) GetBool(key string, def bool) bool {
	if v, ok := c.Data[key]; ok {
		return Truthy(v)
	}
	return def
}

// Host returns the bind address.
func (c *Config) Host() string { return c.GetString("host", "127.0.0.1") }

// Port returns the bind port.
func (c *Config) Port() int { return IntOr(c.Data["port"], 8765) }

// RetentionDays returns the event retention window in days.
func (c *Config) RetentionDays() int { return IntOr(c.Data["retention_days"], 7) }

// WatchedDirs returns the watched directories as strings.
func (c *Config) WatchedDirs() []string {
	var raw []any
	switch v := c.Data["watched_dirs"].(type) {
	case []any:
		raw = v
	case []string:
		out := make([]string, 0, len(v))
		out = append(out, v...)
		return out
	default:
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		out = append(out, StrOf(item))
	}
	return out
}

// Poll returns one poll interval in seconds (cfg["poll"].get(name, def)).
func (c *Config) Poll(name string, def float64) float64 {
	poll, ok := c.Data["poll"].(map[string]any)
	if !ok {
		return def
	}
	if v, ok := poll[name]; ok {
		if f, ok := ToFloat(v); ok {
			return f
		}
	}
	return def
}

// CollectorsCfg returns the per-category collector toggles.
func (c *Config) CollectorsCfg() map[string]any {
	if m, ok := c.Data["collectors"].(map[string]any); ok {
		return m
	}
	return nil
}

// DataDir resolves the data directory (Path(data_dir).expanduser(), made
// absolute relative to the config file's directory).
func (c *Config) DataDir() string {
	dir := StrOf(c.Data["data_dir"])
	dir = expandUser(dir)
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(filepath.Dir(c.Path), dir)
	}
	return dir
}

func expandUser(path string) string {
	if path == "~" || strings.HasPrefix(path, "~"+string(filepath.Separator)) ||
		strings.HasPrefix(path, "~/") || strings.HasPrefix(path, "~\\") {
		if home, err := os.UserHomeDir(); err == nil {
			if path == "~" {
				return home
			}
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

// LoadConfig mirrors load_config(): default config.json lives in the working
// directory; when absent there we also look next to the executable (which
// emulates Python's PROJECT_DIR resolution for a compiled binary).
func LoadConfig(path string) *Config {
	if path != "" {
		return NewConfig(path)
	}
	// The deck hands every app a private data folder (APPDECK_DATA) — it is
	// the one place guaranteed writable across launch modes, so the config
	// lives there first. (The dashboard's 📂 button opens this folder.)
	candidates := []string{}
	if dataDir := os.Getenv("APPDECK_DATA"); dataDir != "" {
		candidates = append(candidates, filepath.Join(dataDir, "config.json"))
	}
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(exeDir, "config.json"),
			filepath.Join(exeDir, "..", "config.json"),
		)
	}
	candidates = append(candidates,
		filepath.Join("config.json"),
		filepath.Join("..", "config.json"),
	)
	for _, cand := range candidates {
		if _, err := os.Stat(cand); err == nil {
			return NewConfig(cand)
		}
	}
	return NewConfig(candidates[0])
}

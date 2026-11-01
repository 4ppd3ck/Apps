package wtower

import (
	"fmt"
	"sort"
	"strings"
)

// Theme is a data-only palette shared by the dashboard's CSS custom properties.
type Theme struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// ColorScheme tells the browser how to paint native controls (selects,
	// checkboxes, scrollbars): "dark" or "light". Empty only on the auto
	// theme, which resolves it client-side from prefers-color-scheme.
	ColorScheme string `json:"color_scheme,omitempty"`
	// Auto marks the follow-the-system theme: it carries no fixed palette
	// and the dashboard applies Dark or Light per the OS preference.
	Auto   bool              `json:"auto,omitempty"`
	Colors map[string]string `json:"colors,omitempty"`
}

// builtinThemes lists the palettes in selector order. Auto comes first.
// --inset is the recessed well color inside panels (gauge troughs, volume
// bars), --shadow the drop-shadow color, --gloss the highlight sheen over
// colored fills — every other surface derives from the tokens via
// color-mix, so a palette only has to get these 15 values right.
var builtinThemes = []Theme{
	{
		ID: "auto", Name: "Auto", Auto: true,
		Description: "Follow the system light/dark preference.",
	},
	{
		ID: "dark", Name: "Dark", ColorScheme: "dark",
		Description: "wTower's original dark palette.",
		Colors: map[string]string{
			"--bg": "#0d1117", "--panel": "#151b26", "--panel2": "#1a2230",
			"--line": "#263041", "--text": "#dbe4f0", "--dim": "#8494ab",
			"--accent": "#4da3ff", "--green": "#3fd68f", "--red": "#ff6b6b",
			"--amber": "#ffb454", "--purple": "#b18cff", "--cyan": "#4fd6e0",
			"--inset": "#0a0e14", "--shadow": "#0008", "--gloss": "#ffffff2e",
		},
	},
	{
		ID: "netwatch", Name: "Blue", ColorScheme: "dark",
		Description: "A blue-forward palette inspired by NetWatch.",
		Colors: map[string]string{
			"--bg": "#080d16", "--panel": "#101a2a", "--panel2": "#17243a",
			"--line": "#29405c", "--text": "#e1edf9", "--dim": "#91a8c2",
			"--accent": "#47c7e8", "--green": "#62d995", "--red": "#ff6f7d",
			"--amber": "#f5c466", "--purple": "#c09aff", "--cyan": "#53d8e8",
			"--inset": "#070b12", "--shadow": "#0009", "--gloss": "#ffffff2e",
		},
	},
	{
		ID: "light", Name: "Light", ColorScheme: "light",
		Description: "A light palette for bright rooms.",
		Colors: map[string]string{
			"--bg": "#f2f4f8", "--panel": "#ffffff", "--panel2": "#eef1f6",
			"--line": "#d8dde7", "--text": "#1c2430", "--dim": "#5a6577",
			"--accent": "#0e6fd8", "--green": "#0e7a45", "--red": "#b3261e",
			"--amber": "#8a5800", "--purple": "#6d28d9", "--cyan": "#0e7490",
			"--inset": "#dde2ea", "--shadow": "rgba(24,38,64,0.22)",
			"--gloss": "rgba(255,255,255,0.55)",
		},
	},
	{
		ID: "red", Name: "Red", ColorScheme: "dark",
		Description: "A dark palette with warm red surfaces and accents.",
		Colors: map[string]string{
			"--bg": "#130b0d", "--panel": "#1e1216", "--panel2": "#29171c",
			"--line": "#5a2632", "--text": "#f3e7e9", "--dim": "#c08d98",
			"--accent": "#ff5c72", "--green": "#72d6a0", "--red": "#ff667a",
			"--amber": "#f5bd72", "--purple": "#d0a0dc", "--cyan": "#71cbd1",
			"--inset": "#0d0709", "--shadow": "#0008", "--gloss": "#ffffff2e",
		},
	},
}

// Themes returns the built-in palettes in selector order.
func (c *Config) Themes() ([]Theme, error) {
	out := make([]Theme, len(builtinThemes))
	copy(out, builtinThemes)
	return out, nil
}

func (c *Config) ActiveTheme() string {
	id := c.GetString("theme", "dark")
	if _, ok := c.ThemeByID(id); !ok {
		return "dark"
	}
	return id
}

func (c *Config) ThemeByID(id string) (Theme, bool) {
	for _, theme := range builtinThemes {
		if theme.ID == id {
			return theme, true
		}
	}
	return Theme{}, false
}

func (c *Config) SetTheme(id string) (Theme, error) {
	theme, ok := c.ThemeByID(id)
	if !ok {
		return Theme{}, fmt.Errorf("unknown theme %q", id)
	}
	c.Data["theme"] = theme.ID
	if err := c.Save(); err != nil {
		return Theme{}, fmt.Errorf("save theme selection: %w", err)
	}
	return theme, nil
}

// ThemeBootCSS renders the active theme as an inline :root style block. The
// server injects it into index.html before the stylesheet/JS load, so the
// first paint already carries the chosen palette (no dark flash for Light
// users) and native form controls match (color-scheme). The auto theme
// emits both palettes and lets the media query pick — the dashboard's JS
// re-applies at runtime and stays authoritative afterwards.
func ThemeBootCSS(cfg *Config) string {
	active := cfg.ActiveTheme()
	var b strings.Builder
	b.WriteString(":root{")
	if theme, ok := cfg.ThemeByID(active); ok && theme.Auto {
		dark, _ := cfg.ThemeByID("dark")
		light, _ := cfg.ThemeByID("light")
		writeColors(&b, dark)
		b.WriteString("color-scheme:dark}@media (prefers-color-scheme:light){:root{")
		writeColors(&b, light)
		b.WriteString("color-scheme:light}}")
		return b.String()
	}
	theme, _ := cfg.ThemeByID(active) // ActiveTheme validated it above
	writeColors(&b, theme)
	scheme := theme.ColorScheme
	if scheme == "" {
		scheme = "dark"
	}
	b.WriteString("color-scheme:" + scheme + "}")
	return b.String()
}

func writeColors(b *strings.Builder, theme Theme) {
	keys := make([]string, 0, len(theme.Colors))
	for k := range theme.Colors {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.WriteString(k + ":" + theme.Colors[k] + ";")
	}
}

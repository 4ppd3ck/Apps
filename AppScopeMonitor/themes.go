package monitor

import "fmt"

// Theme is a data-only palette shared by the dashboard's CSS custom properties.
type Theme struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Colors      map[string]string `json:"colors"`
}

var builtinThemes = []Theme{
	{
		ID: "dark", Name: "Dark", Description: "AppScope Monitor's original dark palette.",
		Colors: map[string]string{
			"--bg": "#0d1117", "--panel": "#151b26", "--panel2": "#1a2230",
			"--line": "#263041", "--text": "#dbe4f0", "--dim": "#8494ab",
			"--accent": "#4da3ff", "--green": "#3fd68f", "--red": "#ff6b6b",
			"--amber": "#ffb454", "--purple": "#b18cff", "--cyan": "#4fd6e0",
		},
	},
	{
		ID: "netwatch", Name: "Blue", Description: "A blue-forward palette inspired by NetWatch.",
		Colors: map[string]string{
			"--bg": "#080d16", "--panel": "#101a2a", "--panel2": "#17243a",
			"--line": "#29405c", "--text": "#e1edf9", "--dim": "#91a8c2",
			"--accent": "#47c7e8", "--green": "#62d995", "--red": "#ff6f7d",
			"--amber": "#f5c466", "--purple": "#c09aff", "--cyan": "#53d8e8",
		},
	},
	{
		ID: "light", Name: "Light", Description: "A light palette for bright rooms.",
		Colors: map[string]string{
			"--bg": "#f2f4f8", "--panel": "#ffffff", "--panel2": "#eef1f6",
			"--line": "#d8dde7", "--text": "#1c2430", "--dim": "#5a6577",
			"--accent": "#0e6fd8", "--green": "#0e7a45", "--red": "#b3261e",
			"--amber": "#8a5800", "--purple": "#6d28d9", "--cyan": "#0e7490",
		},
	},
	{
		ID: "red", Name: "Red", Description: "A dark palette with warm red surfaces and accents.",
		Colors: map[string]string{
			"--bg": "#130b0d", "--panel": "#1e1216", "--panel2": "#29171c",
			"--line": "#5a2632", "--text": "#f3e7e9", "--dim": "#c08d98",
			"--accent": "#ff5c72", "--green": "#72d6a0", "--red": "#ff667a",
			"--amber": "#f5bd72", "--purple": "#d0a0dc", "--cyan": "#71cbd1",
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

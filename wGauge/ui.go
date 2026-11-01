// ui.go — embeds the dashboard assets so a binary dropped anywhere (e.g. a
// lone Windows exe) still serves the full UI; the on-disk copies in the app
// folder remain preferred (live-editable, index.html at root is the
// launcher contract). go:embed cannot cross package dirs, so this file
// lives beside the assets it embeds.
package ui

import "embed"

//go:embed index.html css js
var Files embed.FS

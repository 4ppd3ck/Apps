//go:build windows

// Windows file access collector.
//
//   - openfiles mode (admin + 'openfiles /local on'): full attribution
//     (user + path) of files held open under watched dirs.
//   - FileSystemWatcher fallback: path-change events only, no per-process
//     attribution (labelled as such).
//
// Mirrors collectors/files_windows.py.
package collectors

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"monitor"
)

const fswScript = `
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$dirs = "@@DIRS@@" -split ';'
$watchers = @()
foreach ($d in $dirs) {
  if (Test-Path $d) {
    $w = New-Object System.IO.FileSystemWatcher
    $w.Path = $d
    $w.IncludeSubdirectories = $true
    $watchers += $w
  }
}
while ($true) {
  foreach ($w in $watchers) {
    $r = $w.WaitForChanged([System.IO.WatcherChangeTypes]::All, 1000)
    if (-not $r.TimedOut) {
      if ($r.ChangeType -eq 'Renamed') {
        @{path=(Join-Path $w.Path $r.Name);
          old=(Join-Path $w.Path $r.OldName); change='Renamed'} |
          ConvertTo-Json -Compress | Write-Output
      } else {
        @{path=(Join-Path $w.Path $r.Name);
          change=[string]$r.ChangeType} |
          ConvertTo-Json -Compress | Write-Output
      }
    }
  }
}
`

// FilesWindows watches file access on Windows.
type FilesWindows struct {
	*BaseCollector
	Mode string // "fsw" or "openfiles"
}

// NewFilesWindows creates the collector.
func NewFilesWindows(ctx *monitor.Ctx) *FilesWindows {
	b := NewBase(ctx, "files-windows",
		"File access via openfiles (admin) or FileSystemWatcher", "files")
	c := &FilesWindows{BaseCollector: b, Mode: "fsw"}
	b.setRun(c.run)
	return c
}

// newFilesCollector is the registry hook for the "files" category on Windows.
func newFilesCollector(ctx *monitor.Ctx) monitor.Collector {
	return NewFilesWindows(ctx)
}

// Available probes openfiles (admin) and degrades to FileSystemWatcher.
func (c *FilesWindows) Available() (bool, string) {
	rc, _, _ := c.openfilesQuery()
	if rc == 0 {
		c.Mode = "openfiles"
		return true, ""
	}
	return true, "degraded: FileSystemWatcher only (no per-process " +
		"attribution; run as admin and enable 'openfiles /local on'" +
		" for attribution)"
}

func (c *FilesWindows) openfilesQuery() (int, string, string) {
	return monitor.Run([]string{"openfiles", "/query", "/fo", "csv", "/nh"},
		15*time.Second)
}

func (c *FilesWindows) run() {
	if c.Mode == "openfiles" {
		c.runOpenfiles()
	} else {
		c.runFSW()
	}
}

// -------------------------------------------------------- openfiles ----

func (c *FilesWindows) runOpenfiles() {
	interval := c.Ctx.Poll("files", 2.0)
	watched := c.Ctx.WatchedDirs()
	type openKey struct{ path, user string }
	seen := map[openKey]bool{}
	c.SetStatus("active", "openfiles polling with user attribution")
	for !c.Stopped() {
		rc, out, _ := c.openfilesQuery()
		if rc == 0 {
			found := map[openKey]bool{}
			reader := csv.NewReader(strings.NewReader(out))
			reader.FieldsPerRecord = -1
			for row, err := reader.Read(); err == nil; row, err = reader.Read() {
				if len(row) < 4 {
					continue
				}
				pid := strings.TrimSpace(row[0])
				user := strings.TrimSpace(row[1])
				ftype := strings.TrimSpace(row[2])
				path := strings.TrimSpace(row[3])
				if !strings.EqualFold(ftype, "file") || !startsWithAny(path, watched) {
					continue
				}
				key := openKey{path, user}
				found[key] = true
				if !seen[key] {
					var pidVal any
					if n, err := strconv.Atoi(pid); err == nil {
						pidVal = n
					}
					c.Emit(&monitor.Event{
						Category: "file",
						Kind:     "file_open",
						App:      "(open)",
						Pid:      pidVal,
						User:     user,
						Path:     path,
						Detail:   "file held open (openfiles)",
					})
				}
			}
			seen = found
		}
		c.Sleep(interval)
	}
}

// -------------------------------------------------------------- fsw ----

func (c *FilesWindows) runFSW() {
	watched := c.Ctx.WatchedDirs()
	for i, d := range watched {
		watched[i] = filepath.Clean(d) // os.path.normpath
	}
	c.SetStatus("active", "FileSystemWatcher on watched dirs (no attribution)")
	script := strings.ReplaceAll(fswScript, "@@DIRS@@",
		strings.Join(watched, ";"))
	path := filepath.Join(os.TempDir(), "appscope_fsw.ps1")
	if err := os.WriteFile(path, []byte(script), 0o644); err != nil {
		c.SetStatus("error", "cannot write helper script: "+err.Error())
		return
	}
	cmd := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy",
		"Bypass", "-File", path)
	cmd.Stderr = os.Stderr // Python inherits the parent's stderr here
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		c.SetStatus("error", err.Error())
		return
	}
	if err := cmd.Start(); err != nil {
		c.SetStatus("unavailable", "powershell.exe not found")
		return
	}
	c.registerProc(cmd)
	scanner := newLineReader(stdout)
	for !c.Stopped() {
		line, readErr := scanner.ReadString('\n')
		c.parseFSW(strings.TrimSpace(line))
		if readErr != nil {
			break
		}
	}
}

var fswKinds = map[string]string{
	"Created": "file_create",
	"Changed": "file_write",
	"Deleted": "file_delete",
	"Renamed": "file_move",
}

func (c *FilesWindows) parseFSW(line string) {
	if !strings.HasPrefix(line, "{") {
		return
	}
	var ev map[string]any
	if json.Unmarshal([]byte(line), &ev) != nil {
		return
	}
	change := monitor.StrOf(ev["change"])
	kind, ok := fswKinds[change]
	if !ok {
		kind = "file_event"
	}
	c.Emit(&monitor.Event{
		Category: "file",
		Kind:     kind,
		App:      "FileSystemWatcher (attribution unavailable)",
		User:     monitor.GetPassUser(),
		Path:     ev["path"],
		Detail: "FileSystemWatcher: " + change +
			" (run as Administrator with openfiles enabled for " +
			"process attribution)",
	})
}

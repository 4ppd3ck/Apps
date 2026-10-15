# 💧 Descale

An honest buildup cleaner: **Descale separates junk from your data** — like
descaling a kettle. It scans caches, logs, and dev-environment buildup,
reports exactly what can be reclaimed (with real byte counts and a two-tier
safety model), and cleans only on explicit confirmation — moving files to
the **Trash** with a restorable journal. No scareware, no "1,247 problems
found".

Built for the AppDeck launcher (`Apps/Descale`), macOS first, with the
engine and rules designed to be OS- and architecture-aware from day one.

## Run

From AppDeck (Descale card), or directly:

```sh
./start.sh            # picks descale-darwin-arm64 / -amd64 by machine
./start.sh 8212       # explicit port
```

The server binds to **127.0.0.1 only** — unlike a plain content server this
process can move files to the Trash, so it must never be LAN-reachable.

## The rules database (the actual product)

Everything Descale knows lives in `rules/descale-rules.json` — edit and
rescan; no rebuild. Every rule is evaluated against the running machine:

- `os` / `arch` — a rule that doesn't match the host simply reports
  *unavailable*;
- `vars` — per-machine values resolved at scan time (e.g. `{brewPrefix}` =
  `/opt/homebrew` on Apple Silicon, `/usr/local` on Intel; resolved via
  `brew --prefix` with an arch-based fallback);
- `requires` — binary on PATH / directory present;
- `runningApps` — the rule is skipped while a named app is running (live
  browser profiles and open Xcode builds are never touched);
- `minAgeDays` — files younger than N days are invisible to the rule;
- `safety` — `safe` (pre-selected, regenerable) vs `review` (never
  pre-checked);
- `action` — `trash` (default, restorable), `delete` (permanent, used only
  for the Trash itself), `command` (explicit shell command, disabled unless
  `enabled: true` in the rule).

## Safety model

1. **The API never accepts paths.** The client sends rule IDs only; the
   server derives every path fresh from the rules DB and re-validates it
   against the same excludes and age limits used in the report.
2. **Two-tier selection.** `safe` rules are pre-checked; `review` rules
   (archives, device backups, old installers) start unchecked — nothing
   risky is ever default-selected.
3. **Trash, not `rm`.** Cleaning renames files into `~/.Trash` under
   collision-safe names. The single `delete` action is `Empty the Trash`
   — files that are already trash.
4. **Journal + restore.** Every session is written to
   `~/.descale/journal.json` (original path ↔ Trash name) and restorable
   from the dashboard.
5. **Fail-safe roots.** A rule that resolves to the home directory itself
   or `/` is refused; broad glob excludes are not supported on purpose.
6. **Never clean blind.** If a rule's targets exist but can't be read, the
   rule reports **blocked** with the OS-specific fix — never a fake
   "0 B · 0 files" — and cleaning it is refused at plan time and at
   execution time until access works and a fresh scan succeeds.

## Permissions (why a rule can show "blocked")

macOS protects `~/.Trash` (and some Library paths) behind **Full Disk
Access**: `stat` succeeds but reading the directory fails with *Operation
not permitted*. Unix permissions and Windows ACLs fail the same engine the
same way. Descale detects this in one place (`checkBlockedPatterns` plus
the walker) and, consistently on every OS/arch:

- the rule's card shows 🙈 **blocked** — "can't see inside" — with the fix:
  on macOS grant the app that *launches* Descale Full Disk Access
  (System Settings › Privacy & Security), on Linux/Windows check folder
  permissions;
- `descale scan` (CLI) prints `[blocked]` with the same reason;
- `descale clean` refuses blocked rules — plan and execution — with
  "never clean blind".

A rule that is genuinely empty still reports a clean `ok · 0 B · 0 files`;
partial blindness (readable files + some unreadable subfolders) keeps `ok`
but lists every unreadable path in the rule's reason line.


## API

| Endpoint | What it does |
| --- | --- |
| `GET /api/info` | machine + active-rule summary |
| `POST /api/scan` | full report (parallel per rule; sizes, counts, top samples) |
| `POST /api/clean` | `{rules:[ids], confirm:false}` → plan; `confirm:true` → act |
| `GET /api/journal` | cleaning history |
| `POST /api/restore` | `{id}` → move a session's files back from the Trash |

## Testing without touching your machine

```sh
DESCALE_HOME=/tmp/descale-fix ./descale-darwin-arm64 8399
```

With `DESCALE_HOME` set, `~`, the Trash and the journal all resolve inside
the override — the fixture tests in CI run the whole scan/clean/restore
cycle against a synthetic tree.

## Build

```sh
go build -o descale-darwin-arm64 .          # Apple Silicon
GOARCH=amd64 go build -o descale-darwin-amd64 .
GOOS=windows GOARCH=amd64 go build -o descale-windows-amd64.exe .
```

## Roadmap

- Windows resolver + rules (`Program Files` vs `Program Files (x86)` vs
  ARM64, Delivery Optimization, update cache) — same engine, new data
- Orphan hunt: Application-Support data whose owning app is gone
- Install watcher (FSEvents) for perfect future uninstalls
- Space treemap, duplicate finder, menu-bar monitor
- Telugu UI (i18n keys already isolated in the client)

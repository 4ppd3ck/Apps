# Apps

The collection of [AppDeck](https://github.com/4ppd3ck/Appdeck) apps — one
folder per app, each carrying an **`app.json`** manifest plus its
entrypoint. Keep this repo cloned as a **sibling of the AppDeck checkout**
(`../Apps` relative to it): that is the deck's `Apps/` container, the place
its central registry and the dashboard's Import flow both land apps.

## The apps

| Folder | id | Kind | What it does |
|--------|----|------|--------------|
| `AppScopeMonitor/` | `monitor` | Go (port 8765) | Privacy & network activity dashboard — per-app collectors, store and web UI |
| `Sentinel/` | `sentinel` | Go (auto port) | Host-compromise watchdog: reads AppScope Monitor and alerts on RATs, MITM, rogue IPs, zombies, keyloggers & exfil |
| `TokenReport/` | `tokenreport` | Static (`servedBy: launcher`) | AI token usage report — which task burned the most |
| `WifiGuard/` | `wifiguard` | Static (`servedBy: launcher`) | What's shared on your Wi-Fi, at a glance |

Each folder has its own README with details. Go apps build with their
`build.sh` into `dist/` — but for deck use you normally don't need it: the
launcher builds a Go app automatically on first start.

## Importing an app into AppDeck

There are three routes; all end in the same place — a validated app folder
in the deck's `Apps/` container. Nothing is executed at import time; an
import that fails validation never leaves a half-installed folder behind.

### 1. Drop the folder in (simplest)

Copy (or `git clone`) the app folder into AppDeck's `Apps/` container and
start the launcher — the app is discovered immediately, no registration, no
launcher restart needed. Go apps are built automatically on first start; to
ship prebuilt binaries instead, put platform-suffixed ones in the folder
(`<binary>-<goos>-<goarch>[.exe]`, e.g. `monitor-darwin-arm64`) — the
launcher prefers them over the plain name and over building.

### 2. The dashboard's 📥 Import button

One endpoint — `POST /api/import` — accepts every source and normalizes all
of them into `Apps/<id>/`:

| Source | How | Notes |
|--------|-----|-------|
| Archive (`.zip` / `.tar.gz` / `.tar`) | upload, or `?url=` | must carry `app.json` at its root (one wrapping folder is stripped) |
| Single `.html` page | upload + `?appname=` | becomes a `servedBy: "launcher"` static app |
| Portable `.exe` / binary | upload with `?name=` + `?appname=` | wrapped, **never executed**; `?kind=desktop` (default, portless card) or `?kind=web&port=N`; `?args=` space-separated |
| Installer `.exe` | detected by content | **refused** by default; `&silent=1` (Windows only) attempts a silent install confined to the app folder |
| Local folder | `?folder=/path` | folder must carry a valid `app.json`; copied (not linked) into the container |
| URL | `?url=https://…` | downloaded (512 MB cap) and routed by sniffed content |

Ids must be unique — an existing install is never overwritten; remove the
old folder (or bump the `id`) first.

### 3. Scaffold a new app

From the launcher: `appdeck new "My App"` (Go template) or
`appdeck new "My Page" --kind=html`. The scaffold lands in `Apps/` with the
full contract already wired (loopback bind, `Host` check, token-protected
API routes).

## The `app.json` manifest

Every app folder carries one. The fields used in this repo:

```json
{
  "apiVersion": 1,
  "id": "monitor",
  "name": "AppScope Monitor",
  "icon": "🛡️",
  "desc": "Privacy & network activity dashboard",
  "category": "Tools",
  "port": 8765,
  "urlPath": "/",
  "network": false,
  "binary": "monitor",
  "args": ["--port", "{port}"],
  "version": "1.0"
}
```

The essentials:

- **`id`** — stable identifier (`^[a-z0-9][a-z0-9-]{0,62}$`); never rename
  after release. **`name`** — card title. **`icon`** — emoji fallback; an
  `icon.png`/`icon.svg` in the folder wins.
- **`port`** — omit it (or `0`) and the launcher assigns a stable port from
  its reserved range (24500–25499) and remembers it; pin an explicit port
  only when something outside the deck must always find the app there.
- **`network`** — loopback by default; `true` shares the app over the LAN.
  **`servedBy: "launcher"`** — static HTML app hosted inside the launcher
  process: no child process, no build (TokenReport, WifiGuard).
- **`binary` / `args`** — the executable (must stay inside the app folder)
  and its arguments; `{port}` and `{host}` placeholders are substituted.
- **`version`** — display-only chip on the card.

At runtime every started app receives `APPDECK_HOST`, `APPDECK_PORT`,
`APPDECK_APP_ID`, `APPDECK_DATA` (its own writable data directory — write
all user state there, never next to the binary) and `APPDECK_TOKEN`
(authenticate API clients with the `X-AppDeck-Token` header).

The full contract — every field, the security rules, distribution and
uninstall semantics — lives in [`AUTHORING.md` in the AppDeck repo](https://github.com/4ppd3ck/Appdeck/blob/main/AUTHORING.md).

## Repo hygiene

- `data/` directories, `*.db`, logs and `dist/` build outputs are
  **gitignored** — they are runtime state, not source.
- Tests (`*_test.go`) stay local, matching the other repos in this org.

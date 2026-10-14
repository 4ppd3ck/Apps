# AppScope Monitor — Go port

A faithful Go port of the Python `monitor` package (`python -m monitor`): a
cross-platform privacy (camera/mic/file) & network activity monitor with a
local web dashboard. The Go module is standalone (`module monitor`) and has
two direct dependencies: `modernc.org/sqlite` (pure Go SQLite — no cgo) and
`golang.org/x/sys` (NetBSD statvfs; indirect everywhere else).

## Build & run

```sh
# from Go/Monitor
go build ./...                        # compile the library and cmd/monitor package
go build -o monitor ./cmd/monitor     # produce the runnable monitor binary

./monitor                          # same CLI as python -m monitor
./monitor --config ../config.json --host 127.0.0.1 --port 8765 \
             --open --debug
```

The module root is the reusable `monitor` library, so `go build .` does not
produce an executable. The CLI entrypoint is `cmd/monitor`; use
`go build -o monitor ./cmd/monitor` (or `go build -o monitor-darwin-arm64
./cmd/monitor` for a macOS Apple Silicon binary).

Flags (identical to the Python CLI):

| flag       | meaning                                          |
|------------|--------------------------------------------------|
| `--config` | path to config.json                              |
| `--host`   | bind address (default from config: 127.0.0.1)    |
| `--port`   | port (default from config: 8765)                 |
| `--open`   | open the dashboard in the default browser        |
| `--debug`  | verbose HTTP request logging                     |

Cross-compilation (the Windows build is the primary target; linux/darwin are
kept compiling and behaviourally faithful):

```sh
GOOS=linux  go build ./...
GOOS=darwin go build ./...
```

Or build every supported target at once into `dist/` (binary + `web/`
assets + checksums per folder):

```sh
./build.sh
```

Requirements: Go 1.27+, network access to proxy.golang.org on first build
(to fetch modernc.org/sqlite). No gcc needed anywhere.

## Platform support

Verified build targets (all pure-Go cross-compiles, no cgo):

| OS                     | amd64 | arm64 | 386 | arm (v7) |
|------------------------|:-----:|:-----:|:---:|:--------:|
| Windows (primary)      | ✔    | ✔    | ✔  | –       |
| Linux (Debian/Kali…)   | ✔    | ✔    | ✔  | ✔       |
| macOS                  | ✔    | ✔    | –  | –       |
| FreeBSD / OpenBSD / NetBSD | ✔ | –   | –  | –       |

- The three platform collectors (**privacy / files / network**) have native
  implementations for Windows, macOS and Linux only. On the BSDs they
  register as `unavailable` (visible reason in the status table); all
  portable collectors still run there: vitals (CPU/RAM/disks/battery),
  devices, logins, appfocus (xdotool/X11), android, events, dashboard,
  store, and block-rule queueing.
- Blocking: Windows uses netsh when elevated, Linux iptables when root (or
  via the sudo helper), macOS pf via the helper script. On the BSDs there
  is no enforcer path — rules are queued and applied if the store is later
  moved to a supported platform.
- 32-bit ARM Linux (`GOARCH=arm`) must be built with `GOARM=7` — the
  pure-Go libc backing SQLite requires ARMv7.
- Solaris/illumos, Plan 9, js/wasm: not supported (modernc.org/sqlite has
  no port for them).

## Layout / Python → Go mapping

| Python source                      | Go source                              | notes |
|------------------------------------|----------------------------------------|-------|
| `monitor/__main__.py`              | `cmd/monitor/main.go`                  | same flags, startup order, status table |
| `monitor/__init__.py`              | `config.go` (`Version`)                | version constant |
| `monitor/config.py`                | `config.go`                            | dynamic dict + defaults merge, `Save()` |
| `monitor/context.py`               | `context.go`                           | Ctx + battery/android-device snapshots; also hosts the `Collector` interface & `Status` type (see notes) |
| `monitor/store.py`                 | `store.go`                             | exact SQL schema (events/blocks/meta), EventBus SSE fan-out |
| `monitor/netstate.py`              | `netstate.go`                          | connection table, traffic history (240 samples), snapshot enrichment |
| `monitor/server.py`                | `server.go`                            | all routes, SSE stream, static UI, block rules API |
| `monitor/enforcer.py`              | `enforcer.go`, `enforcer_windows.go`, `enforcer_unix.go` | netsh / iptables / sudo helper |
| `monitor/util.py`                  | `util.go`, `util_unix.go`, `util_windows.go` | run(), services, classify_ip, RdnsCache, filetime |
| `collectors/__init__.py`           | `collectors/registry.go`               | build_collectors / apply_toggles / enabled_for |
| `collectors/base.py`               | `collectors/base.go`                   | lifecycle (goroutine per collector), emit, status |
| `collectors/android.py`            | `collectors/android.go`                | dumpsys camera/mic/foreground/netstats |
| `collectors/appfocus.py`           | `collectors/appfocus.go`               | lsappinfo / PowerShell focus loop / xdotool |
| `collectors/battery.py`            | `collectors/battery.go`, `battery_psloop.go`, `battery_unix.go`, `battery_darwin.go`, `battery_linux.go`, `battery_winvolume.go` | vitals gauges + volumes + top consumers |
| `collectors/devices.py`            | `collectors/devices.go`                | USB/mount diff + PowerShell snapshot loop |
| `collectors/logins.py`             | `collectors/logins.go`                 | who / quser / CIM |
| `collectors/files_windows.py`      | `collectors/files_windows.go` (`//go:build windows`) | openfiles + FileSystemWatcher |
| `collectors/files_linux.py`        | `collectors/files_linux.go` (`//go:build linux`)     | auditd + /proc polling |
| `collectors/files_macos.py`        | `collectors/files_darwin.go` (`//go:build darwin`)   | fs_usage parsing |
| `collectors/network_windows.py`    | `collectors/network_windows.go` (`//go:build windows`) | PowerShell snapshot loop |
| `collectors/network_linux.py`      | `collectors/network_linux.go` (`//go:build linux`)     | ss + /proc/net/dev + nethogs |
| `collectors/network_macos.py`      | `collectors/network_darwin.go` (`//go:build darwin`)   | lsof -F0 + nettop + netstat |
| `collectors/privacy_windows.py`    | `collectors/privacy_windows.go` + `winreg_windows.go` (`//go:build windows`) | ConsentStore registry walk |
| `collectors/privacy_linux.py`      | `collectors/privacy_linux.go` (`//go:build linux`)   | /proc fd device scan |
| `collectors/privacy_macos.py`      | `collectors/privacy_darwin.go` (`//go:build darwin`) | `log stream` + TCC.db |
| `monitor/web/` (dashboard assets)  | embedded via `//go:embed web` (server.go) | served from the binary; disk folder only as `MONITOR_WEB_DIR` dev override |

Notes on the split:

- The `Collector` interface and `Status` type live in the root package
  (`context.go`) because `Ctx` carries the collector set and the
  `collectors` package imports `monitor`; `collectors/base.go` re-exports the
  alias and provides the `BaseCollector` implementation.
- Platform collectors are selected with Go build tags exactly mirroring the
  Python file split (`_windows` / `_linux` / `_darwin`). Shared logic is in
  untagged files. A few pieces that use only portable APIs (battery loops,
  appfocus, logins, devices, enforcer) use `runtime.GOOS` switches instead,
  matching Python's `sys.platform` branching.
- `statVolume` (os.statvfs equivalent) is implemented per-OS: f_frsize on
  Linux, f_bsize on darwin, GetDiskFreeSpaceExW on Windows.

## Dashboard assets

The Python build serves `<project>/monitor/web`. The Go binary resolves the
web directory at startup from, in order: `$MONITOR_WEB_DIR`, `./web`,
`./monitor/web`, `<exe dir>/web`, `<exe dir>/../monitor/web`,
`<exe dir>/../web` — so running the binary from the project root serves the
same dashboard files without duplication.

## Deviations from the Python implementation

1. **`python` field in `/api/status`** — kept for dashboard compatibility but
   now reports the Go runtime version (`runtime.Version()`). The dashboard
   does not display it.
2. **`platform` values** — reported in `sys.platform` style (`win32`,
   `darwin`, `linux`) so the console banner and API look identical.
3. **`_netsh` keyword-argument bug fixed.** In `enforcer.py`,
   `_apply_windows` calls `self._netsh("add", "rule", name=..., dir=...)` —
   keyword arguments into a `*args`-only function, which raises `TypeError`
   at runtime. The Go port implements the evident intent: the kwargs become
   `name=... dir=out action=block program=...` argv entries for netsh.
4. **`ServiceName` fallback** — Python falls back to
   `socket.getservbyport`; Go has no such stdlib call, so the fallback parses
   the system services file (`/etc/services`, or
   `%SystemRoot%\System32\drivers\etc\services` on Windows) lazily, which is
   the same data source.
5. **Subprocess termination on stop** — Python's dashboard toggle leaves a
   persistent PowerShell child alive until its next output line; the Go port
   kills tracked subprocesses immediately in `Stop()` (strictly an
   improvement, prevents goroutine/handle leaks).
6. **Unknown top-level config keys** — Python's `dict.update` keeps unknown
   keys from config.json on save; the Go `Config.Data` map is equally
   dynamic, so this behaves the same.
7. **`linuxTopApps` uses a fixed 100 Hz SC_CLK_TCK** — the stock Linux
   kernel value; Python reads `os.sysconf("SC_CLK_TCK")` which resolves to
   the same 100 on all common distros.
8. **JSON object key order** — Go marshals map keys alphabetically; the
   Python dicts preserve insertion order. JSON object order is
   semantically irrelevant to the dashboard and SSE clients.
9. **HTTP layer** — `ThreadingHTTPServer` is replaced by `net/http`
   (per-request goroutines). Client-abort noise is filtered the same way
   `handle_error` suppressed it. `--debug` request logging goes to stderr.
10. **Fidelity quirks preserved on purpose**: `percent or 100` in
    battery publish (0% treated as 100%), empty `watched_dirs` disabling
    file events, the FSW helper printing a `Test-Path` warning when no dirs
    are configured, first-poll emitting `device_connect` for already-present
    devices, `str(None)` → `"None"` inside f-string addresses, etc.
11. **Connection-state names normalised** (bug fix): the dashboard's
    live-connections filter matches Windows spellings only (`ESTABLISHED`,
    `SYN_SENT`, …), so on Linux — where `ss` reports `ESTAB`, `SYN-SENT`,
    `FIN-WAIT-1`, … — every row was filtered out and the panel stayed
    empty. `NetState.UpdateConnections` now canonicalises states from all
    three collectors (`ss`, PowerShell, lsof) to the netstat long form in
    one place, covering both the snapshot and connection events.

## Verification

```sh
gofmt -l .                      # clean (on an LF checkout)
go vet ./...
go test ./...
go build ./...                  # host platform
GOOS=linux  go build ./...      # linux/amd64
GOOS=darwin go build ./...      # darwin/amd64
GOOS=freebsd go build ./...     # bsd fallback collectors compile
./build.sh                      # full matrix into dist/
```

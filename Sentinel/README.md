# Sentinel 🚨

Host-compromise watchdog for AppDeck. Sentinel reads **AppScope Monitor**'s
live data (connections, privacy & file events) and layers its own per-OS
checks on top, then **alerts** when the machine shows indicators of being
compromised:

| Threat class | What Sentinel looks for |
|---|---|
| **RAT / remote-control implants** | Listeners on known C2/RAT/tunnel ports (4444, 12345, 31337, 5900-03, 3389, …) owned by non-allowlisted processes; active outbound sessions to those ports; process names matching a known-tool list (meterpreter, njrat, darkcomet, quasar, asyncrat, cobaltstrike, sliver, ngrok/chisel-style tunnels…) |
| **Rogue IPs / C2 beacons** | Every new outbound public endpoint is recorded to a baseline (unknown-process ones alert after the learning window); **beacons are computed from the monitor's connection *events*** — ≥6 connections to one endpoint at a mean interval of 5 s–1 h with <15% jitter flags clockwork C2 callbacks. A burst of first-seen endpoints in one pass is treated as a monitor rescan and learned silently |
| **MITM / network compromise** | Default-gateway **MAC change** (ARP spoof / rogue AP) — the MAC is warm-read (ping then ARP, with an `ndp`/EUI-64 fallback for hotspot proxy-ARP networks where the v4 neighbour entry ages out in under a second), ARP flapping (one IP answered by two MACs), one MAC claiming many IPs, **DNS resolver takeover** (full replacement of the resolver set alerts; partial churn is learned silently, two-scan confirmed), DNS-rebinding probe (known domains resolving into private space) |
| **Zombie / orphan processes** | Defunct children persisting across scans; mass parent-death (killed supervisor/AV); processes running out of temp paths |
| **Keyloggers / credential & screen exfil** | New macOS **TCC grants** for Accessibility, Input Monitoring (keystrokes), PostEvent, ScreenCapture, Full Disk Access vs a learned baseline; keylogger/clipboard-grabber process names; **correlation** — camera/mic turned on or sensitive file (`~/.ssh`, wallets, cookies…) touched by an app that is *also* holding an outbound connection |
| **Persistence** | New launch agents/daemons (macOS), cron jobs, `~/.config/autostart` + systemd user units (Linux), Run/RunOnce keys + startup folders (Windows) — with stager-pattern scoring (curl/iex/base64/temp targets) |

Sentinel **detects and alerts; it does not block** — pair it with AppScope
Monitor's enforcement (netsh/iptables/pf) for that.

## The AppScope Monitor link

Sentinel polls `http://127.0.0.1:8765` (`/api/connections`, `/api/events`,
`/api/status`) every fast tick. The monitor is optional: if it is offline,
Sentinel's own process, listener, MITM, persistence and permission checks
still run, and the dashboard shows the reduced coverage. Start AppScope
Monitor from AppDeck for the full picture.

## Alerting

- Severity-ranked alerts (critical / high / medium / low / info), deduplicated
  by fingerprint so one ongoing issue is one alert with a hit counter.
- Desktop notifications (osascript / notify-send / PowerShell message box)
  for alerts at or above the configured floor (default: medium), re-notifying
  at most every 30 minutes per fingerprint.
- Optional **webhook** delivery (ntfy / Telegram / generic JSON) so alerts
  reach your phone even on a headless box or if the GUI is compromised.
- Dashboard SSE feed + a beep on high/critical.
- Everything is exported as JSON (`⇩ Export`).

## Baselines (learned, then diffed)

First run **learns** (no alert storm): gateway MAC, DNS resolvers, ARP table,
every app↔endpoint pair, persistence entries, TCC grants. After that, any
*change* is what alerts. `Reset baseline (re-learn)` in the dashboard (or
deleting `baseline.json`) starts over — do this after intentional hardware/
network changes.

## Run it

It is an AppDeck app — start it from the dashboard. Manually:

```sh
./sentinel-darwin-arm64 --port 8899            # serve the dashboard
./sentinel-darwin-arm64 --once                 # one full scan, findings to stdout
APPDECK_DATA=/tmp/sentinel-data ./sentinel...  # explicit state dir
```

State lives in `APPDECK_DATA` (AppDeck hands each app its own directory) or
`./data`: `alerts.json`, `baseline.json`, `rules.user.json`.

## Tuning — rules.user.json

An overlay on the defaults; omitted fields keep defaults:

```json
{
  "monitor_url": "http://127.0.0.1:8765",
  "tick_seconds": 15,
  "slow_minutes": 5,
  "learn_minutes": 120,
  "notify": {
    "desktop": true, "sound": true, "min_severity": "medium",
    "webhook_url": "https://ntfy.sh/my-private-topic",
    "webhook_format": "ntfy",
    "webhook_chat_id": ""
  },
  "bad_ports": [4444, 5555],
  "trusted_cidrs": ["127.0.0.0/8", "10.0.0.0/8", "192.168.1.0/24"],
  "sensitive_paths": [".ssh", "wallet"],
  "process_allowlist": ["sshd", "tailscaled", "screensharingd"],
  "process_bad_names": ["mimikatz", "njrat"]
}
```

- `bad_ports` — remote-control ports that alert when listened on or contacted
  (owner checked against `process_allowlist` first).
- `trusted_cidrs` — networks that count as *internal*; everything else public
  is watched for new-endpoint/beacon behaviour.
- `process_allowlist` — names that legitimately hold remote-control ports or
  screen/keyboard abilities (VNC, RDP, TeamViewer, tailscaled, …); a zombie
  whose parent is allowlisted is treated as known supervisor noise.
- `process_bad_names` — always-alert process-name patterns.
- `sensitive_paths` — substrings that mark a file event as sensitive for the
  exfil correlation.
- `bad_tcc_client` (macOS) — TCC clients that escalate a new grant to high.
- `learn_minutes` — silent learning window after first start: new outbound
  endpoints are recorded to the baseline without alerting (default 120).
  Set 0 to alert from the first scan.
- `quiet_apps` — apps whose endpoint churn is their nature (browsers,
  updaters; brave/chrome/firefox/safari/edge/… by default). They are
  baselined and beacon-tracked but never generate new-endpoint alerts.
- `new_endpoint_burst` (default 8) — a non-quiet app reaching this many
  first-seen public destinations in a single scan escalates the aggregated
  alert to medium ("Endpoint expansion") — spread/scanner behaviour.

  New-endpoint alerts are **aggregated per app over a 6-hour window**: one
  low alert listing the destinations in its evidence, not one per IP. The
  window bucket is part of the fingerprint, so a quiet app that keeps
  meeting new hosts re-reports at most every 6 hours.
- `notify.webhook_*` — out-of-band alert delivery, for headless machines or
  when the attacker may control the GUI. Formats:
  - `"json"` — generic POST `{"severity","title","detail","check","ts","count"}`
  - `"ntfy"` — plain-text POST with `Title`/`Priority`/`Tags` headers
    (works with ntfy.sh or a self-hosted server)
  - `"telegram"` — bot API sendMessage; `webhook_url` is the bot API base
    (`https://api.telegram.org/bot<token>/sendMessage`) and
    `webhook_chat_id` your chat id

  Webhooks fire for alerts at or above `min_severity`, same 30-minute
  re-notify window as desktop toasts.

## Platform support

Pure Go stdlib (no cgo, no SQLite). `./build.sh` builds the host binary by
default — what AppDeck launches and what an import zips — and takes `--all`
or explicit `<os>/<arch>` targets to cross-compile the rest of the matrix
(no toolchain prerequisites beyond Go itself):

| OS | amd64 | arm64 | 386 | arm v7 |
|---|:-:|:-:|:-:|:-:|
| macOS | ✔ | ✔ | – | – |
| Windows | ✔ | ✔ | ✔ | – |
| Linux | ✔ | ✔ | ✔ | ✔ |
| FreeBSD / OpenBSD / NetBSD | ✔ | – | – | – |

Per-check capability by platform:

| Check | macOS | Linux | Windows | BSD |
|---|---|---|---|---|
| Zombies/orphans/bad names | ps | /proc | PowerShell CIM | ps |
| Listening sockets | lsof | /proc/net/tcp | Get-NetTCPConnection | lsof/netstat |
| Gateway/ARP/DNS baseline | route/arp/scutil | /proc + resolv.conf | Get-NetRoute/arp | route/arp |
| Persistence | LaunchAgents/Daemons, cron | autostart, systemd, cron | Run keys, startup folders | cron |
| TCC grants | sqlite3 (needs Full Disk Access for the host terminal) | – | – | – |
| Monitor correlation | everywhere (HTTP) | everywhere | everywhere | everywhere |

Checks that cannot run on a platform surface as `unavailable` on the dashboard
with the reason — never silently skipped.

## Privacy

Sentinel watches *your machine for you*. Everything stays local: the API
binds loopback (AppDeck passes the bind host), state is JSON files in the
app's data directory, and the only network traffic it generates is the
loopback calls to AppScope Monitor plus the DNS probes for the rebinding
check (three well-known domains). Feed files are not fetched from the
internet — add your own intel as lines in `rules.user.json` /
`trusted_cidrs` / `bad_ports`.

## Layout

```
main.go       flags, env (APPDECK_*), wiring
server.go     HTTP API + SSE + embedded dashboard (go:embed web)
engine.go     scheduler (fast/slow ticks), finding→alert dispatch
store.go      JSON persistence: alerts, baseline (no SQLite on purpose)
rules.go      defaults + rules.user.json overlay
integ.go      AppScope Monitor client (events + connections poll)
procs.go      process enumeration (per-OS) + zombie/bad-name/temp checks
netwatch.go   listening sockets, rogue endpoints, bad-port sessions
beacon.go     event-based endpoint & beacon tracking (C2 callback intervals)
mitm.go       gateway MAC / ARP / DNS baselines + rebinding probe
persist.go    persistence locations scan (per-OS)
exfil.go      TCC grants, keylogger names, camera/mic/file + outbound correlation
alert.go      SSE hub + desktop notifications
util.go       shared helpers: safe exec, IP classification, JSON IO
web/          dashboard (vanilla JS, no build step)
build.sh      host binary by default; --all / <os>/<arch> into ./ and dist/
sentinel_test.go   unit tests for the pure detection logic
```

## Verification

```sh
gofmt -l . && go vet . && go test .
./build.sh                    # host binary — the one AppDeck launches/imports
./sentinel-<host> --once      # walk a full scan on your machine
./build.sh --all              # optional: full cross-compile matrix + dist/
```

Live-test recipe (on your own machine, then clean up):

```sh
python3 -c "import socket,time; s=socket.socket(); s.bind(('0.0.0.0',4444)); s.listen(1); time.sleep(60)"
# → Sentinel raises HIGH "Listener on known remote-control port 4444" within one tick
```

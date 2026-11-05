# wtower (wTower)
Go app (binary: wtower, rebuilt by the launcher on start). Privacy/network dashboard: Go daemon + web UI.

## Files
- *.go at root (context, config, store, server, netstate, geo, enforcer, grant,
  dnsfilter, themes, util*) —
  package `monitor`: app context, SQLite store, HTTP+SSE server, firewall enforcement. Must stay at root.
- collectors/ — per-platform collectors (network, privacy, battery, files, logins, devices...);
  build-tagged files: *_darwin.go, *_windows.go, *_linux.go, plus fallbacks
- web/ — dashboard UI (index.html, app.js, style.css) served by the Go server
- data/ — runtime output (event store). Do not delete; not source.
- scripts/, build.sh — helper scripts and build entry
- docs/screenshots/ — screenshots only
## Verify
- go build ./... && go vet ./... ; run tests: go test ./...

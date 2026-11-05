# whawk (wHawk)
Go app (binary: whawk, rebuilt by the launcher on start). Host-compromise watchdog reading AppScope Monitor.

## Files
- cmd/sentinel/*.go — detection logic (firewall.go, RAT/MITM/rogue-IP/zombie checks), alerting, UI
- Scripts/tcc.sh — macOS TCC helper
- .zcode/ — editor session artifacts; ignore
## Verify
- go build ./... && go vet ./... ; go test ./...

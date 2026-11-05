# wscout (wScout)
Go app (binary: wscout, rebuilt by the launcher on start). GitHub runnable-app search/download.

## Files
- cmd/repolens/ — Go server (GitHub API, download/run plumbing, AppDeck install bridge in appdeck.go)
- public/ — static frontend: index.html, app.js, styles.css (served by the Go server)
## Verify
- go build ./... && go vet ./...

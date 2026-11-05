# wgrid (wGrid)
Go app (binary: wgrid, rebuilt by the launcher on start). Publishes provider IP ranges to Sentinel over loopback.

## Files
- cmd/ipolice/*.go — entrypoint, provider-range fetching/normalization, git sync
- samples/ — sample provider-range JSON (goog, aws) for offline testing
## Verify
- go build ./... && go vet ./...

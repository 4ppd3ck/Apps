# wpurge (wPurge)
Go app (binary: wpurge, rebuilt by the launcher on start) + static dashboard. Cleanup/uninstall/startup manager.

## Files
- cmd/descale/ — Go server (rules engine, Trash-based removal)
- rules/ — built-in cleanup rule definitions (data, not code)
- index.html + css/app.css + js/app.js — dashboard UI (js/app.js talks to the local Go server)
- start.sh / start.bat — manual launch helpers (leave at root)
## Verify
- go build ./... ; UI: serve folder or run the binary.

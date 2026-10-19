# AppDeck apps

This folder contains the apps that AppDeck discovers and starts. For the
first run, keep `Apps/` beside the `Appdeck/` launcher folder, then start
AppDeck with `go run .` from inside `Appdeck/`.

![AppDeck app cards. All names and values are synthetic.](../Appdeck/screenshots/overview.svg)

*Privacy-safe UI preview: synthetic example data only; no workstation or
network details are shown.*

## Apps in this guide

| App folder | Purpose | How to run |
|---|---|---|
| [AppScopeMonitor](AppScopeMonitor/README.md) | Local device, privacy, and network activity dashboard | Start from AppDeck; Go can also run it directly |
| [Sentinel](Sentinel/README.md) | Host checks and security alerts | Start from AppDeck; Go can also run it directly |
| [Descale](Descale/README.md) | Review cleanup candidates and restore items from Trash | Start from AppDeck; Go can also run it directly |
| [RepoLens](RepoLens/README.md) | Search GitHub for open-source applications | Start from AppDeck or run the Go server directly |
| [TokenReport](TokenReport/README.md) | Analyze selected local AI-agent logs | Start from AppDeck |
| [WifiGuard](WifiGuard/README.md) | View which AppDeck apps are shared on Wi-Fi | Start from AppDeck |

## First-time setup

1. Install Go 1.27 or newer if you plan to run AppDeck or build a Go app.
2. Start the launcher from `Appdeck/`:

   ```sh
   go run .
   ```

3. Open <http://127.0.0.1:9090> if the browser did not open automatically.
4. On an app card, choose **Start**, then **Open**.
5. To shut down, stop the app from its card, then press **Ctrl+C** in the
   terminal running AppDeck.

The launcher builds Go apps the first time they are started. A working
internet connection may be needed to download Go modules. The static
TokenReport and Wi-Fi Guard pages are served by AppDeck and do not need a
separate runtime.

## Keep your data private

Some apps collect local system information, scan local files, or read log
folders you select. Read the app-specific privacy notes before using them.
Do not publish logs, screenshots, exports, or runtime data without checking
them for usernames, device names, file paths, IP addresses, tokens, and other
private details.

AppDeck can make some apps reachable by other devices on your Wi-Fi. Keep
sharing disabled unless you need it. None of these apps should be exposed
directly to the public internet.

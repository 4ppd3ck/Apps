# Sample databases 📁

Ready-made example feeds in every format IPolice parses. All ranges are
reserved documentation addresses (TEST-NET / 2001:db8::/32) — safe to load,
they never match real traffic. Use them to try the flow, then swap in real
feeds.

Exception: `sample-whatsapp.txt` carries **real** Meta (AS32934) production
ranges — loading it labels live Meta/WhatsApp traffic in Sentinel.

## The files

| File | Format | Shape |
|---|---|---|
| `sample-text.txt` | `text` | One CIDR per line, `#` comments. Bare IPs are **not** accepted here — write full CIDRs. |
| `sample.csv` | `csv` | CSV with a header; the network column is picked by name (`network`/`cidr`/`prefix`/`ip`/`range`/…) or forced via **CSV column** (header name or 1-based index). Comment rows whose first cell starts with `#` are skipped. Bare IPs are normalised (`198.51.100.7` → `/32`, IPv6 → `/128`). |
| `sample-goog.json` | `goog` | Google ipranges shape: `{"prefixes":[{"ipv4Prefix":…},{"ipv6Prefix":…}]}` |
| `sample-aws.json` | `aws` | AWS ip-ranges shape: `prefixes[].ip_prefix` + `ipv6_prefixes[].ipv6_prefix` |
| `sample-whatsapp.txt` | `text` | Real Meta (AS32934) aggregates — WhatsApp/Facebook/Instagram shared network. Not TEST-NET; see header. |

Not sampled here because they come from live services: `ms365`
(endpoints.office.com — a fresh `clientrequestid` GUID is added for you),
`github-meta` (api.github.com/meta), `fastly` (api.fastly.com/public-ip-list).
Local copies of those JSON shapes parse with the same format names.

## Try one (dashboard)

1. Open the IPolice dashboard → **Databases** → **Add a database**.
2. Provider name: `Sample` — Type: **local file** — Format: **csv**.
3. Local file path: the absolute path of `samples/sample.csv`
   (e.g. `/Users/you/Desktop/Launcher/Apps/IPolice/samples/sample.csv`).
4. **Add & download**, then look up `192.0.2.1` in the IP box — it should
   answer `known: Sample`.

## Or via data/sources.json

```json
{
  "replace": false,
  "sources": [
    { "name": "Sample", "type": "file", "path": "/absolute/path/samples/sample.csv",
      "format": "csv", "csv_column": "network" }
  ]
}
```

`replace: false` keeps the built-in defaults (Google & YouTube, Cloudflare,
GitHub) and merges your sources in. A plain `[ … ]` array instead replaces
the defaults entirely.

## Git example

Point `type: git` at any repo and name the list file inside it:

```json
{ "name": "Firehol L1", "type": "git",
  "url": "https://github.com/firehol/blocklist-ipsets",
  "path": "firehol_level1.netset", "format": "text" }
```

IPolice shallow-clones into `data/repos/` and `git fetch`-updates it on
every refresh (needs the `git` CLI installed).

## Naming & merging

Sources sharing a **name** merge into one provider (union of networks).
Two YouTube lists both named `YouTube` = one provider; different names =
separate providers. Deleting a source is safe: a provider only loses its
data when its **last** source goes, and built-in defaults can be deleted
too — the deletion is remembered across restarts, and re-adding the same
source restores it.

## When Sentinel is wired

With Sentinel running and `intel_match` set (see the main README), anything
you add here immediately starts labelling/suppressing traffic to those
ranges on Sentinel's next poll — remove the sample afterwards so TEST-NET
addresses don't linger in your intel (they're harmless, just noise).

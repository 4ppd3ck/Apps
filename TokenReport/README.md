# Token Report

A local dashboard that answers one question: **which task burned the most
tokens, on which AI tool?** It reads the AI agents' own log files with plain
code — no AI calls anywhere in the pipeline, so the report itself costs
**zero tokens**.

Hosted in-process by AppDeck (plain HTML/JS, no build step, no dependencies).

## What it shows

- **Report tab** — KPI cards (total tokens, estimated cost with
  week-over-week deltas, request count, cache reads, output tokens, top task,
  peak hour, optional budget card), the **Tasks table** (one row per agent
  session; click a row for its request-by-request breakdown), **By model**,
  **By project** (grouped by the workspace each agent worked in),
  **Tokens over time** (metric selector + cumulative mode) and
  **Recent requests**.
- **🧮 Token mix tab** — input / output / cache read / cache write kept
  individual: per-kind KPI cards, a proportional split bar, and both tables
  with the four kinds as columns.
- **⏰ Peak hours tab** — hour-of-day chart, weekday × hour heatmap, and
  peak-vs-off-peak comparison with an editable peak window.

## Sources (folder selection)

Click **+ Add source** (or ⚙ → Sources) and pick the folder where an agent
writes its logs. Six templates:

| Template | Typical folder |
|---|---|
| ZCode | `~/.zcode/cli/rollout` |
| Claude Code | `~/.claude/projects` |
| Codex CLI | `~/.codex/sessions` (older builds) |
| Copilot CLI | `~/.copilot` — reads `session-store.db` **or** `data.db` |
| OpenClaw / AutoClaw | `~/.openclaw-autoclaw` |
| Custom / new agent | any folder with `.jsonl` / `.json` logs |

- **Agent name (optional)** — type a name when adding a source and it becomes
  that agent's identity everywhere: the Agent dropdown, records, tables.
  Useful for two folders of the same tool (Work / Personal) and for custom
  agents. Leave empty for the default behavior.
- **Changed directory?** Remove the source and re-pick the new folder — or
  just re-pick; the app never copies anything.
- **New AI agent?** Pick its log folder with the *Custom / new agent*
  template — the format is sniffed automatically from the file contents
  (usage blocks, timestamps, model fields), falling back to a generic
  deep-search parser that understands camelCase and snake_case usage objects.
- Folder handles persist in IndexedDB across restarts. Chromium drops the
  access grant per browser session: after a restart the report keeps showing
  each source's **last cached scan**, an amber banner appears, and
  **🔑 Restore access** re-grants every source in one click.
- Browsers without the File System Access API fall back to a
  `webkitdirectory` file input (picked files are scanned, but not persisted).

Parsing runs entirely in the page: recursive scan of the chosen folder
(skipping caches and `node_modules`), `.jsonl`/`.json`/`.db` files only,
capped at 4000 files / 300 MB.

## Filters

- **Agent dropdown** — All agents, or one source's agent.
- **Project dropdown** — All projects, or one workspace (from the log's
  `cwd`/project fields, or Claude Code's per-project folders).
- **Range** — 5 minutes, 15 minutes, 1 hour, 12 hours, 24 hours, 7 days,
  all-time-on-disk, or **Custom** from/to datetimes.
- **Scanning** — sources are scanned when the app opens, when a source is
  added/reconnected/removed, and on every page reload. There is no manual
  Refresh button or 30-second auto-rescan: repeated rescans kept re-triggering
  folder-permission errors after browser restarts, so the dashboard works on
  the data it has until you reload the page.

## Cost estimates & budget

Costs are computed from an editable price table (⚙ → Est. pricing): USD per
1M tokens per model, with `cacheReadRatio` and `cacheWriteRatio` multipliers
on the input price. Longest model-name substring match wins; `default`
catches everything else. The shipped numbers are public list prices and
placeholders — edit them to match your plan (Z.ai subscription usage, for
example, is not per-token billed). Nothing is ever sent anywhere.

Set a **Budget** (⚙ → amount + period) to get a KPI card with spend vs
budget and a pace forecast from your last 7 days of data (amber ≥ 80%,
red ≥ 100%).

## Exports

- **⬇ CSV** — the currently filtered data, one row per request.
- **⧉ MD** — a Markdown summary (KPIs, by-model table, top tasks) copied to
  the clipboard for standups and notes.

## Archive — keeping history locally

ZCode prunes ended sessions from its rollout folder, so on-disk history
shrinks over time. To keep it: ⚙ → **Archive** → choose a
`tokenreport-archive.jsonl` file once. New records are **auto-archived** on
every scan (deduped by request identity; toggle in ⚙), **Save now** does the
same manually, and **include archive in reports** folds it back into the
dashboard. The archive is a plain local JSONL file — exactly the "save data
to local, dashboard works on the local file" model. Sources that lose folder
access keep serving their **last cached scan** from an IndexedDB cache until
reconnected.

## Supported log formats

- **ZCode** `model-io-*.jsonl` — `response.usage` (camelCase) with
  `inputTokens / outputTokens / cacheReadTokens / cacheWriteTokens`, per
  session file; task label from the session's first non-system user message.
- **Claude Code** — assistant lines with `message.usage` (snake_case incl.
  `cache_creation_input_tokens` / `cache_read_input_tokens`), task label from
  the first user line.
- **Codex CLI** — `token_count` events (uses `last_token_usage`, or diffs
  cumulative `total_token_usage`), model from `session_meta`, task from
  `user_message` events.
- **Copilot CLI** — both known SQLite layouts, detected from the database
  content (never from OS/arch/version): old `session-store.db`
  (`assistant_usage_events` per request + `turns` labels) and current
  `data.db` (per-session cumulative totals on the `sessions` table, one
  record per session timestamped at its last activity). WAL replay included;
  zero-byte `-wal` files are handled.
- **OpenClaw / AutoClaw** — `agents/<name>/sessions/<uuid>.jsonl`: assistant
  `usage` blocks (reasoning already included in output), task = first
  authored user message (policy/system wrappers skipped), project = the
  session workspace folder.
- **Generic** — any JSONL with a findable usage-like object, timestamp and
  model field.

## Claude & ChatGPT — how to get their data into the report

Claude Desktop (claude.ai) and ChatGPT (chatgpt.com / Atlas) keep
conversations and usage **on their servers** — the local app folders contain
no token usage, so there is nothing for a local-first tool to scan. Three
realistic ways to still see their burn here:

1. **Import their official data exports** (works with plain Plus/Pro
   subscriptions). ChatGPT: Settings → Data controls → *Export data* (ZIP by
   email, contains `conversations.json`). Claude: claude.ai → Settings →
   Privacy → *Export data*. A future **"Import export file"** source type can
   parse those into records with real timestamps and models — tokens
   *estimated locally* (no AI calls) and labeled as such, since the exports
   carry no token counts. Re-import after each export to update.
2. **Official usage APIs** (exact numbers, needs pay-per-token API keys):
   Anthropic's admin usage-report endpoint and OpenAI's platform usage
   endpoint could be fetched through a small loopback-only proxy in the
   launcher. Only relevant if you hold API keys — Plus/Pro subscriptions
   expose no usage API.
3. **Route work through CLI agents** (zero new code): Claude Code and Codex
   CLI write exactly the local logs this app already parses, and Claude Code
   accepts a Pro/Max login. Usage from them flows in automatically with
   exact per-request numbers.

Recommended: import (1) for historical coverage, CLI agents (3) for exact
numbers going forward, (2) only if API keys enter the picture.

## Limits

- ZCode's `no-session` file and any unparseable lines are counted and shown
  in the status bar, never fatal.
- Claude/ChatGPT subscriptions keep usage server-side — see the section
  above for the import/API options.
- Very large folders are capped as above; files > 64 MB are skipped.
- The Copilot `data.db` layout stores cumulative per-session totals only, so
  its sessions have no per-request timeline (ZCode / OpenClaw / old Copilot
  do).

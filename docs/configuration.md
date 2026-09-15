# Configuration

Everything is configured by environment variable. To make a setting permanent without
touching a shell rc, put it in `~/.traffic-deck/config.toml` — the keys are the same env var
names, and the environment still wins over the file:

```toml
# ~/.traffic-deck/config.toml  ($TRAFFIC_DECK_HOME/config.toml)
GATEWAY_VIEWER = "web"          # bare `trafficdeck` brings up the web UI, not the TUI
GATEWAY_MCP = false             # values may be strings, bools or numbers
DATA_ROOT = "/Users/me/captures"
```

Keys are matched case-insensitively (`gateway_viewer` works too), settings are flat (there
are no `[sections]`), and an unknown key is ignored. A malformed file is logged and skipped
rather than fatal — a typo in config must not stop the gateway from starting. Precedence is
**env → file → built-in default**, so `GATEWAY_VIEWER=tui trafficdeck` still overrides the
file for one run.

## Gateway

| Env | Default | Meaning |
|-----|---------|---------|
| `DATA_ROOT` | `./data` | SQLite bundles + catalog |
| `TRAFFIC_DECK_HOME` | `~/.traffic-deck` | per-user root, shared with the capture tools: `config.toml`, [plugin manifests](modules.md), profiles. Env only — a config file can't relocate the directory it lives in. |
| `GATEWAY_ADDR` | `127.0.0.1:7331` | gRPC listen / viewer + tools connect addr |
| `TRAFFICDECK_FP_DIR` | `~/.traffic-deck/fingerprints` | dir of user TLS-fingerprint `*.json` files (on top of the builtin set) — see [TLS client fingerprint names](fingerprints.md) |
| `TSHARK_PATH` | `tshark` | batch-decode / import binary (not used by the default live path) |
| `GATEWAY_LIVE_DECODE` | `true` | decode a streaming capture live, fully in-process in Go. Set `0`/`false` to archive only and decode with the batch tshark pass on close. |
| `GATEWAY_RECORD_LIVE` | `true` | the live decode is authoritative: persist its flows on close and skip the batch pass, keeping bodies whole (so they are readable in full mid-capture). Set `off` to run an authoritative batch tshark re-decode on close instead (useful to verify the live decoder) — then a live body is capped at 256 KiB and the viewer labels it a preview until the session closes. |
| `GATEWAY_TSHARK_VERIFY` | `false` | on close, compare the live-decoded flows against a tshark decode and log the differences. |
| `GATEWAY_MCP` | `true` | auto-start the [MCP server](mcp.md) on launch, so an agent client can attach without a viewer. Set `off` to keep it down; the TUI toggles it with `X` either way. The gateway owns it, so it outlives the viewer, and a gateway with no MCP launcher installed just logs that and carries on. |
| `GATEWAY_LOG_FILE` | `<DATA_ROOT>/logs/gateway.log` | rolling log file; logs are teed to stderr. Set `off` for stderr only. |
| `GATEWAY_VIEWER` | `tui` | what bare `trafficdeck` runs in the foreground: `tui` (built-in); a [module](modules.md) viewer by name (`webui`, or `webui:web` when a module declares several) — its command, `cwd`, `env`, `url` and `screen` come from the manifest; a bare command line (`myviewer --flag`, assumed full-screen, split on spaces, no shell quoting); or `none` — nothing in the foreground, the gateway stays up until Ctrl-C while a module (or you) serves the UI. The viewer inherits the terminal and gets `GATEWAY_ADDR`; when it exits, the gateway shuts down. |

### Logging

Size/retention knobs: `GATEWAY_LOG_MAX_SIZE_MB` (50), `GATEWAY_LOG_MAX_BACKUPS` (10),
`GATEWAY_LOG_MAX_AGE_DAYS` (30), `GATEWAY_LOG_COMPRESS` (true).

Under `trafficdeck` (one-command mode) the terminal belongs to the TUI, so the gateway and
its children log to the file only — `tail -f` it to watch, press `L` in the TUI, or use
`trafficdeck serve`. Each spawned child (capture source, MCP, a [module's](modules.md)
processes) also gets its own rolling file in the same directory — `logs/chrome.log`,
`logs/mcp.log` — so one tool can be read on its own; under `serve` its output is
additionally teed to the terminal tagged `[chrome]`.

## TUI

| Env | Default | Meaning |
|-----|---------|---------|
| `GATEWAY_ADDR` | `127.0.0.1:7331` | gateway to attach to |
| `TRAFFICDECK_PAGE_SIZE` | `250` | rows in the flow table's window, clamped to 50–2000 — see [the TUI guide](tui.md#the-flow-table-is-a-window-not-a-page) |
| `TRAFFICDECK_META_COLUMNS` | — | comma-separated extra flow-table columns to show by default (e.g. `conn,stream`, or any source metadata key) |
| `TRAFFICDECK_WIRESHARK` | `wireshark` | Wireshark GUI binary for `W` |
| `EDITOR` / `VISUAL` | — | editor used to open a body |

## MCP server

| Env | Default | Meaning |
|-----|---------|---------|
| `GATEWAY_ADDR` | `127.0.0.1:7331` | gateway to read from |
| `MCP_TRANSPORT` | `streamable-http` | also `sse` or `stdio` |
| `MCP_HOST` / `MCP_PORT` | `127.0.0.1` / `8765` | bind address for the HTTP transports (endpoint `/mcp`) |
| `MCP_READONLY` | `1` | expose only the read tools; `0` also exposes `rename_session` and `set_session_group` |

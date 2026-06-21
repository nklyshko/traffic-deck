# Modular Traffic Analysis System

Capture raw traffic from multiple sources, decode it server-side into HTTP flows,
store it, and browse it in a mitmproxy-like TUI. See [`plan/`](plan/) for the full
design and roadmap.

## Components

| Dir | What |
|-----|------|
| [`proto/`](proto/) | gRPC contract (source of truth) |
| [`traffic-gateway/`](traffic-gateway/) | Go service: ingest, decode (tshark), per-session SQLite store, serve |
| [`capture-tools/`](capture-tools/) | Python capture agents (Chrome, mitmproxy; Android later) |
| [`traffic-viewer/`](traffic-viewer/) | Textual TUI |
| [`traffic-mcp/`](traffic-mcp/) | MCP server exposing recorded sessions to LLM/agent clients |

Storage is embedded SQLite: a per-session bundle (`data/sessions/<id>/` holding
`capture.pcap`, `key.log`, `flows.sqlite`) plus a global `data/catalog.sqlite`. No
database server or Docker required.

## Prerequisites

- **[mise](https://mise.jdx.dev)** — provisions the toolchain (go, python, uv, buf,
  protoc plugins).
- **Wireshark CLI** — the gateway shells out to **`tshark`** for decode, and the
  Chrome tool captures with **`dumpcap`** (both ship with Wireshark). Not provisioned
  by mise.
- **Capture permission for dumpcap** (only for live capture):
  - Linux: be in the `wireshark` group (`sudo usermod -aG wireshark $USER`, then
    re-login). Run capture under that group with `sg wireshark -c '…'` if your current
    shell isn't in it yet.
  - macOS: install Wireshark's ChmodBPF helper.

```sh
mise install            # toolchain
mise run gen            # generate gRPC stubs (Go + Python) — REQUIRED before build/run
```

## Quick start

Start the gateway (serves on `127.0.0.1:8080`, data under `./data`):

```sh
mise exec -- go -C traffic-gateway run ./cmd/gateway serve
```

Browse in the TUI (separate terminal):

```sh
uv run --directory traffic-viewer python -m traffic_viewer.app
```

TUI keys: `↑/↓`+`Enter` drill in (sessions → flows → detail), `Esc` back, `r`
refresh sessions. In a flow list: `f` filter (mitmproxy-style: `~m ~d ~u ~c ~t`,
plus annotations `~fav ~mark ~tag ~group ~comment`, naked = URL, `!` negate), `c`
mark/compare two requests across sessions. Annotate (plan §12): `space` toggle
select (for bulk), `t` tag, `F` favorite, `m` color-mark, `n` comment, `g` group —
each acts on the selection if any, else the focused row. `M` opens the WebSocket
message timeline for a `⇅` flow. In a flow detail: `s`/`r` save response/request
body, `x` export curl, `w` export raw request+response, `M` ws messages. `q` quit.

### MCP server (for LLM/agent clients)

`traffic-mcp` exposes recorded sessions over the Model Context Protocol, backed by the
gateway's `ViewerService` (it never touches SQLite directly, so it works against a
local or remote gateway). Tools: `list_sessions`, `search_flows` (same filter DSL as
the TUI), `get_flow`, `get_body`, `list_ws_messages`, `export_curl`.

Run it over stdio (point your MCP client at this command):

```sh
GATEWAY_ADDR=127.0.0.1:8080 uv run --directory traffic-mcp python -m traffic_mcp.server
```

Or over HTTP — set `MCP_TRANSPORT` to `streamable-http` (or `sse`); it binds
`MCP_HOST:MCP_PORT` (default `127.0.0.1:8765`) and serves the MCP endpoint at `/mcp`:

```sh
MCP_TRANSPORT=streamable-http MCP_PORT=8765 GATEWAY_ADDR=127.0.0.1:8080 \
    uv run --directory traffic-mcp python -m traffic_mcp.server
```

## Getting traffic in

### A) Import a pre-captured pcap + key.log

```sh
mise exec -- go -C traffic-gateway run ./cmd/gateway import \
    --pcap capture.pcap --keylog key.log --label demo
```

The `key.log` is an NSS keylog (e.g. from `SSLKEYLOGFILE`); without it HTTPS can't be
decrypted. The pcapng-with-embedded-secrets case works too — pass just `--pcap`.

### B) Live-capture Chrome

Launches Chrome with a dedicated `SSLKEYLOGFILE`, captures with `dumpcap`, and streams
to the gateway live (`STREAMING_LIVE`) — decrypted flows appear in the TUI as you
browse. Capture is interface-wide, but only Chrome's TLS sessions have keys, so the
**decoded view is effectively Chrome-only**.

Fresh throwaway profile (recommended for clean captures):

```sh
sg wireshark -c 'cd capture-tools && uv run python -m capture_tools.chrome \
    --label "live demo" --url https://example.com'
```

Against an **existing** Chrome profile (e.g. Chrome Canary) — keeps your logins,
extensions, history. Quit any Chrome already running on that profile first, otherwise
the launch just attaches to the running instance and no TLS keys are logged:

```sh
sg wireshark -c 'cd capture-tools && CHROME_BIN=google-chrome-canary uv run python \
    -m capture_tools.chrome --label "manual test" \
    --profile-dir "$HOME/.config/google-chrome-canary"'
```

Browse, then close Chrome (or use `--duration N` to auto-stop after N seconds) to
finalize the session.

Useful flags / env:

| | |
|---|---|
| `--profile-dir DIR` | use an existing profile instead of a fresh temp one |
| `--url URL` | open a URL on launch |
| `--duration N` | auto-stop after N seconds |
| `--iface IFACE` | capture interface (default: auto-detected) |
| `--filter BPF` | dumpcap capture filter (default `tcp port 80 or tcp port 443`) |
| `--gateway ADDR` | gateway address (default `127.0.0.1:8080`) |
| `CHROME_BIN` | Chrome/Chromium binary (e.g. `google-chrome-canary`) |
| `DUMPCAP_BIN` / `CAPTURE_IFACE` | override dumpcap / interface |

> `sg wireshark -c '…'` runs the whole command (and the `dumpcap` it spawns) under the
> `wireshark` group. If your shell is already in that group, you can drop the `sg`
> wrapper. The keylog is written to a temp dir, never into your real profile.

### C) mitmproxy (any device, incl. WireGuard)

Runs `mitmdump` with an addon that streams **already-decoded** flows to the gateway
(`PushFlows`) — no pcap/keylog, since mitmproxy terminates TLS. Unlike the Chrome path
this is an active **MITM**: the device must trust mitmproxy's CA (visit `mitm.it` once
connected, or install `~/.mitmproxy/mitmproxy-ca-cert.*`); cert-pinned apps still need
a Frida bypass.

```sh
# regular HTTP proxy on :8080 — set the device/app proxy to <this-host>:8080
uv run --project capture-tools python -m capture_tools.mitm --label "api poke"

# WireGuard server — any device that can be a WireGuard client routes through it
# (mitmproxy prints the peer config / QR on startup)
uv run --project capture-tools python -m capture_tools.mitm --mode wireguard --label phone
```

Flows appear live in the TUI as they complete; stop mitmdump (`q`/Ctrl-C) to close the
session. Args after `--` pass through to `mitmdump`. Flags: `--mode` (regular |
wireguard | transparent | …), `--label`, `--listen-port`, `--gateway ADDR`.

### D) Android (rooted emulator/device, per-app)

Captures **one app's** traffic from a rooted emulator/device: Frida hooks the system
`libssl.so` to dump TLS secrets (NSS `key.log`, no proxy/CA), and the app's packets
are isolated by UID via `iptables … NFLOG` + on-device `tcpdump -i nflog:<group>`.
Both stream to the gateway over the same pipeline as Chrome and decode to decrypted
flows.

Prereqs: the Android SDK (so `adb`/`emulator` are available) and a **rooted** target.
Root is auto-detected: `adb root` (emulator / `userdebug` builds) or **Magisk `su`**
(retail devices) — capture commands elevate accordingly. The agent auto-fetches a
matching `frida-server` (GitHub) and pushes it; both the emulator and typical
Magisk devices already ship `tcpdump` + `iptables`.

**Interactive (recommended)** — guided flow: pick target (emulator/device), set up or
boot an emulator if needed, ensure root, pick the **frida version** (v16/v17, defaulting
to the one recommended for the device's Android release — frida 17 can't spawn on
Android ≤ 11), pick the app, optionally add Frida scripts (SSL-unpinning/bypass):

```sh
uv run --project capture-tools python -m capture_tools.android.cli
```

It can create + boot a rootable `google_apis` AVD (installing the system image on
first use) and drop extra Frida scripts from `~/.config/traffic/frida-scripts` (or a
path you enter). The chosen frida version is applied via `uv run --with frida==<ver>`
(client and server must match). The CLI is a thin front-end over the capture library.

**Non-interactive** — for scripting/known targets:

```sh
uv run --project capture-tools python -m capture_tools.android \
    --package com.example.app --url https://example.com --duration 30 --script unpin.js
```

Flags: `--package` (required), `--url`, `--duration`, `--script FILE` (repeatable),
`--attach` (hook the running app instead of spawning), `--serial`, `--nflog-group`,
`--gateway`.

> Works for apps using the **system** TLS stack (OkHttp/`HttpURLConnection`→Conscrypt).
> Apps that **bundle their own BoringSSL** (Chrome, most Flutter apps) won't be
> decrypted by the `libssl.so` hook — Chrome has its own `--ssl-key-log-file` for that.
> The agent hooks the main process **and** matching `<pkg>:child` processes.
>
> Verified end-to-end on both an emulator and a Magisk-rooted retail device (decrypted
> HTTPS flows). frida-server is matched to the installed `frida` (pinned to 16.7.x,
> which still supports older Android — frida 17 fails to spawn on e.g. Android 10) and
> started as a root daemon in its own session.

## Configuration (gateway)

| Env | Default | Meaning |
|-----|---------|---------|
| `DATA_ROOT` | `./data` | SQLite bundles + catalog |
| `GATEWAY_ADDR` | `127.0.0.1:8080` | gRPC listen / viewer + tools connect addr |
| `TSHARK_PATH` | `tshark` | decode binary |

## Status

- **Phase 1** — import a pcap + key.log → tshark decode (incl. request/response
  bodies) → per-session SQLite → `ViewerService` → Textual TUI. HTTP/1.1 + HTTP/2.
- **Phase 2** — live Chrome capture: `dumpcap` + `SSLKEYLOGFILE` → streamed ingest →
  live `tshark -r -` decode → live-following TUI.
- **Phase 3** — mitmproxy-like TUI: filter DSL, cross-session compare, curl/raw
  export, and **annotations** (tags + Favorite, comments, color marks, groups;
  `ControlService` + per-session SQLite, plan §12).
- **Phase 4** — **WebSocket**: `websocket` frames (HTTP/1.1 Upgrade) decode into
  message records bound to the Upgrade flow; the TUI marks ws flows with `⇅` and shows
  a directional message timeline (`M`).
- **Phase 5** — `traffic-mcp`: an MCP server (stdio or HTTP) over `ViewerService`.
- **Phase 6** — **mitmproxy source**: an addon streams decoded flows via `PushFlows`
  (any device, incl. WireGuard mode); live-followed and persisted with no pcap.
- **Phase 7** — **Android**: per-app capture from a rooted emulator/device — Frida
  `libssl.so` keylog + UID→NFLOG `tcpdump`, streamed and decoded to HTTPS flows.

Next: Kaitai custom decoders + on-demand re-decode. See
[`plan/09-roadmap.md`](plan/09-roadmap.md).

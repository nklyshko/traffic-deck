# TrafficDeck — Modular Traffic Analysis System

Capture raw traffic from multiple sources, decode it server-side into HTTP flows,
store it, and browse it in a mitmproxy-like TUI. See [`docs/architecture.md`](docs/architecture.md)
for the design and [`docs/adr/`](docs/adr/) for the key decisions.

## Components

| Dir | What |
|-----|------|
| [`proto/`](proto/) | gRPC contract (source of truth) |
| [`gateway/`](gateway/) | Go service: ingest, decode (tshark + pluggable [`decoders/`](gateway/decoders/)), per-session SQLite store, serve |
| [`capture/`](capture/) | Independent Python capture apps — `capture_chrome`, `capture_mitmproxy`, `capture_android` — over a shared `capture_sdk` (each its own project + deps) |
| [`tui/`](tui/) | Textual TUI |
| [`mcp/`](mcp/) | MCP server exposing recorded sessions to LLM/agent clients |

Storage is embedded SQLite: a per-session bundle (`data/sessions/<id>/` holding
`capture.pcap`, `key.log`, `flows.sqlite`) plus a global `data/catalog.sqlite`. No
database server or Docker required.

## Prerequisites

- **[mise](https://mise.jdx.dev)** — provisions the toolchain (go, python, uv, buf,
  protoc plugins).
- **Wireshark CLI** — the Chrome tool captures with **`dumpcap`**, and the gateway
  shells out to **`tshark`** for pcap import and the optional batch decode (the default
  live decode is pure Go and needs neither). Both ship with Wireshark; not provisioned
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

One command runs the gateway and the TUI together — the gateway supervises capture, so
it starts and stops the capture tools for you (no separate terminal for them):

```sh
make build && ./trafficdeck            # gateway in-process + the TUI in the foreground
```

Quitting the TUI shuts the gateway down cleanly. If a gateway is already listening on the
address, `./trafficdeck` just attaches the viewer to it. In the sessions screen, press `a`
to start a capture (pick a source, step through its options) and `s` to stop one.

Prefer them apart (headless gateway, remote viewer, several viewers)? Run the daemon and
the TUI separately:

```sh
make run                                   # build ./trafficdeck and serve (gateway only)
# or: mise exec -- go -C gateway run ./cmd/gateway serve

tui/run.sh                                 # the TUI (GATEWAY_ADDR overridable)
# or: uv run --directory tui python -m traffic_viewer.app
```

`↑/↓`+`Enter` drills in (sessions → flows → detail), `Esc` goes back, `q` quits.
Several sessions can be open at once as tabs in the workspace. Keys by screen:

| Screen | Keys |
|---|---|
| Sessions | `a` new capture (pick a source, then step through its options — binary, profile, … — and start) · `s` stop the focused capture · `X` start/stop the MCP server · `r` refresh · `n` rename · `g` group · `e` export as a `.tar.gz` bundle · `i` import a bundle · `c` force-close a session left open · `d` delete |
| Workspace (tabs) | `o` open another session in a tab · `[` / `]` prev/next tab · `w` close tab |
| Flow list | `f` filter (see below) · `C` toggle optional columns (`Conn`/`Stream`, and any source metadata key) · `c` mark/compare two requests across sessions · `l` follow new flows as they arrive · `space` select / `D` deselect · `t` tag · `F` favorite · `m` color-mark · `n` comment · `g` group · `M` WebSocket timeline for a `⇅` flow · `W` open the request in Wireshark |
| Flow detail | `b` / `B` view request/response body · `r` / `s` save request/response body · `x` export curl · `w` export raw request+response · `H` export TLS ClientHellos · `M` ws messages · `W` open in Wireshark |
| WS messages | `space` select / `D` deselect · `t` `F` `m` `n` `g` annotate · `l` follow new |
| Compare A/B | `s` switch A/B · `h` copy header order · `p` copy pseudo-header order · `k` copy cookie order |

Annotation keys act on the selection if there is one, else on the focused row. Bodies
in the detail view are pretty-printed (JSON reindented + syntax-colored, form fields as
key/value).

The filter (`f`) is mitmproxy-style: `~m ~d ~u ~c ~t` (method, domain, url, status,
content-type), connection identity `~conn ~stream`, annotations `~fav ~mark ~tag
~group ~comment`, source metadata `~meta <key>=<re>`, `~s`/`~q` (has/no response). A
naked regex matches the URL and `!` negates a term; terms are ANDed. The cheat sheet
shows while the filter input is focused.

#### HTTP/2 connections and streams

HTTP/2 multiplexes many requests over one connection, so a flow carries both the
transport connection it rode on (a `tcp.stream` index, or `quic:<conn-id>` for HTTP/3)
and its stream id within that connection. The flow detail always shows them
(`conn=12  stream=5`), and the flow table has optional `Conn`/`Stream` columns — one
`Conn` value repeated across rows with different `Stream` values *is* connection reuse.
Filter with `~conn`/`~stream` to isolate one connection's streams (both are regexes
like every other term, so anchor to pin an exact id: `~conn '^12$'`).

The pcap-based sources (`capture_chrome`, `capture_android`) show both columns by
default — they decode the frames off the wire, so the ids are the client's real ones.
`capture_mitmproxy` doesn't: mitmproxy terminates the connection, and its addon API
never exposes the HTTP/2 stream id, so both fields stay empty for proxy-captured flows.

#### Open a request in Wireshark

`W` — on a flow row or in the flow detail — hands the request to Wireshark for
packet-level inspection: the session's own `capture.pcap`, its `key.log` as
`tls.keylog_file` (so TLS decrypts there too), a display filter scoped to the flow's
connection, and the packet cursor on the request's frame. On an HTTP/2 connection the
filter also drops the *other* streams' frames (`http2.streamid eq N or not http2`), which
leaves the target request plus the connection's handshake/ACK packets around it. Widen it
in Wireshark's filter bar to see the whole connection again.

The filter pins the connection by its address/port 4-tuple, not by the `Conn` id: that id
matches Wireshark's `tcp.stream` index only on the tshark decode path — the native decoder
numbers the connections it tracks, which is its own sequence.

Needs the `wireshark` GUI on `PATH` (or `TRAFFICDECK_WIRESHARK` pointing at it) and the
pcap readable locally — the gateway reports where it keeps the session's files, so a
viewer attached to a *remote* gateway is told the path is on that host instead. Sessions
without a pcap (`capture_mitmproxy`) have nothing to open.

### MCP server (for LLM/agent clients)

`trafficdeck-mcp` exposes recorded sessions over the Model Context Protocol, backed by the
gateway's `ViewerService` (it never touches SQLite directly, so it works against a
local or remote gateway). Tools: `list_sessions` + `list_session_groups`,
`network_timeline` (the request sequence, like the DevTools Network tab), `search`
(structured, combined domain/method/content-type/status/… in one query), `search_flows`
(the TUI's filter DSL), `get_flow`, `get_body` (text/base64/`as_hex`), `compare_flows`
(diff two requests, across sessions), `export_request` (request+response headers, no
bodies), `export_client_hellos` (a flow's raw TLS ClientHello bytes), `list_ws_messages`
(paginated) + `get_ws_message_body` (WebSocket frames; `as_hex` for byte inspection).
Session args accept an id prefix.

Sessions still being captured are readable too: flows, WebSocket frames and bodies are
served from the live decode until the session closes and they are persisted. Under
record-live (the default) bodies come back whole at any size; with `GATEWAY_RECORD_LIVE=off`
the live decode keeps only the first 256 KiB of a body, and `get_body` marks what it
returns `partial` — fetch it again once the session closes for all of it.

It runs **read-only by default**: only the inspection tools above are exposed. Set
`MCP_READONLY=0` to additionally expose the mutating tools `rename_session` and
`set_session_group` (relabel / regroup a recorded session).

Run it (defaults to the `streamable-http` transport, binding `MCP_HOST:MCP_PORT` =
`127.0.0.1:8765` and serving the MCP endpoint at `/mcp`):

```sh
mcp/run.sh                                            # GATEWAY_ADDR / MCP_PORT overridable
# or: GATEWAY_ADDR=127.0.0.1:8080 uv run --directory mcp python -m traffic_mcp.server
```

For a client that speaks MCP over stdio instead, set `MCP_TRANSPORT=stdio` (other
value: `sse`):

```sh
MCP_TRANSPORT=stdio mcp/run.sh
```

## Getting traffic in

### A) Import a pre-captured pcap + key.log

```sh
mise exec -- go -C gateway run ./cmd/gateway import \
    --pcap capture.pcap --keylog key.log --label demo [--decoder tshark|native]
```

The `key.log` is an NSS keylog (e.g. from `SSLKEYLOGFILE`); without it HTTPS can't be
decrypted. The pcapng-with-embedded-secrets case works too — pass just `--pcap`.

`--decoder` picks the batch decoder: `tshark` (default) orchestrates tshark, while
`native` runs the same in-process Go pipeline as live capture (no tshark needed). Both
decoders read classic pcap and pcapng.

You can also import from the TUI: press `I` on the sessions screen to pick a pcap, an
optional key.log, and the decoder. The paths resolve on the gateway host (the local host
under one-command mode).

### B) Live-capture Chrome

Launches Chrome with a dedicated `SSLKEYLOGFILE`, captures with `dumpcap`, and streams
to the gateway live (`STREAMING_LIVE`) — decrypted flows appear in the TUI as you
browse. Capture is interface-wide, but only Chrome's TLS sessions have keys, so the
**decoded view is effectively Chrome-only**.

Interactive (recommended) — the launcher activates the `wireshark` group itself (via
`sg`), then lets you pick the Chrome binary and the profile: the **browser's own
default** (launched with no `--user-data-dir`), a fresh temp profile, or a named
persistent profile (pick an existing one or create a new one) under
`~/.traffic-deck/chrome-profiles`. The pickers default to your previous run's choices
(remembered under `~/.traffic-deck/state`):

```sh
capture/capture-chrome.sh
```

Scripted / explicit — flags override each picker; `--no-prompt` skips them:

```sh
sg wireshark -c 'uv run --project capture/capture_chrome trafficdeck-capture-chrome \
    --no-prompt --label "live demo" --url https://example.com'
```

Against an **existing** Chrome profile (e.g. Chrome Canary) — keeps your logins,
extensions, history. Quit any Chrome already running on that profile first, otherwise
the launch just attaches to the running instance and no TLS keys are logged:

```sh
sg wireshark -c 'uv run --project capture/capture_chrome trafficdeck-capture-chrome \
    --no-prompt --chrome google-chrome-canary --label "manual test" \
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
| `--filter BPF` | dumpcap capture filter (default empty = capture everything, so proxies/non-standard ports/HTTP3 are all included; decode only surfaces Chrome-decryptable + plaintext HTTP. Narrow to e.g. `tcp port 443` for smaller captures) |
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
# regular HTTP proxy on :8888 — set the device/app proxy to <this-host>:8888
uv run --project capture/capture_mitmproxy trafficdeck-capture-mitmproxy --label "api poke"

# WireGuard server — any device that can be a WireGuard client routes through it
# (mitmproxy prints the peer config / QR on startup)
uv run --project capture/capture_mitmproxy trafficdeck-capture-mitmproxy --mode wireguard --label phone
```

Flows appear live in the TUI as they complete; stop mitmdump (`q`/Ctrl-C) to close the
session. Args after `--` pass through to `mitmdump`. Flags: `--mode` (regular |
wireguard | transparent | …), `--label`, `--listen-port` (default `8888`), `--gateway ADDR`.

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
uv run --project capture/capture_android trafficdeck-capture-android
```

It can create + boot a rootable `google_apis` AVD (installing the system image on
first use) and drop extra Frida scripts from `~/.traffic-deck/frida-scripts` (or a
path you enter). The chosen frida version is applied via `uv run --with frida==<ver>`
(client and server must match). The CLI is a thin front-end over the capture library.

**Non-interactive** — for scripting/known targets:

```sh
uv run --project capture/capture_android python -m capture_android.headless \
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

## Custom protocol decoders

Non-HTTP binary protocols carried over TCP (e.g. MAX messenger, `ru.oneme`) are decoded
by **compiled-in Go modules** under [`gateway/decoders/`](gateway/decoders/).
Each decoder is its own package that self-registers via `init()`; the gateway
blank-imports it in `cmd/gateway`. The decoder turns a connection's TLS-decrypted
directional byte stream into message frames, surfaced as a synthetic flow with the
WebSocket-style `M` message timeline. HTTP and custom-protocol flows coexist in one
session. Two paths produce the decrypted bytes:

- **Live** (during capture, the default): fully in-process in Go — the gateway taps the
  live pcap, reassembles TCP (`gopacket`, including the Android `NFLOG` link type), and
  decrypts TLS (SSL 3.0 – TLS 1.3) from the key-log
  ([`internal/tlsdecrypt`](gateway/internal/tlsdecrypt/)), feeding the decoder as bytes
  arrive — no `tshark` re-run. So MAX frames stream into the `M` timeline in real time.
  **Verified end-to-end** on the Android `ru.oneme` (MAX) app: live TLS decryption +
  decoding of MAX frames during capture.
- **Batch** (session close): `tshark -z follow,tls,raw` over each matched stream. Runs
  only with `GATEWAY_RECORD_LIVE=off` (or on import/verify), and is what can still
  recover a connection the live decryptor had to skip — one negotiating a version or
  cipher suite it doesn't implement, or whose key-log secret never arrived.

A decoder implements `decoders.Decoder` (`Name`, `Matches(StreamMeta)`, `NewSession`);
the returned `Session` is a stateful framer — `Feed(fromClient, data) []Message` —
that buffers a partial frame until the rest arrives, so it works fed all-at-once
(batch) or incrementally (live). See `decoders/max` (MAX framing → LZ4 → MessagePack →
JSON). Add one = add a package + a blank import + rebuild.

```sh
# re-run custom decoders over an already-captured session (e.g. after adding a decoder)
mise exec -- go -C gateway run ./cmd/gateway redecode <session-id>
```

Decoding needs the connection's TLS to be decryptable from the capture's `key.log`
(i.e. the app uses the system `libssl` the Android Frida hook logs) — verified working
on `ru.oneme`.

## Sharing sessions (export / import)

A session is self-contained — its bundle holds the flows DB, the capture, the key.log,
spilled bodies, and the tags/groups it uses — so it can be exported as a single
`.tar.gz` and imported into another gateway.

```sh
# export (CLI). In the TUI, press `e` on the sessions list to export the focused one.
mise exec -- go -C gateway run ./cmd/gateway export <session-id> -o session.tar.gz

# import into this gateway's data root + catalog. --new-id imports a copy when the
# original id already exists; --label overrides the session label.
mise exec -- go -C gateway run ./cmd/gateway import-session session.tar.gz [--new-id] [--label name]
```

## Third-party capture/viewer modules

A module (e.g. a private adapter that pushes flows plus its own web UI) enrolls by dropping
a manifest in `~/.traffic-deck/plugins/*.toml` after its own setup — TrafficDeck installs
nothing. The gateway launches the declared processes at startup (in order, with
`GATEWAY_ADDR` injected) and group-kills them on shutdown; a `[control]` block whose `addr`
speaks `CaptureSourceService` registers the module as a capture source the gateway *dials*
(it appears in the TUI's source picker like a built-in). A manifest is executable trust —
whatever lands in `plugins/` runs inside TrafficDeck, like a shell rc file.

```toml
name = "acme"

[[process]]
name    = "adapter"
cwd     = "/home/you/src/acme/adapter"
command = ["uv", "run", "acme-adapter", "--listen", "127.0.0.1:7070"]

[[process]]
name    = "web"
cwd     = "/home/you/src/acme/web"
command = ["npm", "run", "dev"]
env     = { VITE_ADAPTER_URL = "http://127.0.0.1:7070" }

[control]                       # optional: this module is also a capture source
addr   = "127.0.0.1:7070"       # speaks traffic.v1.CaptureSourceService
source = "acme"
label  = "Acme"
```

## TLS client fingerprint names

Every decrypted ClientHello already yields a **JA3** and **JA4** (see *Fingerprinting*).
On top of that the gateway names the client — `Chrome 150`, `OkHttp (Android)`,
`Firefox`, … — shown as **Client:** in a flow's *TLS ClientHello* detail block. Names come
from a registry of well-known fingerprints: a **compiled-in builtin set**
([`gateway/internal/tlsfp/builtin.json`](gateway/internal/tlsfp/builtin.json), embedded)
plus any files you drop in — no rebuild.

Classification is a pure function of the fingerprint, run **at serve time**, so editing the
registry re-labels flows you already captured — no re-decode.

**Register your own** (like [`plugins/`](#third-party-captureviewer-modules), it's just a
drop-in dir): put `*.json` in `~/.traffic-deck/fingerprints/` (override with
`TRAFFICDECK_FP_DIR`). Same schema as the builtin; **later files win ties**, so a row can
add a new name or override a builtin one:

```json
{"fingerprints": [
  {"name": "AcmeApp", "version": "3", "ja4": "t13d1516h2_8daaf6152771_806a8c22fdea"},
  {"name": "Internal tool", "ja4_pre": "t13d1715h2_5b57614c22b0", "sni": "api.acme.internal"}
]}
```

Match keys, most specific wins: **`ja4`** (exact) › **`ja4_pre`** (a JA4 prefix — the
`a_b` sections, i.e. client + version era, robust while only the trailing extension hash
changes across minor versions) › **`ja4_b`** (just the cipher-list hash = a whole client
family) › **`ja3`** (legacy, exact). An optional **`sni`** further constrains any row.
Malformed rows are skipped and logged, never fatal; the dir is hot-reloaded, so a new file
takes effect on the next flow without a restart.

> **On versions:** JA4 is deliberately stable across browser releases — one JA4 spans many
> versions (Chrome 120–131 all share `…_02713d6af862`), and FoxIO's ja4db doesn't version
> Chrome at all. So builtin rows carry a version *range*, and the `ja4_b` family rows
> recognize **any** version — including ones with no exact row, like Chrome 139/144 — as
> `Chrome`. To pin a version you care about, capture it once and add its exact `ja4` as a
> user row. The seed set is real (computed by this repo's parser over uTLS ClientHellos +
> FoxIO ja4db + local captures); grow it from <https://ja4db.com>.

## Configuration (gateway)

| Env | Default | Meaning |
|-----|---------|---------|
| `DATA_ROOT` | `./data` | SQLite bundles + catalog |
| `TRAFFICDECK_FP_DIR` | `~/.traffic-deck/fingerprints` | dir of user TLS-fingerprint `*.json` files (on top of the builtin set) — see [TLS client fingerprint names](#tls-client-fingerprint-names) |
| `GATEWAY_ADDR` | `127.0.0.1:8080` | gRPC listen / viewer + tools connect addr |
| `TSHARK_PATH` | `tshark` | batch-decode / import binary (not used by the default live path) |
| `GATEWAY_LIVE_DECODE` | `true` | decode a streaming capture live, fully in-process in Go. Set `0`/`false` to archive only and decode with the batch tshark pass on close. |
| `GATEWAY_RECORD_LIVE` | `true` | the live decode is authoritative: persist its flows on close and skip the batch pass, keeping bodies whole (so they are readable in full mid-capture). Set `off` to run an authoritative batch tshark re-decode on close instead (useful to verify the live decoder) — then a live body is capped at 256 KiB and the viewer labels it a preview until the session closes. |
| `GATEWAY_TSHARK_VERIFY` | `false` | on close, compare the live-decoded flows against a tshark decode and log the differences. |
| `GATEWAY_MCP` | `false` | auto-start the MCP server on launch (headless agent access without a viewer). The TUI can also toggle it with `X`; either way the gateway owns it, so it outlives the viewer. |
| `GATEWAY_LOG_FILE` | `<DATA_ROOT>/logs/gateway.log` | rolling log file; logs are teed to stderr. Set `off` for stderr only. Size/retention: `GATEWAY_LOG_MAX_SIZE_MB` (50), `GATEWAY_LOG_MAX_BACKUPS` (10), `GATEWAY_LOG_MAX_AGE_DAYS` (30), `GATEWAY_LOG_COMPRESS` (true). Under `trafficdeck` (one-command mode) the terminal belongs to the TUI, so the gateway and its children log to the file only — `tail -f` it to watch, or use `trafficdeck serve`. Each spawned child (capture source, MCP, a module's processes) also gets its own rolling file in the same directory — `logs/chrome.log`, `logs/mcp.log` — so one tool can be read on its own; under `serve` its output is additionally teed to the terminal tagged `[chrome]`. |

## Features

- **Protocols** — HTTP/1.1, HTTP/2, HTTP/3 + QUIC, WebSocket, and custom binary
  protocols over TLS (compiled-in Go decoders; first decoder: **MAX** / `ru.oneme`).
- **Fingerprinting** — what a client's stack looks like on the wire, from the raw
  frames the native decoder sees: **JA3/JA4** with a **named client** (`Chrome 150`,
  `OkHttp (Android)`, …) classified from a registry you can extend without a rebuild
  (see [TLS client fingerprint names](#tls-client-fingerprint-names)), the verbatim TLS
  ClientHello bytes (exportable, incl. the second one after a HelloRetryRequest), and the
  Akamai **HTTP/2 fingerprint** (client SETTINGS, connection WINDOW_UPDATE, PRIORITY,
  pseudo-header order) — decoded to named settings in the detail view. Compare A/B
  diffs two requests' header/pseudo-header/cookie order across sessions.
- **HTTP/2 connections** — a flow records the connection it rode on and its stream
  within it, so multiplexed requests can be grouped back onto one connection
  (`Conn`/`Stream` columns, `~conn`/`~stream` filters).
- **Proxy detection** — connections through an HTTP `CONNECT` or SOCKS proxy are
  flagged per flow (proxy address, type, and any credentials seen on the wire),
  detected from the captured handshake.
- **Capture sources** — live Chrome (`dumpcap` + `SSLKEYLOGFILE`), mitmproxy (any
  device, incl. WireGuard), and per-app Android from a rooted device/emulator (Frida
  `libssl` key-log + UID→NFLOG `tcpdump`).
- **Live decode** — a streaming capture decodes live **fully in-process in Go, no tshark**:
  TCP/QUIC reassembly, TLS/QUIC decryption from the key-log, and HTTP/1.1, HTTP/2, HTTP/3,
  WebSocket and custom raw-TCP framing (plaintext or TLS). By default the live decode is
  authoritative and persisted on close (record-live); set `GATEWAY_RECORD_LIVE=off` for an
  authoritative batch **tshark** re-decode on close instead (tshark is otherwise used only
  for pcap import). WebSocket and custom-protocol frames stream into a directional `M`
  timeline live. Toggle live with `GATEWAY_LIVE_DECODE`.
- **TUI** — Textual viewer: session list → flow table → detail, body pretty-printing
  (JSON/forms), a mitmproxy-style filter DSL, cross-session compare, curl/raw export,
  and annotations (tags + Favorite, comments, color marks, groups).
- **Sessions** — self-contained per-session SQLite bundles; export/import as a single
  `.tar.gz`.
- **MCP** — `trafficdeck-mcp` exposes recorded sessions to LLM/agent clients over the same
  read API.

See [`docs/architecture.md`](docs/architecture.md) for the design and
[`docs/adr/`](docs/adr/) for the decisions behind it.

# Modular Traffic Analysis System

Capture raw traffic from multiple sources, decode it server-side into HTTP flows,
store it, and browse it in a mitmproxy-like TUI. See [`plan/`](plan/) for the full
design and roadmap.

## Components

| Dir | What |
|-----|------|
| [`proto/`](proto/) | gRPC contract (source of truth) |
| [`traffic-gateway/`](traffic-gateway/) | Go service: ingest, decode (tshark), per-session SQLite store, serve |
| [`capture-tools/`](capture-tools/) | Python capture agents (Chrome; mitmproxy/Android later) |
| [`traffic-viewer/`](traffic-viewer/) | Textual TUI |

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
refresh sessions, `s`/`r` save response/request body, `q` quit.

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

Next: annotations (bookmarks/groups) + on-demand re-decode. See
[`plan/09-roadmap.md`](plan/09-roadmap.md).

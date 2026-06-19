# Modular Traffic Analysis System

Capture raw traffic from multiple sources, decode it server-side into HTTP flows,
store it, and browse it in a TUI. See [`plan/`](plan/) for the full design.

## Components

| Dir | What |
|-----|------|
| [`proto/`](proto/) | gRPC contract (source of truth) |
| [`traffic-gateway/`](traffic-gateway/) | Go service: ingest, decode (tshark), per-session SQLite store, serve |
| [`capture-tools/`](capture-tools/) | Python capture agents (Chrome, mitmproxy, Android) |
| [`traffic-viewer/`](traffic-viewer/) | Textual TUI |

Storage is embedded SQLite: a per-session bundle (`data/sessions/<id>/` holding
`capture.pcap`, `key.log`, `flows.sqlite`) plus a global `data/catalog.sqlite`. No
database server or docker required.

## Toolchain

All tooling is provisioned by [mise](https://mise.jdx.dev) from `mise.toml`:

```sh
mise install            # go, python, uv, buf, protoc plugins
mise run gen            # generate gRPC stubs (Go + Python)
mise run lint-proto     # lint the proto contract
mise run gateway:build  # build the gateway binary
```

## Run (Phase 1)

```sh
# import a pre-captured pcap + key.log, then serve
mise exec -- go -C traffic-gateway run ./cmd/gateway import \
    --pcap capture.pcap --keylog key.log --label demo
mise exec -- go -C traffic-gateway run ./cmd/gateway serve &

# browse it
uv run --directory traffic-viewer python -m traffic_viewer.app
```

`DATA_ROOT` (default `./data`), `GATEWAY_ADDR` (default `127.0.0.1:8080`), and
`TSHARK_PATH` configure the gateway.

## Status

Phases 0–1 complete: import a pcap + key.log → tshark decode → per-session SQLite →
gRPC `ViewerService` → Textual TUI (sessions → flows → headers). HTTP/1.1 + HTTP/2,
headers only (bodies pending). See [`plan/09-roadmap.md`](plan/09-roadmap.md).

External dependency: the gateway requires the **`tshark`** binary at runtime for
decode (not provisioned by mise; install Wireshark CLI tools).

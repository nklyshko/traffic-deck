# Modular Traffic Analysis System

Capture raw traffic from multiple sources, decode it server-side into HTTP flows,
store it, and browse it in a TUI. See [`plan/`](plan/) for the full design.

## Components

| Dir | What |
|-----|------|
| [`proto/`](proto/) | gRPC contract (source of truth) |
| [`traffic-gateway/`](traffic-gateway/) | Go service: ingest, decode (tshark), store, serve |
| [`capture-tools/`](capture-tools/) | Python capture agents (Chrome, mitmproxy, Android) |
| [`traffic-viewer/`](traffic-viewer/) | Textual TUI |
| [`deploy/`](deploy/) | docker-compose (Postgres) |

## Toolchain

All tooling is provisioned by [mise](https://mise.jdx.dev) from `mise.toml`:

```sh
mise install            # go, python, uv, buf, protoc plugins
mise run gen            # generate gRPC stubs (Go + Python)
mise run lint-proto     # lint the proto contract
mise run gateway:build  # build the gateway binary
```

> Network is behind a proxy — prefix install/codegen commands that fetch with
> `https_proxy=… http_proxy=…` if they time out.

## Status

Phase 0 (foundations) — scaffolding, proto contract, object store, migrations,
docker-compose. See [`plan/09-roadmap.md`](plan/09-roadmap.md). Decode (`tshark`),
the gateway read APIs, and the TUI land in Phase 1.

External dependency: the gateway requires the **`tshark`** binary at runtime for
decode (not provisioned by mise; install Wireshark CLI tools or bundle in the image).

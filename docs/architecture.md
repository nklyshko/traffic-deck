# Architecture

A modular traffic-analysis system for reverse-engineering and parser fingerprinting:
capture an app's traffic, decode it (HTTP/1.1, HTTP/2, HTTP/3, WebSocket, and custom
binary protocols), and browse the decoded flows in a TUI or via an LLM/agent (MCP).

## Components

| Module | Language | Role |
|--------|----------|------|
| `proto/` | protobuf | gRPC contract (source of truth), generated for Go + Python via `buf` |
| `gateway/` | Go | ingest, decode, store, serve |
| `capture/` | Python | capture apps (`capture_chrome`, `capture_mitmproxy`, `capture_android`) over a shared `capture_sdk` |
| `tui/` | Python (Textual) | terminal UI over the gateway's read API |
| `mcp/` | Python (FastMCP) | Model Context Protocol server over the same read API |

```mermaid
flowchart LR
  subgraph capture[capture]
    chrome[capture_chrome]
    mitm[capture_mitmproxy]
    android[capture_android]
  end

  chrome -- "UploadCapture\n(pcap + key.log)" --> gw
  android -- "UploadCapture\n(pcap + key.log)" --> gw
  mitm -- "PushFlows\n(decoded flows)" --> gw

  subgraph gw[gateway]
    ingest[IngestService]
    decode[decode pipeline]
    store[(per-session SQLite\n+ catalog)]
    viewer[ViewerService]
    control[ControlService]
    ingest --> decode --> store
    store --> viewer
    store --> control
  end

  viewer -- "StreamFlows / StreamMessages\nGetFlow / GetBody" --> tui[tui]
  viewer --> mcp[mcp]
  control -- "annotations, export" --> tui
```

## Storage layout

The gateway has no database server: each session is a self-contained bundle, and a
small global catalog lists them.

```
data/
  catalog.sqlite                 # session list + tag/group definitions
  sessions/<id>/
    capture.pcap                 # raw capture (packet sources)
    key.log                      # TLS secrets (NSS key-log)
    flows.sqlite                 # decoded flows, headers, ws/custom messages, annotations
    blobs/<sha256>               # bodies/payloads too large to inline
```

A bundle is portable on its own (tag/group definitions are mirrored into it), which is
what makes session export/import a single `.tar.gz` (catalog row + the bundle files).
See [ADR-0001](adr/0001-embedded-per-session-sqlite.md).

## Decode pipeline

The gateway shells out to `tshark` for the heavy lifting (TCP reassembly, TLS
decryption, HPACK/QPACK) — see [ADR-0002](adr/0002-tshark-for-dissection.md) — parses
its per-frame PDML, and stitches frames into flows. Custom non-HTTP protocols are
decoded by compiled-in Go modules.

```mermaid
flowchart TD
  pcap[capture.pcap + key.log] --> tshark["tshark -T pdml"]
  tshark --> stitch[stitcher]
  stitch --> http["HTTP/1.1 · HTTP/2 · HTTP/3 flows"]
  stitch --> ws["WebSocket frames\n(message records)"]
  stitch --> meta["per-TLS-stream metadata\n(SNI, stream index)"]
  meta --> match{matches a\ncustom decoder?}
  match -- yes --> follow["tshark -z follow,tls,raw\n(decrypted bytes)"]
  follow --> dec[decoder session]
  dec --> custom["custom-protocol frames\n(message records)"]
```

- One PDML `<proto>` element becomes one stitcher record, so multiplexed HTTP/2 frames
  in a single packet keep their own stream id. See
  [ADR-0003](adr/0003-per-frame-pdml-decode.md).
- HTTP request/response pairs become `Flow`s; WebSocket and custom-protocol frames
  become **message records** bound to their flow, rendered as one directional timeline.
  See [ADR-0005](adr/0005-message-shaped-records.md).
- Custom decoders are compiled-in Go modules that self-register; each is a stateful
  framer fed the connection's decrypted byte stream. See
  [ADR-0004](adr/0004-compiled-in-go-decoders.md).

## Live vs. batch decode

A streaming capture is decoded **live** so flows appear while the user browses. By
default the live decode is authoritative — its flows are persisted on close and no
`tshark` batch pass runs (`GATEWAY_RECORD_LIVE`, on by default). Set
`GATEWAY_RECORD_LIVE=off` to instead run an authoritative **batch** tshark pass that
re-decodes the finalized capture on close (e.g. to verify the live decoder, or for
full-fidelity bodies). The live pipeline itself is toggleable (`GATEWAY_LIVE_DECODE`);
when off, captures are archived and decoded only by the batch pass on close.

```mermaid
flowchart TD
  up["UploadCapture chunks"] --> tee{tee}
  tee --> archive[(append to capture.pcap)]
  tee --> pipe["Go decode pipeline"]
  pipe --> hub[live hub]
  hub -- "StreamFlows / StreamMessages" --> client[viewer / mcp]
  hub -. "on close (record-live, default)" .-> sqlite[(flows.sqlite)]
  archive -. "on close (GATEWAY_RECORD_LIVE=off)" .-> batch["batch tshark decode"]
  batch --> sqlite
```

- The live decode is **fully in-process in Go — no tshark**. A single pipeline
  reassembles TCP and QUIC (`gopacket`, incl. the Android NFLOG link type), decrypts TLS
  (1.0–1.3 + SSL 3.0) and QUIC from the key-log, and frames HTTP/1.1, HTTP/2, HTTP/3,
  WebSocket and custom raw-TCP protocols — plaintext or TLS. See
  [ADR-0006](adr/0006-in-process-tls-decryption.md).
- `tshark` is used only for the **optional batch decode** on close (`GATEWAY_RECORD_LIVE=off`,
  or `verify-live`) and for pcap import — never for the default live capture path.
- In record-live mode (default) the live decode is authoritative and persisted on close.

## Capture sources

```mermaid
flowchart LR
  subgraph pkt[packet sources → UploadCapture]
    c[Chrome: dumpcap + SSLKEYLOGFILE]
    a[Android: Frida libssl key-log + UID→NFLOG tcpdump]
  end
  subgraph flow[flow source → PushFlows]
    m[mitmproxy: terminates TLS, pushes decoded flows]
  end
  c --> gw[gateway]
  a --> gw
  m --> gw
```

- **Chrome** and **Android** are *packet* sources: they stream a pcap + a TLS key-log,
  and the gateway decodes. Android captures one app's traffic from a rooted
  device/emulator (Frida hooks the system `libssl` for the key-log; the app's packets
  are isolated by UID). See [ADR-0007](adr/0007-android-per-app-capture.md).
- **mitmproxy** is a *flow* source: it terminates TLS and pushes already-decoded flows,
  so no pcap/key-log is involved.

## Capture-tools structure

Each capture tool is an independent app with isolated dependencies (installing the
Chrome tool pulls neither `mitmproxy` nor `frida`), sharing a light `capture_sdk`. See
[ADR-0008](adr/0008-independent-capture-apps.md).

## Architecture decisions

The decisions above are recorded as ADRs in [`docs/adr/`](adr/).

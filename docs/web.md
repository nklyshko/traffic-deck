# The web viewer

A browser viewer over the gateway: sessions, flows, bodies, WebSocket timelines, A/B compare, a
value decoder, and capture control. It shows what the TUI shows, on one loopback port.

```sh
GATEWAY_VIEWER=web trafficdeck        # starts the gateway, opens the browser
```

To make it the default, install with `make install VIEWER=web`, or set `GATEWAY_VIEWER = "web"`
in `~/.traffic-deck/config.toml`, which also covers dev builds. If a gateway is already running,
the same command attaches to it.

**To stop it, press Ctrl-C in the terminal.** Closing the browser tab stops nothing, so a capture
keeps running and you can reopen the URL. Ctrl-C ends the gateway too if this command started it,
along with its captures. An attached viewer leaves the gateway running.

| Env | Default | Meaning |
|-----|---------|---------|
| `TRAFFICDECK_WEB_ADDR` | `127.0.0.1:18890` | HTTP listen address. It serves captured traffic with no authentication, so keep it on loopback. |
| `TRAFFICDECK_WEB_OPEN` | `1` under `GATEWAY_VIEWER=web` | open the default browser once the server answers |
| `TRAFFICDECK_WEB` | | override which binary the gateway launches |
| `TRAFFICDECK_WIRESHARK` | `wireshark` on `PATH`, then the macOS app | the Wireshark the **wireshark** button starts; read at startup |
| `GATEWAY_ADDR` | `127.0.0.1:7331` | the gateway to talk to |
| `NO_COLOR` | | no colour in the startup banner |

## Filters

The filter box takes [the same language](filters.md) as the TUI, and the gateway evaluates it.
The controls under it edit the same expression. Focus the empty box for the whole syntax, type
`~` to narrow it, Tab to insert, Ctrl-Space to reopen. In the message timeline the box takes the
message dialect, applied on Enter.

Selecting a row: ↑/↓ move, Home/End jump within the loaded rows, Esc clears.

## Open a request in Wireshark

**wireshark** in a flow's details opens Wireshark on the session's `capture.pcap`. The session's
`key.log` is set as `tls.keylog_file`, so TLS is decrypted there too. The display filter is the
flow's connection, narrowed to its stream on HTTP/2, and the cursor goes to the request's frame
when the flow has one. This is the same view the TUI's `W` opens
([tui.md](tui.md#open-a-request-in-wireshark)).

It's the one thing the web viewer does that starts a program, so it only works under these
conditions, and otherwise says why it can't:

- The web viewer listens on loopback and reaches the gateway on loopback, and the gateway reports
  this machine's hostname.
- The session has a pcap. A mitmproxy session has none.
- The page names only the session and the flow. The program is resolved at startup. The files must
  be the gateway's own `sessions/<id>/capture.pcap` and `key.log`, as regular files. The filter is
  built from addresses and ports that are parsed and printed back. Wireshark is started without a
  shell.
- The request must be same-origin JSON and carry an `X-TrafficDeck-Action` header.
- The same flow can't be opened again within 2 s, and at most 4 windows can be open at once.

## Working on it

```sh
cd web/ui
npm ci
npm test             # unit tests
npm run lint
npm run dev          # Vite on :5173, proxying /api to a running trafficdeck-web
```

`make build` builds the bundle and embeds it. Without node, `trafficdeck-web` serves a page saying
so. The design decisions are in [ADR-0018](adr/0018-web-viewer-bridge.md).

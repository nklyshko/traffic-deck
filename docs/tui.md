# The TUI

A Textual viewer over the gateway's read API: sessions → flows → detail. `↑/↓`+`Enter`
drills in, `Esc` goes back, `q` quits. Several sessions can be open at once as tabs in
the workspace.

```sh
tui/run.sh                                 # GATEWAY_ADDR overridable
# or: uv run --directory tui python -m traffic_viewer.app
```

## Keys by screen

| Screen | Keys |
|---|---|
| Sessions | `a` new capture (pick a source, then step through its options — binary, profile, … — and start) · `s` stop the focused capture · `X` start/stop the MCP server · `L` gateway/child logs · `r` refresh · `n` rename · `g` group · `e` export as a `.tar.gz` bundle · `i` import a bundle · `I` import a pcap · `c` force-close a session left open · `d` delete |
| Workspace (tabs) | `o` open another session in a tab · `[` / `]` prev/next tab · `w` close tab |
| Flow list | `f` filter (see [filters.md](filters.md)) · `C` toggle optional columns (`Conn`/`Stream`, and any source metadata key) · `c` mark/compare two requests across sessions · `l` follow new flows as they arrive · `space` select / `D` deselect · `t` tag · `F` favorite · `m` color-mark · `n` comment · `g` group · `M` WebSocket timeline for a `⇅` flow · `W` open the request in Wireshark |
| Flow detail | `b` / `B` view request/response body · `r` / `s` save request/response body · `x` export curl · `w` export raw request+response · `H` export TLS ClientHellos · `M` ws messages · `W` open in Wireshark |
| WS messages | `f` filter by payload/opcode/direction (the message dialect — see [filters.md](filters.md#filtering-a-message-timeline)) · `C` toggle decoder-field columns · `space` select / `D` deselect · `t` `F` `m` `n` `g` annotate · `l` follow new |
| Compare A/B | `s` switch A/B · `h` copy header order · `p` copy pseudo-header order · `k` copy cookie order |

Annotation keys act on the selection if there is one, else on the focused row. Bodies
in the detail view are pretty-printed (JSON reindented + syntax-colored, form fields as
key/value).

## The flow table is a window, not a page

Large sessions open straight away, because the viewer never holds one. Filtering and
paging happen in the gateway ([ADR-0012](adr/0012-server-side-filtering-and-pagination.md)):
the table shows one window of rows queried from the server, and moving the cursor off
either end fetches the adjacent window. Navigation is continuous — `↑`/`↓` and
`PageUp`/`PageDown` walk off one window onto the next, `Home`/`End` jump to the start/end
of the whole list — so the paging is invisible unless you look at the status line.

`TRAFFICDECK_PAGE_SIZE` (default 250, clamped to 50–2000) sets the window size. It bounds
how many rows Textual repaints on each keystroke and each arriving flow, so it governs how
a big session *feels*; it is not a limit on what you can reach.

The status line shows a position, not a page index:

```
1499 matching · showing 250 · ⇣ follow
20000+ flows · 3 selected
```

The count is capped rather than exact. An exact "N matching" would need a full scan of the
session on every query, so the gateway counts up to a scan cap (20,000 rows) and the
viewer renders a capped count as `N+` — never a precise number it cannot cheaply have.
Navigation never consults the total: "end of list" is a query from the end, which is why
jumping to the end and follow mode (`l`) are the same operation.

Follow mode pins the window to the tail of the **matching** set — a filter and follow
compose, and the gateway sends stream events only for flows matching the subscription's
filter. A flow that stops matching after an edit is retracted from the view explicitly.

A window that has not filled up yet grows on its own, follow or not: arriving flows are
appended below the last row, which takes nothing away from what is on screen, so a session
opened before it captured anything starts listing flows as they arrive. Once the window is
full, moving it would drop rows off the front — there follow is what keeps it on the tail,
and with follow off the arrivals are counted and reached with `End`.

Paging away from the end turns follow off, since a window that is not on the tail cannot
be tailing: `Home`, `PageUp` and `↑` off the top all stop it, and the `⇣` badge goes with
them. Applying a filter while following keeps it — the view lands on the tail of what the
new filter matches.

```
1499 matching · reconnecting…
```

A live pane holds a subscription to the gateway for as long as the capture runs, and
reconnects if it is lost — a gateway restart, a dropped connection, or asking to follow a
capture whose source has not started pushing yet. `reconnecting…` says the pane has no
live stream at that moment; it clears itself, and each reconnect re-reads the current
window so nothing that arrived meanwhile is missed. Only the gateway reporting the session
closed stops it, which is also when the `⏱` stopwatches stop.

## Decoder fields are columns

A custom protocol decoder ([decoders.md](decoders.md)) reads its own frame header —
MAX's command, sequence number and opcode — and hands those out as opaque key/value
pairs. The message timeline turns each key into a column:

```
      Time          Dir  Opcode  Len   Preview          max.cmd      max.opcode       max.seq
 ●    14:22:07.114  C→S  binary  793   {"token":"…      Request(0)   Auth(19)         17
      14:22:07.152  S→C  binary  36885 {"chats":[…      Response(1)  Auth(19)         17
      14:22:07.230  C→S  binary  147   {"chatId":…      Request(0)   GetMessages(49)  18
```

Nothing in the viewer or the gateway knows what `max.cmd` means: the columns are
discovered from the frames themselves, so a new decoder — or a new field on an existing
one — shows up with no viewer change at all. A well-known code renders as `Name(code)`
and an unknown one as its number, which is the decoder's own business.

The `Opcode` column stays the **transport's**: `binary` for these, because that is the
WebSocket frame the protocol message arrived in (a raw TCP stream shows the decoder's name
instead, having no frame types of its own). The protocol's own opcode is `max.opcode`
beside it. That separation is what keeps `~op ping` meaning the WebSocket control frame on
a connection whose payloads also carry an application-level ping.

They are shown by default, unlike the flow table's metadata columns: a decoder emits a
handful of fields and they are the reason to read the frame. `C` toggles one off (and it
stays off as new frames arrive), and `TRAFFICDECK_MSG_COLUMNS` pins an explicit set.
Filter on them with `~meta <key>=<re>` — see
[filters.md](filters.md#filtering-a-message-timeline).

## HTTP/2 connections and streams

HTTP/2 multiplexes many requests over one connection, so a flow carries both the
transport connection it rode on (a `tcp.stream` index, or `quic:<conn-id>` for HTTP/3)
and its stream id within that connection. The flow detail always shows them
(`conn=12  stream=5`), and the flow table has optional `Conn`/`Stream` columns — one
`Conn` value repeated across rows with different `Stream` values *is* connection reuse.
Filter with `~conn`/`~stream` to isolate one connection's streams (both are regexes
like every other term, so anchor to pin an exact id: `~conn ^12$` — unquoted, since
arguments are not quote-parsed).

The pcap-based sources (`capture_chrome`, `capture_android`) show both columns by
default — they decode the frames off the wire, so the ids are the client's real ones.
`capture_mitmproxy` doesn't: mitmproxy terminates the connection, and its addon API
never exposes the HTTP/2 stream id, so both fields stay empty for proxy-captured flows.

## Open a request in Wireshark

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

# 0018 — The web viewer is a separate binary that bridges HTTP to the gateway's gRPC

Status: accepted

## Context

The gateway speaks plain gRPC on loopback, which a browser cannot call. A browser viewer needs
something to translate, and that something has to serve captured traffic, cookies and tokens
included, on a port with no authentication
([0010](0010-supervisor-and-capture-modules.md) leaves viewers as clients of the gateway).

## Decision

**1. `trafficdeck-web` is a second binary, resolved like the TUI.** It is a client of the
gateway over gRPC and imports only the public stubs in `gateway/gen`. `web/` is its own Go
module, so `internal` packages are out of reach by construction. Building the bridge into
`trafficdeck` was considered: it needs no install step, but it would put an HTTP server on the
process that owns capture and blur the line 0010 drew.

`GATEWAY_VIEWER=web` selects it, and as with `tui` the built-in name wins over a module of that
name. There is no `trafficdeck web`: a bare `trafficdeck` already attaches its viewer to a
gateway that is running. Installed, the binary lives in `libexec`
([0017](0017-frozen-install.md)).

**2. The bridge is stateless.** It translates, and holds no data and no business logic. JSON is
protojson verbatim, gateway events are relayed as SSE verbatim, and filters are forwarded
unread: the gateway stays the only interpreter of the language
([0012](0012-server-side-filtering-and-pagination.md)). Control calls go through an explicit
allow-list, so a method added to the proto is unreachable from a browser until someone names it.

**3. The bundle is embedded and not committed.** A viewer is spawned with no meaningful working
directory, so the SPA is `go:embed`ded. `make build` builds it with node, and without node embeds
a page saying so, because gateway work shouldn't need a JavaScript toolchain. `make install`
fails instead: a frozen stub would only be found by opening it.

**4. Exit stays in the terminal.** Closing a tab stops nothing. It is indistinguishable from a
reload or a crash, and there can be several tabs. A Quit button would be an unauthenticated
endpoint that stops captures. So Ctrl-C ends the bridge and, as with the TUI, the viewer's exit
ends a gateway it started; an attached bridge leaves the gateway alone.

**5. Security rests on loopback plus four rules**, since there is no authentication:

- **No CORS headers, ever.** The SPA is same-origin with the API.
- **Mutations require `application/json` or `application/octet-stream`.** Both are non-simple
  types, so a cross-origin request dies at a preflight nobody answers. Accepting `text/plain`
  or a form encoding would silently disable this.
- **Captured bytes never run on this origin.** Bodies are `application/octet-stream` with
  `nosniff`, and captured HTML is shown as text.
- **The `Host` header must be this server's.** The same-origin policy keys on the name, so
  without this a site could rebind its own domain to 127.0.0.1 and read the API as same-origin.

## Consequences

- A second binary means a stale one is possible: a checkout runs whatever `make build` last left
  at its root. Rebuilding on launch would hide compile errors behind a slow start.
- A bridge crash or a taken port ends a gateway it was launched from, captures included, exactly
  as a TUI crash does. The port is bound first, so a conflict fails before any capture exists.
- HTTP/1.1 allows a browser about six connections per origin and each live tab holds one SSE
  stream, so six live sessions open at once would starve requests. Serving HTTP/2 would need TLS
  on loopback, which is not worth it for a case that has not been met.
- `web/` has a `replace` onto `../gateway`, so it builds only from a whole tree. That is the point:
  the contract can't drift from the gateway it ships with.

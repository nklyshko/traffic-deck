# Third-party capture/viewer modules

A module (e.g. a private adapter that pushes flows plus its own web UI) enrolls by dropping
a manifest in `~/.traffic-deck/plugins/*.toml` after its own setup — TrafficDeck installs
nothing. The gateway launches the declared processes at startup (in order, with
`GATEWAY_ADDR` injected) and group-kills them on shutdown; a `[control]` block whose `addr`
speaks `CaptureSourceService` registers the module as a capture source the gateway *dials*
(it appears in the TUI's source picker like a built-in). See
[ADR-0010](adr/0010-supervisor-and-capture-modules.md).

> A manifest is executable trust — whatever lands in `plugins/` runs inside TrafficDeck,
> like a shell rc file.

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

Each spawned process gets its own rolling log file under `<DATA_ROOT>/logs/` — see
[configuration](configuration.md).

A third-party **viewer** is a client of the gateway's `ViewerService` like the built-in
TUI is. It queries and filters through the gateway rather than implementing the filter
language itself ([ADR-0012](adr/0012-server-side-filtering-and-pagination.md)).

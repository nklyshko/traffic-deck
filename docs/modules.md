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
url     = "http://127.0.0.1:5173"   # optional: where this process is reachable once up
detail  = "loopback only"           # optional: one-line note for the viewer's service list

[[process]]                         # optional: a viewer, not a service
name    = "ui"
command = ["acme-viewer"]
viewer  = true                      # never auto-starts; runs only when GATEWAY_VIEWER picks it
screen  = false                     # true for a full-screen TUI (see below)

[control]                       # optional: this module is also a capture source
addr   = "127.0.0.1:7070"       # speaks traffic.v1.CaptureSourceService
source = "acme"
label  = "Acme"
```

Each spawned process gets its own rolling log file under `<DATA_ROOT>/logs/` — see
[configuration](configuration.md). A process's `url` is narration only: the gateway prints
`service "module:acme:01-web" started — open http://127.0.0.1:5173 (log: …)` and passes it to
viewers in the service list, so a UI a user has to open is discoverable without reading the
module's own output. The process's own stdout/stderr go to its log file, and are teed to the
terminal tagged `[module:acme:01-web]` whenever the terminal is the gateway's (under
`trafficdeck serve`, or one-command mode with `GATEWAY_VIEWER=none`) — never under the TUI,
where they would overwrite it.

A third-party **viewer** is a client of the gateway's `ViewerService` like the built-in
TUI is. It queries and filters through the gateway rather than implementing the filter
language itself ([ADR-0012](adr/0012-server-side-filtering-and-pagination.md)). A module
declares one by marking a process `viewer = true`, and
`GATEWAY_VIEWER` ([configuration](configuration.md)) selects it by name — `acme` when the
module declares one, `acme:ui` when it declares several. A viewer is **not** a service: it
never auto-starts, so the copy you select is the only one running. It takes the foreground
slot the TUI usually holds, inheriting stdin/stdout/stderr (its output goes straight to the
terminal, untagged) plus the `cwd`, `env` and `url` its manifest declares; when it exits,
the gateway shuts down.

`screen` says which kind of viewer it is. A full-screen TUI sets `screen = true` and the
gateway goes quiet — its logs and every child's output go to the log file, or they would
overwrite the display. A viewer that just prints a line and opens a browser leaves it
`false` and shares the terminal with the gateway's log. With no viewer at all
(`GATEWAY_VIEWER=none`) a module's UI runs as an ordinary auto-started service and the
gateway waits on Ctrl-C.

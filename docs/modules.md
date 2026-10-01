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
source_dir  = "/home/you/src/acme"          # optional: the module's git checkout (see below)
update_hint = "run ~/src/acme/update.sh"    # optional: what to run to update it

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

A `[control]` module's processes are **started on first use of its capture source**, not at
gateway launch, so its adapter and UI come up only when its capture is actually used. A
module that declares a `[control]` block and no startable `[[process]]` is the other case:
there is nothing for the gateway to launch, so whatever serves that address is yours to run
(`plugins/pktap.toml` is deliberately like this — PKTAP needs root, and a child of the
gateway has no terminal to ask for a password on). Such a source is offered to viewers
**only while it is listening**: the gateway probes the address when it builds the picker
list and leaves the source out when nothing answers, rather than letting a user pick
something that can only time out. Starting it by name anyway fails in seconds with the
address it tried.

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

## Update checks

`source_dir` opts a module into update checks: the gateway compares that checkout against its
git remote (`ls-remote`, never `fetch` — nothing in your working tree is touched) and reports
it alongside TrafficDeck itself, so a viewer can say a newer version is published. It is the
whole integration — one line in whatever already writes the manifest, no RPC to implement and
nothing to keep in sync per language. `update_hint` is free text shown with the notification,
because how to update is the module's own business; the gateway never runs it.

The gateway reads the checkout rather than asking the module, because a module is not running
most of the time: its processes start lazily on first use of its capture source, and a
dial-only source may declare none at all. See
[ADR-0014](adr/0014-update-checks-read-git.md).

A module that declares no `source_dir` is simply not checked — there is deliberately no
fallback to a process's `cwd`, which means *working directory* and only coincides with the
checkout root by accident. A checkout with no upstream branch, or one whose remote is
unreachable, is reported as unknown rather than as up to date. The whole feature is off under
`GATEWAY_UPDATE_CHECK=off` ([configuration](configuration.md)).

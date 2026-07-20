# 0010 — The gateway supervises capture; viewers are clients

Status: accepted; implemented. `ReDecode` remains unwired (never part of this decision).

## Context

Using TrafficDeck means starting several things by hand, each in its own terminal: the
gateway, the TUI, and a capture tool. A third-party module adds more — the existing one
is a private adapter that pushes flows (`IngestService`) plus an npm web UI, two more
processes again. Nothing composes them, so "run TrafficDeck" is a checklist.

The intended shape is already in the contract and was never finished.
[`control.proto`](../../proto/traffic/v1/control.proto) describes ControlService as
"viewer -> gateway -> tools" and declares `StartCapture`/`StopCapture`, while
`internal/server/control.go` says they are "not wired yet and fall through to the
Unimplemented base". The consequences of that gap are visible: nothing owns a capture
tool's process, so when one dies its session strands open — which is why
`ForceCloseSession` and the TUI's force-close exist at all. A running capture is already
modelled (a session with `SESSION_STATUS_OPEN`), and the sessions screen already lists
them. The viewer is, in effect, a supervisor UI with no start button and a stop button
that stops nothing.

Two constraints shape the rest. A module can be proprietary and unmergeable, so it is a
separate process by necessity, not by preference. And a module installs itself: setup is
never TrafficDeck's job.

## Decision

**1. One command.** `trafficdeck` with no arguments starts the gateway in-process and
runs the TUI in the foreground; `trafficdeck serve` keeps the daemon for headless,
remote, or outlive-the-viewer use. `serve()` is already thin glue over `server.Register`,
so this is a refactor, not a rewrite.

**2. The gateway supervises; viewers are clients.** Spawning, process groups, signals and
reaping live in the gateway, reached over ControlService. The TUI gains two RPC calls and
no process management. MCP and third-party viewers therefore drive capture as
first-class citizens, and a capture is never a child of whatever happened to be looking
at it.

**3. Modules are launched from drop-in manifests.** A module sets itself up and then
writes `$TRAFFIC_DECK_HOME/plugins/<name>.toml` (default `~/.traffic-deck`, the root
`capture_sdk.paths` already uses), declaring its processes with resolved cwd, command,
env and order. TrafficDeck installs nothing, checks no toolchains and probes no
versions: it injects `GATEWAY_ADDR`, starts in declared order, stops in reverse by
process group, and tees output to the gateway log. Because the manifest is generated
after a successful setup, it needs no template language.

**4. Every source is a `CaptureSourceService` server; the gateway spawns-if-needed and
dials.** One contract for all sources — built-in or third-party:

    service CaptureSourceService {
      rpc Describe(DescribeRequest) returns (SourceDescriptor);   // options, given partial params
      rpc StartCapture(StartCaptureRequest) returns (StartCaptureResponse); // → session id
      rpc StopCapture(StopCaptureRequest) returns (Empty);        // end session, stay warm
      rpc ReleaseSource(ReleaseSourceRequest) returns (Empty);    // drop the warm resource
      rpc Status(StatusRequest) returns (SourceStatus);           // provisioning|ready|capturing
    }

The gateway ensures the source process is running (spawns a built-in's `serve` mode;
for a module it is the manifest's process) and dials `CaptureSourceService` at an address
the gateway allocated or the manifest declared. There is no CLI-stdout path and no
spawn-vs-dial branch: Chrome, Android and the adapter all look identical to the gateway —
an address speaking the service. A source is both a client of `IngestService` (it goes on
calling `OpenSession`/`UploadCapture`/`PushFlows`/`CloseSession` as today) and a server of
this one. `StartCaptureRequest` gains `string source`, since `SourceKind` is a closed enum
and cannot name a module.

**5. `Describe` carries the whole option model; transient vs persistent is one policy
knob.** `Describe(source, partial_params)` returns a typed `SourceDescriptor` (params:
key, label, type, choices, default, required), so viewers render the form generically and
a module gets the same picker as a built-in. Cascading is re-description: fill the Chrome
binary, `Describe` again, get that binary's profiles; a not-yet-provisioned Android
returns a "provision required" state instead of silently booting an emulator. Whether a
source keeps a warm resource across captures is a single `keep_warm` flag, not two
lifecycles: `keep_warm=false` (Chrome) is reaped after its capture ends plus a short idle;
`keep_warm=true` (Android's emulator, the adapter) is held until `ReleaseSource`, an idle
timeout, or shutdown. `StopCapture` always ends a session and returns to `ready` — never
kills a warm source.

**6. Auxiliary services are managed processes, not sources.** Some processes are gateway
*clients* with no capture surface: the first-party MCP server, and a module's web UI. They
do not implement `CaptureSourceService`, produce no sessions, and are never dispatched
through `StartCapture` — they are opaque processes the supervisor runs with just
start/stop/status, reusing decision 3's launcher (inject `GATEWAY_ADDR`, own the lifecycle,
group-kill). MCP is the first-party instance and lives in the supervisor's registry
alongside the built-in sources; a module's UI comes from its manifest. A viewer may
*toggle* such a service (the TUI gets "start/stop MCP", showing the resolved
`127.0.0.1:8765/mcp` URL and its status), but never *owns* it: the gateway does, so MCP
outlives the TUI — an agent querying sessions must not lose access when the viewer closes.
A `serve`-mode daemon can auto-start MCP headless, since agent access should not require a
TUI at all. Toggling MCP opens a port serving session data (loopback, `MCP_READONLY=true`
by default); the viewer surfaces that it is now listening, and may offer read-only vs.
mutating, because a one-tap toggle otherwise hides a network-exposure action.

## Consequences

- One terminal. Note the ceiling: this buys *one command*, not one click. Capture still
  needs `dumpcap`/`adb`/`tshark` and their privileges, which no packaging removes.
- Quitting the TUI stops the gateway and with it any running capture — but *cleanly*:
  children are signalled and sessions finalize. That is strictly better than today, where
  killing the gateway strands sessions. Captures that must outlive a viewer use
  `trafficdeck serve` + attach.
- `ForceCloseSession` keeps the job its comment claims: recovery when a tool dies anyway.
- **Resolved — dispatch direction.** The gateway dials the source (it becomes a client of
  something it normally serves), rather than the source subscribing to a command stream.
  Accepted because the supervisor launches the source, so it is local by construction, and
  a unary RPC is far easier to debug than correlating responses over a bidi stream. The
  stream alternative — which would suit sources running on another host and allow dynamic
  registration — is deferred, not designed out.
- **Resolved — dependent params.** Handled by re-description, not a static schema:
  `Describe(partial_params)` is re-called as fields fill, so a persistent source answers
  from its warm state and a transient one recomputes (idempotent, cheap). Deep cascades a
  form can't drive stay free text in v1.
- **The uniform server has a cost, now accepted.** Chrome gains a `serve` mode and runs
  its capture asynchronously so `StartCapture` can return the session id while capture
  continues — real but modest new code. It also means a cheap, idle Chrome process exists
  during selection; that is fine because the supervisor owns it (`keep_warm=false` →
  lazy spawn on first `Describe`, teardown after capture + idle), so it is a managed state,
  not an orphan. This was the trade for one gateway code path instead of two.
- **Two managed-process categories, one supervisor.** Capture sources speak
  `CaptureSourceService` and produce sessions; auxiliary services (MCP, a module's UI) are
  opaque gateway clients with only start/stop/status. Both are spawned, dialed-or-not,
  reaped and group-killed by the same machinery — the second is just the first minus the
  capture surface.
- **The supervisor owns every child uniformly.** Process groups (`setpgid`) + group-kill
  so `npm`→node and tool→`dumpcap`/emulator grandchildren never leak; reap on exit, stop,
  idle timeout and shutdown. The other half is the child's job: a source whose gateway
  vanished must notice its broken stream and exit, since a crash can't run the supervisor's
  cleanup. Orphan-avoidance is a supervisor invariant, not a per-source concern.
- **Teardown follows provisioning ownership** — the one non-uniform rule. If TrafficDeck
  booted the emulator it tears it down; if Android *attached* to one the user already had
  running, `ReleaseSource` must leave it alone. Same principle as "only close the session
  you opened".
- The CLI pickers stay for direct human use — they already skip themselves without a TTY
  (`cli.py`: `interactive = not args.no_prompt and sys.stdin.isatty()`). The `Describe`
  logic and the interactive picker must call the *same* discovery code
  (`platform.chrome_binaries`, `chrome_profiles`, `capture_sdk.state`, `list_apps`), or the
  two drift into disagreeing about defaults; factoring that shared core is a precondition,
  not a cleanup.
- The supervisor is a small process-compose, and is deliberately dumb: ordered start,
  wait-for-serve (dial until the source's `Status` answers), reverse-order group kill. No
  dependency graph, no restart policy until a second module needs them.
- A plugin manifest is code execution: whatever writes to `plugins/` runs inside
  TrafficDeck. For a local tool with self-installing modules that is the right trade, and
  it makes the directory trust-equivalent to a shell rc file — documented, not
  mechanised.

# 0015 — An agent starts and stops captures through the MCP server

Status: accepted; implemented — `list_capture_sources`, `describe_capture_source`,
`start_capture` and `stop_capture` on the MCP server, behind the same `MCP_READONLY` gate
as the session edits. No gateway or proto change: the RPCs already existed for the viewers.

## Context

The MCP server ([mcp.md](../mcp.md)) can read a capture in every way a viewer can, and
cannot produce one. Its "driving a capture" surface was `wait_for_flows` — the *second*
half of a loop whose first half no agent could reach. So every agent-run investigation
began with a human opening the TUI, pressing `a` and stepping through a wizard, and the
agent could only work on traffic somebody else had already recorded.

Meanwhile `ControlService` has had `ListCaptureSources`, `DescribeCaptureSource`,
`StartCapture` and `StopCapture` since [0010](0010-supervisor-and-capture-modules.md),
because the gateway supervises capture and *every* viewer is a client of it. The MCP server
is a client like the TUI is. Nothing was missing but the exposure.

What is genuinely missing is a way to hand the browser over. A browser source **launches**
the browser itself, because `--ssl-key-log-file` has to be set on that process from the
start — that is what makes the traffic decodable at all
([0006](0006-in-process-tls-decryption.md), [0009](0009-native-live-decode-default.md)). An
agent that drives a browser through some other tool is driving a *different* browser, one
with no key-log, and a capture of it records bytes nothing can decrypt. Every component
reports success and the session is useless.

## Decision

**1. Four tools, mirroring the RPCs, with no new control plane.** `list_capture_sources` →
`start_capture` → (produce the traffic) → `wait_for_flows` → `stop_capture` → read it with
the existing tools. The gateway already serializes and routes all of this for the TUI; a
second implementation for agents would be a second set of bugs.

**2. `start_capture` works with no parameters.** Every source already resolves its own
defaults — a browser source opens a fresh temporary profile — so `start_capture("chrome")`
is a complete call. `describe_capture_source` exists for choosing something specific, and
is cascading (answering one option changes which options come next), which is a loop worth
making optional rather than mandatory. An agent that had to walk a four-step wizard to do
the common thing would get it wrong often enough to matter.

The response reports `params_sent` — what actually went to the source, including anything
this server added — rather than echoing the request. The transcript is then an honest
record of what ran.

**3. A capture started by an agent auto-stops by default.** Nothing in the gateway closes
an abandoned live session: there is no reaper, by design, because a capture's end is the
source's business. So an agent that starts a capture and then fails holds a browser open
and a session unfinished indefinitely, and the operator finds out later.

Sources that offer a `duration` option already auto-stop, so the default uses the source's
own mechanism and introduces nothing. Five minutes: longer than the interactions this is
for, short enough that a forgotten capture is a nuisance rather than a leak.
`duration_seconds=0` opts out.

It is applied **only when the source declares that option** — a proxy source does not — and
the response says which happened. Setting a params key no source reads would do nothing at
all, and reporting an auto-stop that will never fire is worse than admitting there is none:
the caller has to know whether it owns the stop.

**4. The gate is `MCP_READONLY`, not a flag of its own.** A separate switch is defensible —
renaming a session and launching a browser are different blast radii — but it splits one
question ("may this server do things, or only look?") into two, and an operator who has
answered yes once should not have to discover a second flag. The existing `_write_tool()`
decorator leaves the tools unregistered in read-only mode, so a read-only server does not
advertise them at all; it is not a permission check that can be argued with.

**5. Only captures the gateway started can be stopped.** `StopCapture` routes by the
session→source map the manager built at start, so a capture launched from a command line
has no route and errors. The tool says to stop it where it was started rather than pointing
at a force-close it does not expose — an agent force-closing a human's capture is a worse
outcome than an agent that cannot help.

**6. Calls that may spawn a source carry a two-and-a-half-minute deadline.** The first
describe or start of a source *starts* it, and the built-ins launch through `uv`, which on
a cold environment resolves and builds the tool's dependencies first — the gateway allows
two minutes for exactly this (`sourcemgr.readyTimeout`) and the TUI paints a "this can take
a minute" notice over the same wait. A client default of thirty seconds would give up
mid-build, leaving the source coming up behind a call that already failed. An installed
component starts without `uv`, so this wait applies to dev; the first-use Frida build, which
does not fit it, runs independently of the call ([0017](0017-frozen-install.md) §5).

## Consequences

- An agent can run the whole investigation: start a capture, make the traffic happen, read
  what it produced. For a source that takes a `url`, "make the traffic happen" is a
  parameter, so the loop closes without any tool outside this server.
- **An agent cannot drive the browser the gateway launched.** There is nothing to attach
  to: no remote-debugging port is passed, and the browser's profile is a fresh temporary
  one. The paths that do work today are a `url` parameter, or the `mitmproxy` source with
  the agent's own browser pointed at the proxy — which costs the real client fingerprint
  and the `conn`/`stream` columns, since mitmproxy terminates TLS. Passing
  `--remote-debugging-port` through as a source option is the obvious next step and was
  deliberately left out of this change.
- Nothing stops an agent and a human capturing at once. They mostly do not collide — a
  browser source refuses a second launch on the same profile with an actionable error, and
  the agent's default profile is a fresh temporary one — but two agents sharing one named
  profile will.
- Sessions an agent started are labelled `agent` by default, so they are identifiable in
  the session list. That is a convention, not a guarantee: the label is free text and the
  gateway records nothing about who asked.
- A capture with no auto-stop (a source without that option, or an explicit opt-out) is the
  one case where an abandoned session still leaks. The honest `note` on the response is the
  whole mitigation; a gateway-side reaper for live sessions remains unbuilt.

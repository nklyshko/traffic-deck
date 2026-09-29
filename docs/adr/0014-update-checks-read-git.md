# 0014 — Update checks read git; modules declare a source directory, not a version

Status: accepted; implemented in this repo — the gateway's checker and `CheckUpdates`, the
manifest's `source_dir`/`update_hint`, and the TUI's `U`. A third-party component opts in on
its own side: a module by declaring `source_dir` in the manifest it already writes, a
third-party viewer by adding its own notification policy over the RPC.

## Context

Nothing in TrafficDeck tells a user that a newer version exists. The gateway, the TUI, the
MCP server and every capture module are git checkouts that a person updates by pulling —
and nothing notices when they have not. For a bundle install the situation is worse than for
a single repo: an installer lays down several checkouts — TrafficDeck, each module it brings,
and its own — and its `update.sh` pulls all of them, so "is an update available" is a question
about a *set* of repos, not one.

The obvious shape — ask each module what version it is, over the existing control plane —
does not survive contact with how modules actually work ([0010](0010-supervisor-and-capture-modules.md)):

- **Modules are not running most of the time.** A module with a `[control]` block has its
  processes started lazily, on first use of its capture source (`sourcemgr.ApplyManifests`).
  `plugins/pktap.toml` deliberately declares *no* `[[process]]` at all — PKTAP needs root,
  so the user starts it by hand and the gateway only dials it. An RPC can reach none of
  these at gateway launch, which is exactly when a notification is wanted.
- **It would be reimplemented per language.** The gateway is Go, the TUI and MCP server are
  Python, and a module is written in whatever its author chose. Every module would grow its
  own copy of the same git plumbing.
- **`CaptureSourceService` is a capture protocol.** `Describe`/`StartCapture`/`Status`
  concern one capture. Adding version reporting there couples module releases to gateway
  releases for a fact that has nothing to do with capturing.
- **A module does not reliably know its own version.** It would have to shell out to `git`
  in its own checkout — the same call the gateway can make, one process earlier.

Meanwhile the gateway already holds the one fact the check needs: manifests carry absolute,
machine-specific paths (`cwd`, `command`), because a module writes its own manifest during
its own setup. And the gateway already locates its own repo by walking up from
`os.Executable()` (`findTUIDir`, for `tui/`).

## Decision

**1. The gateway performs every check, by reading git.** One implementation, in Go, covering
itself and every module. Git is the authority on "is something newer published"; a version
string a module reports about itself is a second copy of that fact, kept by hand.

**2. A module opts in with `source_dir` in its manifest — a new optional key, and no new
RPC.** The manifest is already how a module describes itself declaratively, and it is
readable whether or not the module is running:

    name = "acme"
    source_dir  = "/home/you/src/acme"
    update_hint = "run ~/src/acme/update.sh"

`update_hint` is free text shown with the notification, because *how* to update is
module-specific: a bundle install is updated by its `update.sh`, a lone checkout by
`git pull && make build`. The gateway does not guess, and it never runs the hint.

**TrafficDeck's own hint is a setting, `GATEWAY_UPDATE_HINT`, because it is the one component
with nowhere to declare it.** Every module has a manifest; TrafficDeck has none, and a manifest
claiming this checkout loses the dedupe below to the gateway's own entry — so without a setting
there is no way to correct the advice. Correcting it matters because the viewer prints each
component's hint: an install where one script updates several checkouts would otherwise show
`git pull && make build` for TrafficDeck beside that script for every module, which is a menu
where one action was wanted, and the `git pull` half of it leaves the modules unrebuilt. It is
read through the normal config path, so an installer can set it in the launcher it writes
without editing anyone's `config.toml`.

**There is deliberately no fallback to `[[process]].cwd`.** For the modules that ship today
the cwd happens to equal the checkout root, which makes the fallback tempting — but `cwd`
means *working directory*, and the two coincide by accident. A module without `source_dir`
is simply not checked; telling someone to update the wrong thing is worse than telling them
nothing.

This also lets a component that is *only* a checkout enroll itself. `LoadManifests` requires
nothing but `name`, and `ApplyManifests` registers nothing from a manifest with no
`[[process]]` and no `[control]` — so a bundle installer can drop a manifest naming its own
checkout and have it version-checked without pretending to be a capture source.

Components are de-duplicated by resolved path (`sourcemgr.Dedupe`), TrafficDeck first, so a
manifest naming a directory *inside* the TrafficDeck checkout does not also appear as a
component of its own — `plugins/pktap.toml` points at `capture/capture-pktap.sh` and is not
a repo. Order is the priority, and symlinks are resolved because a checkout reached two ways
is still one checkout. This is also what lets an installer over-declare while each module
grows its own `source_dir` at its own pace, without anything being reported twice.

**3. The comparison is `git ls-remote`, not `git fetch`.** For each checkout: resolve the
upstream branch, `ls-remote` its tip, and report an update when that commit is not present
locally (`git cat-file -e`).

`fetch` + `rev-list --count HEAD..@{upstream}` would yield a commit count, which reads
better. It also downloads objects and writes remote-tracking refs into the user's checkout —
from a background task in a long-lived daemon, against a repo the user may be working in.
An update notification does not justify mutating a working tree, so the count is given up.
Reporting "not present locally" rather than "differs from HEAD" is what keeps a checkout
with local commits from being reported as behind.

Every git call runs with prompting disabled:

    GIT_TERMINAL_PROMPT=0
    GIT_SSH_COMMAND=ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new

This is not defensive dressing. `manifest.go` already records that the gateway spawns
children with no controlling terminal, which is why `plugins/pktap.toml` cannot answer a
sudo prompt; a git that decides to ask for an SSH key passphrase or a host-key confirmation
has the same problem, and would sit until its timeout with nothing on screen to explain it.
Disarmed, the same case returns an error string the viewer can show.

**4. The viewer owns the cadence; the gateway keeps one schedule, at launch.** The gateway
checks once after the server is listening, so a viewer's first paint usually has a warm
answer. It runs no periodic loop: a timer is state to get wrong, and the component that
knows when a notification is *due* is the one that knows whether it has already shown it.

`CheckUpdatesRequest.refresh` is how a viewer asks for more:

- `refresh = false` answers from cache without touching the network — the first-paint call.
- `refresh = true` contacts each remote before answering, so it can take as long as the
  per-component timeout and needs a deadline.

A browser-based viewer's policy can be one notification per day, tracked in its own storage
and evaluated on page open; the TUI's is a keypress. Neither needs the gateway's agreement,
and a second viewer does not inherit the first's schedule.

The gateway protects itself rather than trusting the cadence: refreshes are serialized, and
one arriving within seconds of the last completed check returns the cache instead of dialing
out. Ten browser tabs opening at once therefore cost one round of `ls-remote`. A
`refresh = true` that returns an unchanged `checked_unix_ms` is a normal outcome, not an
error, and the proto says so.

That floor is deliberately **seconds, not minutes**. It exists to collapse a burst, and it
has to outlast nothing longer than one; the gateway cannot tell an automatic poll from a
human pressing "check for updates", so a floor long enough to be felt turns into a viewer
insisting everything is up to date after something was published. It was three minutes
first, and that is exactly what happened.

**5. `CheckUpdates` is a new RPC on `ControlService`, not a field on `ListServices`.**
`ServiceInfo` describes one gateway-owned *process*; updates are a property of a *checkout*.
The two do not line up in either direction — `pktap` has a manifest and no process, and
TrafficDeck itself is not a service at all.

**6. Failure is per component, and "unknown" is never allowed to read as "up to date".**
`ComponentUpdate.error` explains why one entry is unknown, and `update_available` is false
whenever it is set. A module cloned from an unreachable internal git host must not prevent the
gateway from reporting that TrafficDeck itself has moved on.

The dangerous case is the *whole answer* being unknown: no check has completed, or checking
is switched off, and `components` is empty with `checked_unix_ms = 0`. An empty list renders
as "nothing to update" in any UI written the obvious way. So the rule is enforced one level
below the UI, in each viewer's gateway client: the TUI's `client.py` returns `None` for that
case, a browser client returns `null`, and neither hands the raw message to UI code. The
distinction becomes unrepresentable rather than merely documented — a tri-state enum in the
proto would also work, but it adds a wire-level enum for a state the timestamp already
encodes.

**7. On by default, with `GATEWAY_UPDATE_CHECK=off`.** The traffic is one `ls-remote` per
checkout at launch, plus whatever the viewers ask for, to the remotes the user cloned from —
not to us, and carrying nothing. A check nobody enables is a check that never fires, so
silence by default would defeat the purpose; the kill switch is there because it is still an
outbound connection made without being asked each time.

## Consequences

- Adding update awareness to a module is one line in whatever already writes its manifest.
  No release coordination, no proto change, nothing to implement per language.
- A module that never declares `source_dir` is invisible to the feature. That is the
  intended failure mode, and it means the notification can under-report — silently.
- The gateway now shells out to `git` and assumes each component is a git checkout with an
  upstream. A tarball install, a vendored copy or a detached HEAD reports as unknown, not as
  up to date.
- No commit counts, and no "you are N behind". The notification can say *that* something is
  published, not how much.
- Manifests are already executable trust (`manifest.go`: "whatever is dropped in plugins/
  runs inside TrafficDeck"). `source_dir` widens that slightly in a different direction: a
  manifest now names a path the gateway runs `git` in. It is read-only git, but it is a
  path the gateway would not otherwise have touched.
- A bundle installer's own update script keeps a reason to exist: it answers before the
  gateway is started, and it can check the installer's own checkout without a manifest.
- Nothing re-checks on its own after launch. A gateway left running for a week reports what
  was true at launch until a viewer asks for a refresh, which means the feature is only as
  good as the viewer policies — and a viewer that never refreshes goes stale silently. The
  trade is deliberate: the alternative is two schedules disagreeing about the same fact.
- `refresh = true` is a network call a viewer can trigger, so the rate floor is load-bearing
  rather than an optimisation. Without it, a page-reload loop in a browser-based viewer
  becomes an `ls-remote` loop against someone's git host.

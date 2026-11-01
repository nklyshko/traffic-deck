# 0017 — A frozen install lives in a self-contained prefix; the running binary picks its code

Status: accepted

## Context

TrafficDeck runs from its checkout, and that is fine until the tool is relied on while it is
being worked on. There was no way to keep a known-good copy beside a moving tree, and building
one would not have helped, for two reasons:

- **Lookup followed the working directory.** `findCaptureDir`, `findTUIDir` and `selfDir` walk
  up from `cwd`, so a perfectly installed binary run from inside the repo picks up checkout
  code. An update check from there reports on whichever checkout you stand in.
- **Packaging reached back into the source tree.** `capture_sdk` is an editable path dependency
  ([0008](0008-independent-capture-apps.md)), the TUI and MCP server are not buildable packages,
  and `capture_android` shells out to `uv run --project <checkout>` and finds `capture_mitmproxy`
  as a sibling directory.

The cause is the lookup order as much as the packaging, so fixing either alone leaves a leak.

## Decision

**1. `make install` builds a self-contained prefix.** `PREFIX` defaults to
`~/.local/share/trafficdeck`, and `~/.local/bin/trafficdeck` is the only thing placed outside it,
so upgrading or uninstalling is replacing a directory.

    <prefix>/bin/trafficdeck
    <prefix>/python/                 the interpreter every venv is built on
    <prefix>/wheels/*.whl
    <prefix>/requirements/*.txt      exported from each uv.lock
    <prefix>/venvs/<component>/      not editable; one per component, as 0008 requires
    <prefix>/venvs/android-frida-<version>/   one per supported Frida version (§5)
    <prefix>/libexec/                the venvs' console scripts
    <prefix>/install.toml            commit, dirty, source_dir, remote, branch, date, viewer

The interpreter is part of the prefix. A venv records the Python it was built on by absolute
path, so building on whichever one was on `PATH` (mise's, Homebrew's) would tie the install to
it, and removing that Python would break the install. uv's Python builds run from any
directory, so it is fetched into the staging directory with everything else and moved in; the
build configuration that names the staging directory (sysconfig, `python3-config`, pkg-config)
is then rewritten to the prefix. The version is an exact release, for the same reason the
dependencies are locked.

Third-party dependencies come from each component's `uv.lock` and first-party wheels are
installed with `--no-index`. `--find-links` alone would resolve to whatever is newest on install
day, and two installs of one commit could differ. A version is `0.0.0+g<sha>`, because a repo
with no tags makes `git describe` return a bare hash, which is not a valid Python version.

The Python stubs are one package, `trafficdeck-proto` (`proto/python`), a dependency of the TUI,
the MCP server and `capture_sdk`. It is separate from the SDK so that neither client takes on a
capture library to reach the contract, and it is a first-party wheel like the SDK.

A dirty tree is refused unless `ALLOW_DIRTY=1`, which is recorded and shown by
`trafficdeck version`: "frozen" means nothing if the recorded commit does not describe the code.

**2. Resolution depends on which binary is running, never on `cwd`.** One resolver replaces the
three walks. An installed binary is one with `<exe>/../install.toml`, symlinks resolved first
(macOS `os.Executable` may return the link):

- Installed: `TRAFFICDECK_*` override → `libexec`. A missing component is *not installed*.
- Dev: `TRAFFICDECK_*` override → checkout found from the executable → `PATH`.

An installed binary deliberately has no `PATH` fallback: a stray console script from a dev venv
on `PATH` would be checkout code again. `go run` no longer finds a checkout; it builds into a
temporary directory, and nothing documented relies on it. Such a binary, like a copied one,
has no data root of its own and refuses to open a catalog until `DATA_ROOT` names one.

**3. Data is separated by binary, the home is shared.** `DATA_ROOT` defaults to
`~/.traffic-deck/data` when installed and `<checkout>/data` in dev, and is removed from
`mise.toml`: mise exports it to anything started inside the repo, so an installed binary launched
there would use the dev catalog. This separation is a requirement, not tidiness. A gateway refuses
a database written by a newer one (`ErrSchemaNewer`), so a dev migration on a shared catalog would
lock the installed gateway out.

`~/.traffic-deck` stays shared. A separate dev home was considered and rejected: saved browser
profiles and enrolled modules would have to be duplicated. What sharing costs is in Consequences.

Both keep `:7331` and `:8765`. Distinct dev defaults would let both run with no setup, but
`capture/*.sh` run by hand default to `7331`, so a dev capture would silently land in the installed
catalog. A second concurrent instance sets `GATEWAY_ADDR` and `MCP_PORT` and otherwise fails
loudly on the port.

**4. Update checks compare the installed commit.** This amends
[0014](0014-update-checks-read-git.md). `git cat-file` in a checkout answers "does the checkout have
this?", which stops being the question: after a `git pull` without `make install` the checkout has
the commit and the install does not. So an installed gateway `ls-remote`s the remote and branch
recorded in `install.toml` and compares the tip with the recorded commit. If `source_dir` still
exists, it also asks whether the installed commit already contains the tip, so an install ahead of
its remote is not reported as behind. Without it that case can be a false alarm, which is harmless.
The default hint is `make install` when installed.

**5. Android has no checkout dependency; every Frida version is installed.** Client and
frida-server versions must match, so a capture runs under the version chosen for its device, and
the base venv holds none: the CLI and source process do not import it, and the proxy method does
not load it. `make install` builds `venvs/android-frida-<version>` for each version in
`frida_versions.SUPPORTED`, so that file stays the one place the versions are named. The venv is
named for the exact version rather than the major, so a mismatched client cannot pass for the
right one.

Building each version on first use instead was tried and dropped. It kept the install smaller
(about 110 MB per version) but needed `uv`, the network and a writable prefix at capture time,
and could outlast `StartCapture`'s deadline ([0015](0015-agents-drive-capture-over-mcp.md) §6),
which took a background build, a lock, and a "retry shortly" error to cover. Installing both
leaves nothing to write into the prefix at runtime.

The proxy method runs `mitmdump` from the sibling `capture_mitmproxy` venv, so Android does not
inherit mitmproxy's dependencies. `frida_scripts/` moves into the package because the Java bridge
is required at runtime on Frida 17; its `node_modules` is build tooling and stays out.

## Consequences

- `trafficdeck` on `PATH` stays frozen until `make install`; `make build && ./trafficdeck` in any
  worktree is a dev build against that worktree's code.
- **Modules are not frozen.** The installed gateway loads every manifest in the shared `plugins/`,
  including ones pointing into a checkout. Modules are versioned separately, with their own
  `source_dir` checks, so this is accepted.
- `config.toml` is read by both, so it must not set `DATA_ROOT`, `GATEWAY_ADDR` or
  `GATEWAY_UPDATE_HINT`. Fingerprints are shared too, and one saved browser profile cannot serve
  two captures at once. Remembered selections tolerate this: invalid state reads as empty.
- **Rollback is not supported.** Once a newer install migrates the data, an older one fails with
  `ErrSchemaNewer` until you move forward again. The failure is loud and loses nothing. Backing up
  the catalog would only be a partial answer, since session bundles are versioned too.
- Every supported Frida version is installed whether or not it is used, about 110 MB each.
- Stopping an Android capture changes shape when installed: `proc` is the capture itself rather
  than a `uv run` wrapper. One SIGINT still reaches it exactly once, which was verified on a
  device.
- An install stages in a hidden `.trafficdeck-stage.*` beside the prefix, not in `/tmp`, so the
  result moves in by rename and the throwaway venvs can hardlink uv's cache. One left by a
  killed install is removed by the next. Installs into one parent directory take a lock, so
  that cleanup never meets a stage still in use.
- The prefix can be moved, which an app bundle needs: the venvs are `--relocatable` and reach
  the prefix's Python by a relative link. Two things still name the old path and are
  harmless: each `pyvenv.cfg`'s `home` (Python finds its base through the link) and the
  Python's build configuration (only a C extension built against it would notice).
  `~/.local/bin/trafficdeck` is outside the prefix and must be re-linked. Moving is not
  porting: the prefix holds platform-specific packages and is built on the machine it runs on.

# Getting traffic in

Six ways to feed the gateway. The first is offline; the others capture live and
stream flows into the TUI as they happen. All of them can be started from the TUI's
sessions screen (`a`), which is usually easier than the command lines below — the gateway
supervises the capture tool for you. The CLIs are here for scripting and for running a
capture against a remote gateway.

- [A) Import a pre-captured pcap + key.log](#a-import-a-pre-captured-pcap--keylog)
- [B) Live-capture Chrome](#b-live-capture-chrome)
- [C) Live-capture Firefox](#c-live-capture-firefox)
- [D) mitmproxy (any device, incl. WireGuard)](#d-mitmproxy-any-device-incl-wireguard)
- [E) Android (rooted emulator/device, per-app)](#e-android-rooted-emulatordevice-per-app)
- [F) Chrome, per-process (macOS, PKTAP)](#f-chrome-per-process-macos-pktap)

See also [`capture/README.md`](../capture/README.md) for how the capture apps are
structured, and [ADR-0008](adr/0008-independent-capture-apps.md) for why each is its own
project.

## A) Import a pre-captured pcap + key.log

```sh
mise exec -- go -C gateway run ./cmd/gateway import \
    --pcap capture.pcap --keylog key.log --label demo [--decoder tshark|native]
```

The `key.log` is an NSS keylog (e.g. from `SSLKEYLOGFILE`); without it HTTPS can't be
decrypted. The pcapng-with-embedded-secrets case works too — pass just `--pcap`.

`--decoder` picks the batch decoder: `tshark` (default) orchestrates tshark, while
`native` runs the same in-process Go pipeline as live capture (no tshark needed). Both
decoders read classic pcap and pcapng.

You can also import from the TUI: press `I` on the sessions screen to pick a pcap, an
optional key.log, and the decoder. The paths resolve on the gateway host (the local host
under one-command mode).

## B) Live-capture Chrome

Launches Chrome with a dedicated `SSLKEYLOGFILE`, captures with `dumpcap`, and streams
to the gateway live (`STREAMING_LIVE`) — decrypted flows appear in the TUI as you
browse. Capture is interface-wide, but only Chrome's TLS sessions have keys, so the
**decoded view is effectively Chrome-only**.

Interactive (recommended) — the launcher activates the `wireshark` group itself (via
`sg`), then lets you pick the Chrome binary and the profile: the **browser's own
default** (launched with no `--user-data-dir`), a fresh temp profile, or a named
persistent profile (pick an existing one or create a new one) under
`~/.traffic-deck/chrome-profiles`. The pickers default to your previous run's choices
(remembered under `~/.traffic-deck/state`):

```sh
capture/capture-chrome.sh
```

Scripted / explicit — flags override each picker; `--no-prompt` skips them:

```sh
sg wireshark -c 'uv run --project capture/capture_chrome trafficdeck-capture-chrome \
    --no-prompt --label "live demo" --url https://example.com'
```

Against an **existing** Chrome profile (e.g. Chrome Canary) — keeps your logins,
extensions, history. Quit any Chrome already running on that profile first, otherwise
the launch just attaches to the running instance and no TLS keys are logged:

```sh
sg wireshark -c 'uv run --project capture/capture_chrome trafficdeck-capture-chrome \
    --no-prompt --chrome google-chrome-canary --label "manual test" \
    --profile-dir "$HOME/.config/google-chrome-canary"'
```

Browse, then close Chrome (or use `--duration N` to auto-stop after N seconds) to
finalize the session.

Useful flags / env:

| | |
|---|---|
| `--profile-dir DIR` | use an existing profile instead of a fresh temp one |
| `--url URL` | open a URL on launch |
| `--duration N` | auto-stop after N seconds |
| `--iface IFACE` | capture interface (default: auto-detected) |
| `--filter BPF` | dumpcap capture filter (default empty = capture everything, so proxies/non-standard ports/HTTP3 are all included; decode only surfaces Chrome-decryptable + plaintext HTTP. Narrow to e.g. `tcp port 443` for smaller captures) |
| `--gateway ADDR` | gateway address (default `127.0.0.1:7331`) |
| `CHROME_BIN` | Chrome/Chromium binary (e.g. `google-chrome-canary`) |
| `DUMPCAP_BIN` / `CAPTURE_IFACE` | override dumpcap / interface |

> `sg wireshark -c '…'` runs the whole command (and the `dumpcap` it spawns) under the
> `wireshark` group. If your shell is already in that group, you can drop the `sg`
> wrapper. The keylog is written to a temp dir, never into your real profile.

## C) Live-capture Firefox

The same shape as the Chrome path — `dumpcap` plus a dedicated key-log, streamed live —
for Firefox and its relatives (Firefox and its channels, LibreWolf, Waterfox, Zen). Only
Firefox's TLS sessions have keys, so the **decoded view is effectively Firefox-only**.

Two things differ from Chrome, both handled for you:

- Firefox has no key-log *flag*. NSS reads `SSLKEYLOGFILE` from the environment, so the
  tool sets it on the launched process.
- Profiles are registered by name in `profiles.ini` rather than laid out per channel, and
  every channel of one fork shares that registry. The picker lists what's registered and
  launches it with `-P <name>`; tool-managed profiles use `--profile <dir>` instead.

Interactive (recommended) — the launcher activates the `wireshark` group itself (via
`sg`), then lets you pick the Firefox binary and the profile: one of the **browser's own
registered profiles**, the browser's own default (launched with no profile flag), a fresh
temp profile, or a named persistent profile under `~/.traffic-deck/firefox-profiles`.
The pickers default to your previous run's choices (remembered under
`~/.traffic-deck/state`):

```sh
capture/capture-firefox.sh
```

Scripted / explicit — flags override each picker; `--no-prompt` skips them:

```sh
sg wireshark -c 'uv run --project capture/capture_firefox trafficdeck-capture-firefox \
    --no-prompt --label "live demo" --url https://example.com'
```

Against one of Firefox's **own registered profiles** — keeps your logins, extensions,
history. Quit any Firefox already running on that profile first; Firefox refuses to start
a second instance on a profile that's already open:

```sh
sg wireshark -c 'uv run --project capture/capture_firefox trafficdeck-capture-firefox \
    --no-prompt --label "manual test" --profile-name default-release'
```

Browse, then close Firefox (or use `--duration N` to auto-stop after N seconds) to
finalize the session.

Useful flags / env:

| | |
|---|---|
| `--profile-name NAME` | one of the browser's own profiles, by its `profiles.ini` name (`-P`) |
| `--profile-dir DIR` | launch a profile directory directly (`--profile`) |
| `--default-profile` | the browser's own default (no profile flag) |
| `--url URL` | open a URL on launch |
| `--duration N` | auto-stop after N seconds |
| `--iface IFACE` | capture interface (default: auto-detected) |
| `--filter BPF` | dumpcap capture filter (default empty = capture everything) |
| `--gateway ADDR` | gateway address (default `127.0.0.1:7331`) |
| `FIREFOX_BIN` | Firefox binary (e.g. a LibreWolf or Nightly path) |
| `DUMPCAP_BIN` / `CAPTURE_IFACE` | override dumpcap / interface |

> A tool-managed profile (temp or persistent) is seeded with a `user.js` that turns off
> the first-run tour and the default-browser prompt — Firefox's equivalent of Chrome's
> `--no-first-run` / `--no-default-browser-check` flags. It's written only when absent,
> so your own edits to a persistent capture profile survive.

## D) mitmproxy (any device, incl. WireGuard)

Runs `mitmdump` with an addon that streams **already-decoded** flows to the gateway
(`PushFlows`) — no pcap/keylog, since mitmproxy terminates TLS. Unlike the Chrome path
this is an active **MITM**: the device must trust mitmproxy's CA (visit `mitm.it` once
connected, or install `~/.mitmproxy/mitmproxy-ca-cert.*`); cert-pinned apps still need
a Frida bypass.

```sh
# regular HTTP proxy on :8888 — set the device/app proxy to <this-host>:8888
uv run --project capture/capture_mitmproxy trafficdeck-capture-mitmproxy --label "api poke"

# WireGuard server — any device that can be a WireGuard client routes through it
# (mitmproxy prints the peer config / QR on startup)
uv run --project capture/capture_mitmproxy trafficdeck-capture-mitmproxy --mode wireguard --label phone
```

Flows appear live in the TUI as they complete; stop mitmdump (`q`/Ctrl-C) to close the
session. Args after `--` pass through to `mitmdump`. Flags: `--mode` (regular |
wireguard | transparent | …), `--label`, `--listen-port` (default `8888`), `--gateway ADDR`.

Because mitmproxy terminates the connection there is no pcap for these sessions, so
`W` (open in Wireshark) has nothing to open and the `Conn`/`Stream` columns stay empty —
see [the TUI guide](tui.md#http2-connections-and-streams).

## E) Android (rooted emulator/device, per-app)

Captures **one app's** traffic from a rooted emulator/device: Frida hooks the system
`libssl.so` to dump TLS secrets (NSS `key.log`, no proxy/CA), and the app's packets
are isolated by UID via `iptables … NFLOG` + on-device `tcpdump -i nflog:<group>`.
Both stream to the gateway over the same pipeline as Chrome and decode to decrypted
flows. See [ADR-0007](adr/0007-android-per-app-capture.md) for the design.

Prereqs: the Android SDK (so `adb`/`emulator` are available) and a **rooted** target.
Root is auto-detected: `adb root` (emulator / `userdebug` builds) or **Magisk `su`**
(retail devices) — capture commands elevate accordingly. The agent auto-fetches a
matching `frida-server` (GitHub) and pushes it; both the emulator and typical
Magisk devices already ship `tcpdump` + `iptables`.

**Interactive (recommended)** — guided flow: pick target (emulator/device), set up or
boot an emulator if needed, ensure root, pick the **frida version** (v16/v17, defaulting
to the one recommended for the device's Android release — frida 17 can't spawn on
Android ≤ 11), pick the app, optionally add Frida scripts (SSL-unpinning/bypass):

```sh
uv run --project capture/capture_android trafficdeck-capture-android
```

It can create + boot a rootable `google_apis` AVD (installing the system image on
first use) and drop extra Frida scripts from `~/.traffic-deck/frida-scripts` (or a
path you enter). The chosen frida version is applied via `uv run --with frida==<ver>`
(client and server must match). The CLI is a thin front-end over the capture library.

**Non-interactive** — for scripting/known targets:

```sh
uv run --project capture/capture_android python -m capture_android.headless \
    --package com.example.app --url https://example.com --duration 30 --script unpin.js
```

Flags: `--package` (required), `--url`, `--duration`, `--script FILE` (repeatable),
`--attach` (hook the running app instead of spawning), `--serial`, `--nflog-group`,
`--gateway`.

> Works for apps using the **system** TLS stack (OkHttp/`HttpURLConnection`→Conscrypt).
> Apps that **bundle their own BoringSSL** (Chrome, most Flutter apps) won't be
> decrypted by the `libssl.so` hook — Chrome has its own `--ssl-key-log-file` for that.
> The agent hooks the main process **and** matching `<pkg>:child` processes.
>
> Verified end-to-end on both an emulator and a Magisk-rooted retail device (decrypted
> HTTPS flows). frida-server is matched to the installed `frida` (pinned to 16.7.x,
> which still supports older Android — frida 17 fails to spawn on e.g. Android 10) and
> started as a root daemon in its own session.

## F) Chrome, per-process (macOS, PKTAP)

Everything above records a whole interface and lets the key-log decide what decodes. The
decoded view is already browser-only, but the **pcap** still carries every other app's
packets, so a two-minute Chrome session can produce a bundle sized like the machine's
traffic rather than like the session.

macOS can do better. PKTAP is a pseudo interface that tags each packet with the process
that sent or received it, and Apple's `tcpdump` filters on that tag — the macOS twin of
the Android path's per-app nflog capture. In practice the tag drops the overwhelming
majority of packets before they are ever written:

```
5 packets captured
307 packets received by filter
289 drops by metadata filter
```

Two things make this source different from every other one:

- **It needs root, every time.** PKTAP creates its interface with a privileged ioctl, so
  Wireshark's ChmodBPF does not help (that grants `/dev/bpf*`, not interface creation) and
  it cannot be pre-created at boot and reused. The browser is still launched as *you* —
  root would use `/var/root`'s profile — and profile directories and state files are
  created as you too.
- **The filtered process is not the browser.** Chrome does all of its networking in the
  NetworkService utility process (`Google Chrome Helper`); the main process owns no
  sockets. The kernel truncates process names to 16 characters, which is the form the
  filter matches, so Chrome is `Google Chrome He`. The tool derives this from whichever
  binary you pick, so Brave/Edge/Chromium work too.

### Why the narrowing happens twice

A metadata filter is fixed when `tcpdump` starts, and that is *before* the browser exists.
So the filter can only say "this process name, minus the instances already running" —
which drops every other app on the machine, but cannot exclude a Chrome you open later.
Its network process has a pid in neither list, and `Google Chrome He` is a name every
Chrome-family browser shares.

So the source keeps watching. Chrome passes the resolved `--user-data-dir` down to every
child, so its own network process is identifiable in `ps` by the profile this capture
launched against — and that is unambiguous only because the source refuses to capture a
profile something is already running on. The pids it finds are reported at `CloseSession`,
and the gateway prunes the stored pcap to exactly them.

Broad in the kernel, exact at the end. A pid-only kernel filter would be exact too, but it
would go blind the moment Chrome replaced its network process, and those packets would be
gone rather than merely unclassified. The prune refuses an empty pid list and keeps any
packet whose `pktap` header it cannot read, so a failure to identify the browser leaves a
capture that is too large — never one that is empty.

The flow list is narrowed by the same evidence. Flows are decoded live, while the filter is
still too broad, so another browser's connections do reach it; the prune records which
connections carried packets owned by which process, and the flows on connections that only
ever carried another process's packets are deleted before the session's flow count is
taken. A connection seen under *both* a kept and a dropped pid is left alone — deleting a
flow needs positive evidence, not the absence of evidence — and a tunnelled flow is matched
by its `proxy_addr`, since its `dst_addr` names a target no packet on the wire ever carried.

One limit remains: nothing here filters by interface, so traffic your browser sends over a
VPN `utun` is not captured at all — `-i pktap,<iface>` taps one NIC.

One capture, interactively (the launcher re-execs under `sudo`; same Chrome/profile
pickers as the Chrome source, sharing its remembered defaults):

```sh
capture/capture-pktap.sh --label "per-process demo" --url https://example.com
```

(Any argument selects this one-shot mode; a bare `capture/capture-pktap.sh` serves.)

### Serve mode: one sudo, then start/stop from the viewer

The gateway spawns its built-in sources with `Setsid: true` and their stdio redirected to
log files, so a source it spawned has **no terminal for `sudo` to prompt on** — for the
TUI and a web UI alike. So this source is not spawned by the gateway: you start it once
yourself and enrol it as a module the gateway *dials*. A manifest with a `[control]` block
and no `[[process]]` entries registers a dial-only source — nothing to launch, just an
address to call:

`make install-pktap` writes it for you (`PKTAP_ADDR=…` to change the port):

```toml
# ~/.traffic-deck/plugins/pktap.toml
name = "pktap"

[control]
addr   = "127.0.0.1:7071"
source = "chrome-pktap"
label  = "Chrome (per-process)"
```

Start the privileged source and leave it running. The launcher re-execs itself under
`sudo` and takes the address from the manifest, so there is nothing to remember and the
port cannot drift between the two:

```sh
capture/capture-pktap.sh
```

Serving is what a bare invocation does, because that is the mode this tool exists for —
started once, left up, captures come and go from the viewer. Pass any flag and it falls
through to a single capture instead.

It now appears in the TUI's source picker (`a`) beside the built-ins, and every capture
after that starts and stops on demand with no further prompting.

Make the one prompt a fingerprint by enabling Touch ID for `sudo` — the template is
already on the system, it just ships commented out:

```sh
sudo sed 's/^#auth/auth/' /etc/pam.d/sudo_local.template | sudo tee /etc/pam.d/sudo_local
```

`sudo_local` is the post-Sonoma location that survives OS updates. It works in a normal
terminal; under tmux/screen it needs Homebrew's `pam_reattach`, and over SSH it never
applies.

Useful flags / env:

| | |
|---|---|
| `serve --control ADDR` | serve CaptureSourceService for the gateway to dial (must match the manifest's `addr`) |
| `--chrome BIN` | which Chrome-family browser (also sets the filtered process name) |
| `--profile-dir DIR` | use an existing profile instead of a fresh temp one |
| `--url URL` / `--duration N` | open a URL / auto-stop after N seconds |
| `--iface IFACE` | interface to tap (default: auto-detected) |
| `--tcpdump BIN` / `TCPDUMP_BIN` | override tcpdump (must be Apple's — Homebrew's lacks `-Q`) |

> There is no `--filter`: a BPF expression would narrow by port or host *on top of* the
> process filter, which is not what this source is for. Use the Chrome source for that.

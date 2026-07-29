# Getting traffic in

Four ways to feed the gateway. The first is offline; the other three capture live and
stream flows into the TUI as they happen. All of them can be started from the TUI's
sessions screen (`a`), which is usually easier than the command lines below — the gateway
supervises the capture tool for you. The CLIs are here for scripting and for running a
capture against a remote gateway.

- [A) Import a pre-captured pcap + key.log](#a-import-a-pre-captured-pcap--keylog)
- [B) Live-capture Chrome](#b-live-capture-chrome)
- [C) mitmproxy (any device, incl. WireGuard)](#c-mitmproxy-any-device-incl-wireguard)
- [D) Android (rooted emulator/device, per-app)](#d-android-rooted-emulatordevice-per-app)

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

## C) mitmproxy (any device, incl. WireGuard)

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

## D) Android (rooted emulator/device, per-app)

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

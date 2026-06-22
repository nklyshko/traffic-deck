# 0007 — Android per-app capture via a Frida key-log and UID→NFLOG

Status: accepted

## Context

Capturing one Android app's HTTPS traffic, decryptable, without a man-in-the-middle
proxy (which trips certificate pinning and needs a trusted CA) and without capturing the
whole device's traffic.

## Decision

On a rooted emulator/device, capture per-app and decrypt from a key-log:

- **Key-log, not MITM**: Frida hooks the app's system `libssl` to dump TLS secrets to an
  NSS key-log — the same key-log the gateway already uses to decrypt. No proxy, no CA,
  no pinning bypass needed for the common case.
- **Per-app isolation by UID**: `iptables` marks the app's packets by owner UID and logs
  them via `NFLOG`; an on-device `tcpdump -i nflog:<group>` captures only those.
- Both the pcap and the key-log stream to the gateway over the normal packet-source
  path. Root is obtained via `adb root` (emulator/userdebug) or Magisk `su` (retail);
  a version-matched `frida-server` is fetched and run.

## Consequences

- Decrypts apps that use the **system** TLS stack (OkHttp/`HttpURLConnection` →
  Conscrypt) with no interception. Apps that bundle their own TLS (e.g. Chrome,
  many Flutter apps) aren't covered by the `libssl` hook.
- The capture link type is `NFLOG`, which the in-process Go decoder handles explicitly
  ([0006](0006-in-process-tls-decryption.md)).
- Requires root and a Frida version compatible with the device's Android release; the
  interactive CLI picks one per device.

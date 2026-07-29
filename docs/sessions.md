# Sharing sessions (export / import)

A session is self-contained — its bundle holds the flows DB, the capture, the key.log,
spilled bodies, and the tags/groups it uses ([ADR-0001](adr/0001-embedded-per-session-sqlite.md))
— so it can be exported as a single `.tar.gz` and imported into another gateway.

```sh
# export (CLI). In the TUI, press `e` on the sessions list to export the focused one.
mise exec -- go -C gateway run ./cmd/gateway export <session-id> -o session.tar.gz

# import into this gateway's data root + catalog. --new-id imports a copy when the
# original id already exists; --label overrides the session label.
mise exec -- go -C gateway run ./cmd/gateway import-session session.tar.gz [--new-id] [--label name]
```

In the TUI, `i` on the sessions screen imports a bundle. (`I` imports a raw pcap instead —
see [capture sources](capture-sources.md#a-import-a-pre-captured-pcap--keylog).)

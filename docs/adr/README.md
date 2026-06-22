# Architecture Decision Records

Short records of the significant, hard-to-reverse decisions behind this system and the
reasoning at the time. Format: Context → Decision → Consequences.

| # | Decision |
|---|----------|
| [0001](0001-embedded-per-session-sqlite.md) | Embedded per-session SQLite bundles + a global catalog (no DB server) |
| [0002](0002-tshark-for-dissection.md) | Use `tshark` for protocol dissection and TLS decryption |
| [0003](0003-per-frame-pdml-decode.md) | Parse per-frame PDML, not flat fields |
| [0004](0004-compiled-in-go-decoders.md) | Custom protocols as compiled-in Go decoder modules |
| [0005](0005-message-shaped-records.md) | WebSocket and custom frames are message records on one timeline |
| [0006](0006-in-process-tls-decryption.md) | In-process Go TLS decryption for live custom-protocol decode |
| [0007](0007-android-per-app-capture.md) | Android per-app capture via a Frida key-log and UID→NFLOG |
| [0008](0008-independent-capture-apps.md) | Capture tools are independent apps over a shared SDK |

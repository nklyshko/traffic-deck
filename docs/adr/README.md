# Architecture Decision Records

Short records of the significant, hard-to-reverse decisions behind this system and the
reasoning at the time. Format: Context → Decision → Consequences.

| # | Decision |
|---|----------|
| [0001](0001-embedded-per-session-sqlite.md) | Embedded per-session SQLite bundles + a global catalog (no DB server) |
| [0002](0002-tshark-for-dissection.md) | Use `tshark` for protocol dissection and TLS decryption *(superseded in part by 0009)* |
| [0003](0003-per-frame-pdml-decode.md) | Parse per-frame PDML, not flat fields *(batch decoder only, per 0009)* |
| [0004](0004-compiled-in-go-decoders.md) | Custom protocols as compiled-in Go decoder modules |
| [0005](0005-message-shaped-records.md) | WebSocket and custom frames are message records on one timeline |
| [0006](0006-in-process-tls-decryption.md) | In-process Go TLS decryption for live custom-protocol decode *(generalized by 0009)* |
| [0007](0007-android-per-app-capture.md) | Android per-app capture via a Frida key-log and UID→NFLOG |
| [0008](0008-independent-capture-apps.md) | Capture tools are independent apps over a shared SDK |
| [0009](0009-native-live-decode-default.md) | The native in-process decoder is the default, authoritative path |
| [0010](0010-supervisor-and-capture-modules.md) | The gateway supervises capture; viewers are clients |
| [0011](0011-incremental-flow-persistence.md) | Live-decoded flows persist incrementally, not on close *(proposed)* |
| [0012](0012-server-side-filtering-and-pagination.md) | Filtering and pagination happen in the gateway *(proposed)* |

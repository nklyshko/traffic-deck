# 0013 — A session records its source as a name plus a delivery shape

Status: accepted

## Context

`SourceKind` was one closed enum answering two questions at once: *which tool produced
this capture* and *how does it reach the gateway*. Adding a second browser made the seam
obvious — `SOURCE_KIND_FIREFOX` would be a third value that no code branches on, next to
`SOURCE_KIND_CHROME`, which nothing branched on either.

Surveying every use of the enum found the imbalance:

- **One** behavioural branch existed in the whole system:
  `if req.GetSourceKind() == SOURCE_KIND_MITMPROXY { hub.startPassive(sid) }` in
  `OpenSession`. Its own comment gave the real predicate away — *"Supplied (pushed)
  sources have no UploadBegin to start a live session"*. It was asking about delivery,
  and using the one tool that happened to push as a stand-in.
- Nothing else compared it. Not the decode pipeline, not the filter DSL, not a single SQL
  predicate, not the TUI. Only the MCP server rendered it, through a hardcoded table.
- The close path already distinguished the two deliveries *correctly and by observation*
  — `pcapBytes > 0` — without consulting the enum at all.

Two forces made the conflation actively wrong rather than merely untidy.
[0010](0010-supervisor-and-capture-modules.md) had already concluded that a closed enum
cannot name a third-party module, and gave `StartCaptureRequest` a `string source` for
exactly that reason; the enum lingered on the ingest side saying the same thing worse. And
a module that pushes flows — which 0010 explicitly anticipates — could never match
`SOURCE_KIND_MITMPROXY`, so it silently missed the pre-registration that makes a pushed
session followable before its first flow.

## Decision

Split the two questions apart, each into the form that fits it.

**1. Provenance is a free string.** `OpenSessionRequest.source` and `Session.source` carry
the producing tool's name — `"chrome"`, `"firefox"`, `"android"`, `"mitmproxy"`,
`"import"`, or a module's own name. No enum, for the reason 0010 already gave: the set is
open, and a module names itself.

**2. Delivery is a small closed enum**, because the gateway must act on it and the
alternatives are genuinely fixed:

    enum SourceShape { UNSPECIFIED = 0; PCAP = 1; FLOWS = 2; }

`PCAP` streams packets for the gateway to decode; `FLOWS` pushes flows already decoded.
The one branch becomes `shape == FLOWS`, which now covers any pushed source rather than
one named tool.

**3. The shape is not persisted.** It is needed at exactly one instant — `OpenSession`,
where nothing has been stored yet and so nothing can be inferred. Afterwards every
consumer either re-derives it from `pcapBytes` (as the close path already did) or does not
care. A column would have been a second, staler copy of a fact the bytes already tell.

**4. The catalog column is reused, and legacy values are translated on read.**
`sessions.source_kind` keeps its name and now holds the tool name. Old rows hold enum
names, and they arrive from two directions — a catalog written by an older build, and a
bundle exported by one and imported at any point in the future, since the export manifest
keeps the `source_kind` JSON key for exactly that compatibility. So the mapping lives on
the read path (`sourceName`), not in a one-shot migration, which would only ever have
fixed the first. An unrecognized `SOURCE_KIND_*` reads as empty rather than leaking a raw
enum name into a viewer.

## Consequences

- Adding a capture source no longer touches the contract. Firefox needed a name, not an
  enum value; the next browser or module needs neither.
- A third-party module that pushes flows now gets the same live-from-open behaviour as
  mitmproxy, which the enum could not express.
- The gateway holds no list of tools it can capture from. The tool names in
  `sourcemgr.builtinSources` are a launcher registry, unrelated to what a session records.
- Provenance is only as good as what a tool sends: an empty `source` is now possible where
  an enum would have forced `UNSPECIFIED`. The built-ins all set it, and the field is
  documented as the session's provenance.
- No schema migration and no `ALTER TABLE`; the cost is one translation table that has to
  stay for as long as pre-0013 bundles might be imported.

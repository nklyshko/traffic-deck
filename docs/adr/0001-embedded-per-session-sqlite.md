# 0001 — Embedded per-session SQLite bundles + a global catalog

Status: accepted

## Context

The system is single-user and local-first: capture an app's traffic, decode it, browse
it. An early version used a Postgres server (with Docker), which added operational
weight disproportionate to a desktop tool, and coupled every capture into one shared
database. Captures are naturally session-scoped (one capture = one investigation) and
benefit from being independently movable, deletable, and shareable.

## Decision

Store each session as a self-contained bundle on disk and keep a small global catalog:

- `data/sessions/<id>/flows.sqlite` — that capture's decoded flows, headers, WebSocket/
  custom messages, and annotations.
- `data/sessions/<id>/{capture.pcap, key.log, blobs/}` — the raw capture, TLS secrets,
  and any bodies too large to inline.
- `data/catalog.sqlite` — the session list plus tag/group definitions.

Use the pure-Go `modernc.org/sqlite` driver (no cgo, no server). Tag/group definitions
are *mirrored* into each bundle that uses them so a bundle renders correctly on its own.

## Consequences

- No database server or Docker; `data/` is the entire state and is trivially backed up.
- A session is portable: export/import is a `.tar.gz` of the catalog row + bundle files.
- Cross-session queries require fanning out over bundles rather than one SQL query;
  acceptable for the single-user scope, and the catalog covers listing/search needs.
- A heavier analytics backend (Postgres/DuckDB) remains a possible future add-on behind
  the same store interface, not a prerequisite.

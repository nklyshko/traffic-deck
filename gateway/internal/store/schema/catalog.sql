-- Global catalog (rebuildable): the session list across all bundles (plan §6.3).
CREATE TABLE IF NOT EXISTS sessions (
    id           TEXT PRIMARY KEY,
    label        TEXT NOT NULL DEFAULT '',
    source_kind  TEXT NOT NULL,
    status       TEXT NOT NULL,
    created_at   INTEGER NOT NULL,            -- unix millis
    closed_at    INTEGER,                     -- unix millis, NULL until terminal
    pcap_bytes   INTEGER NOT NULL DEFAULT 0,
    keylog_bytes INTEGER NOT NULL DEFAULT 0,
    flow_count   INTEGER NOT NULL DEFAULT 0,
    session_group TEXT NOT NULL DEFAULT ''    -- free-text group label for organizing sessions
);

-- Opaque per-session metadata supplied by the capture source at OpenSession (e.g.
-- viewer.columns declaring the viewer's default table columns). A side table so
-- existing catalogs keep reading cleanly (it's just empty for them).
CREATE TABLE IF NOT EXISTS session_metadata (
    session_id TEXT NOT NULL,
    key        TEXT NOT NULL,
    value      TEXT NOT NULL,
    PRIMARY KEY (session_id, key)
);

-- Annotation definitions (plan §12): canonical here so tags/groups are consistent
-- and selectable across sessions; mirrored into each bundle that uses them. The
-- built-in Favorite tag is seeded with a fixed id.
CREATE TABLE IF NOT EXISTS tags (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    color       TEXT NOT NULL DEFAULT '',
    is_favorite INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS groups (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    color      TEXT NOT NULL DEFAULT '',
    parent_id  TEXT,
    created_at INTEGER NOT NULL
);

INSERT OR IGNORE INTO tags (id, name, color, is_favorite, created_at)
VALUES ('__favorite__', 'Favorite', 'yellow', 1, 0);

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
    flow_count   INTEGER NOT NULL DEFAULT 0
);

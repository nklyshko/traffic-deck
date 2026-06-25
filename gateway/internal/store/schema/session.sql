-- Per-session bundle DB (sessions/<id>/flows.sqlite). HTTP schema for now; the
-- generic records/decode_runs/streams model arrives with Kaitai (plan §6.3, Phase 6).
CREATE TABLE IF NOT EXISTS analyses (
    id                 TEXT PRIMARY KEY,
    session_id         TEXT NOT NULL,
    engine             TEXT NOT NULL,
    tls_key_log_used   INTEGER NOT NULL DEFAULT 0,
    plaintext_fallback INTEGER NOT NULL DEFAULT 0,
    created_at         INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS flows (
    id            TEXT PRIMARY KEY,
    session_id    TEXT NOT NULL,
    analysis_id   TEXT NOT NULL,
    frame_number  INTEGER,
    ts_micros     INTEGER,
    method        TEXT,
    scheme        TEXT,
    authority     TEXT,
    path          TEXT,
    query         TEXT,
    protocol      TEXT,
    status        INTEGER,
    src_addr      TEXT,
    dst_addr      TEXT,
    user_agent    TEXT,
    content_type  TEXT,
    request_bytes INTEGER,
    tls_decrypted INTEGER NOT NULL DEFAULT 0,
    tcp_stream    TEXT,
    h2_stream_id  TEXT,
    req_body_ref  TEXT,
    resp_body_ref TEXT,
    proxy_addr    TEXT,           -- proxy this connection went through (host:port), if any
    proxy_type    TEXT,           -- "http" | "socks"
    proxy_user    TEXT,
    proxy_pass    TEXT
);

CREATE TABLE IF NOT EXISTS flow_headers (
    flow_id   TEXT NOT NULL,
    direction INTEGER NOT NULL,   -- 0 request, 1 response
    ord       INTEGER NOT NULL,
    name      TEXT NOT NULL,
    value     TEXT NOT NULL
);

-- Content-addressed bodies (plan §6.4): small bodies inline (bytes set), large
-- bodies spilled to sessions/<id>/blobs/<sha256> (external_path set, bytes NULL).
CREATE TABLE IF NOT EXISTS blobs (
    sha256        TEXT PRIMARY KEY,
    size          INTEGER NOT NULL,
    content_type  TEXT,
    bytes         BLOB,           -- NULL when spilled to a file
    external_path TEXT            -- set when spilled; relative to the data root
);

-- WebSocket frames (plan §8.6): message-shaped records belonging to an Upgrade flow.
CREATE TABLE IF NOT EXISTS ws_messages (
    id           TEXT PRIMARY KEY,
    flow_id      TEXT NOT NULL,        -- parent Upgrade flow
    frame_number INTEGER,
    ts_micros    INTEGER,
    from_client  INTEGER NOT NULL DEFAULT 0,
    opcode       TEXT,
    payload_len  INTEGER NOT NULL DEFAULT 0,
    payload_ref  TEXT                  -- -> blobs.sha256 (NULL when empty)
);

CREATE INDEX IF NOT EXISTS flows_ts_idx          ON flows (ts_micros, frame_number);
CREATE INDEX IF NOT EXISTS flows_authority_idx   ON flows (authority);
CREATE INDEX IF NOT EXISTS flow_headers_flow_idx ON flow_headers (flow_id);
CREATE INDEX IF NOT EXISTS ws_messages_flow_idx  ON ws_messages (flow_id, ts_micros, frame_number);

-- Annotations (plan §12). A "record" is a flow today (a WebSocket message later).
-- tags/groups here mirror the catalog defs so the bundle stays self-contained;
-- assignments, comments, and marks are authoritative here.
CREATE TABLE IF NOT EXISTS tags (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    color       TEXT NOT NULL DEFAULT '',
    is_favorite INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS record_tags (
    record_id TEXT NOT NULL,
    tag_id    TEXT NOT NULL,
    PRIMARY KEY (record_id, tag_id)
);

CREATE TABLE IF NOT EXISTS comments (
    id         TEXT PRIMARY KEY,
    record_id  TEXT NOT NULL,
    body       TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS record_marks (
    record_id TEXT PRIMARY KEY,
    color     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS groups (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    color      TEXT NOT NULL DEFAULT '',
    parent_id  TEXT,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS group_members (
    group_id  TEXT NOT NULL,
    record_id TEXT NOT NULL,
    PRIMARY KEY (group_id, record_id)
);

CREATE INDEX IF NOT EXISTS record_tags_rec_idx   ON record_tags (record_id);
CREATE INDEX IF NOT EXISTS comments_rec_idx      ON comments (record_id);
CREATE INDEX IF NOT EXISTS group_members_rec_idx ON group_members (record_id);

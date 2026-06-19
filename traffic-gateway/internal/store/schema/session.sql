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
    resp_body_ref TEXT
);

CREATE TABLE IF NOT EXISTS flow_headers (
    flow_id   TEXT NOT NULL,
    direction INTEGER NOT NULL,   -- 0 request, 1 response
    ord       INTEGER NOT NULL,
    name      TEXT NOT NULL,
    value     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS flows_ts_idx          ON flows (ts_micros, frame_number);
CREATE INDEX IF NOT EXISTS flows_authority_idx   ON flows (authority);
CREATE INDEX IF NOT EXISTS flow_headers_flow_idx ON flow_headers (flow_id);

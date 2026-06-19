-- Initial schema (plan §6.1).

CREATE TABLE sessions (
    id                 TEXT PRIMARY KEY,
    label              TEXT NOT NULL DEFAULT '',
    source_kind        TEXT NOT NULL,
    source_detail      JSONB NOT NULL DEFAULT '{}'::jsonb,
    status             TEXT NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    closed_at          TIMESTAMPTZ,
    pcap_object_key    TEXT,
    keylog_object_key  TEXT,
    pcapng_object_key  TEXT,            -- derived export, nullable (plan §6.3)
    pcap_bytes         BIGINT NOT NULL DEFAULT 0,
    keylog_bytes       BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE analyses (
    id                  TEXT PRIMARY KEY,
    session_id          TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    engine              TEXT NOT NULL,
    tls_key_log_used    BOOLEAN NOT NULL DEFAULT false,
    plaintext_fallback  BOOLEAN NOT NULL DEFAULT false,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    dataset_object_key  TEXT
);

CREATE TABLE flows (
    id             TEXT PRIMARY KEY,
    session_id     TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    analysis_id    TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    frame_number   BIGINT,
    ts_micros      BIGINT,
    method         TEXT,
    scheme         TEXT,
    authority      TEXT,
    path           TEXT,
    query          TEXT,
    protocol       TEXT,
    status         INT,
    src_addr       TEXT,
    dst_addr       TEXT,
    user_agent     TEXT,
    content_type   TEXT,
    request_bytes  BIGINT,
    tls_decrypted  BOOLEAN NOT NULL DEFAULT false,
    tcp_stream     TEXT,
    h2_stream_id   TEXT,
    req_body_ref   TEXT,
    resp_body_ref  TEXT
);

CREATE TABLE flow_headers (
    flow_id    TEXT NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
    direction  SMALLINT NOT NULL,  -- 0 request, 1 response
    ord        INT NOT NULL,
    name       TEXT NOT NULL,
    value      TEXT NOT NULL
);

CREATE TABLE flow_cookies (
    flow_id    TEXT NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
    direction  SMALLINT NOT NULL,
    name       TEXT NOT NULL,
    value      TEXT NOT NULL
);

CREATE TABLE bookmarks (
    id          TEXT PRIMARY KEY,
    flow_id     TEXT NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
    note        TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE groups (
    id          TEXT PRIMARY KEY,
    label       TEXT NOT NULL,
    color       TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE group_members (
    group_id  TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    flow_id   TEXT NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, flow_id)
);

CREATE TABLE launch_profiles (
    package            TEXT PRIMARY KEY,
    frida_extra_args   JSONB NOT NULL DEFAULT '[]'::jsonb,
    has_bypass         BOOLEAN NOT NULL DEFAULT false,
    bypass_object_key  TEXT,
    source             TEXT,
    notes              TEXT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX flows_session_ts_idx ON flows (session_id, ts_micros);
CREATE INDEX flows_authority_idx  ON flows (authority);
CREATE INDEX flows_tcp_stream_idx ON flows (tcp_stream);

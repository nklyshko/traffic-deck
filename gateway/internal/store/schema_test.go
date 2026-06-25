package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// oldFlowsSchema is the flows table as it stood before the proxy_* columns were
// added — what a bundle captured by an older gateway looks like on disk.
const oldFlowsSchema = `CREATE TABLE flows (
    id TEXT PRIMARY KEY, session_id TEXT, analysis_id TEXT, frame_number INTEGER,
    ts_micros INTEGER, method TEXT, scheme TEXT, authority TEXT, path TEXT, query TEXT,
    protocol TEXT, status INTEGER, src_addr TEXT, dst_addr TEXT, user_agent TEXT,
    content_type TEXT, request_bytes INTEGER, tls_decrypted INTEGER NOT NULL DEFAULT 0,
    tcp_stream TEXT, h2_stream_id TEXT, req_body_ref TEXT, resp_body_ref TEXT
);`

// writeOldBundle materializes sessions/<id>/flows.sqlite with the pre-proxy schema.
func writeOldBundle(t *testing.T, dataRoot, sessionID string) {
	t.Helper()
	dir := filepath.Join(dataRoot, "sessions", sessionID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "flows.sqlite"))
	if err != nil {
		t.Fatalf("open old db: %v", err)
	}
	defer db.Close()
	if _, err := db.ExecContext(context.Background(), oldFlowsSchema); err != nil {
		t.Fatalf("create old flows: %v", err)
	}
}

// An outdated bundle must surface ErrSchemaOutdated (which the server maps to
// FailedPrecondition) on read, naming the missing columns — not a raw SQL error.
func TestOutdatedBundleReportsReimport(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	sid := uuid.NewString()
	writeOldBundle(t, dir, sid)

	st, err := Open(ctx, dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(st.Close)

	_, err = st.ListFlows(ctx, sid)
	if !errors.Is(err, ErrSchemaOutdated) {
		t.Fatalf("want ErrSchemaOutdated, got %v", err)
	}
	if msg := err.Error(); !strings.Contains(msg, "re-import") || !strings.Contains(msg, "proxy_addr") {
		t.Fatalf("error should name the fix and the missing column: %q", msg)
	}

	// Other read paths funnel through sessionDB too, so they report it consistently.
	if _, err := st.GetFlow(ctx, sid, "whatever"); !errors.Is(err, ErrSchemaOutdated) {
		t.Fatalf("GetFlow want ErrSchemaOutdated, got %v", err)
	}
}

// A fresh, current-schema session opens and reads cleanly (no false positive).
func TestCurrentBundlePassesValidation(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	sid := uuid.NewString()
	if err := st.CreateSession(ctx, NewSession{ID: sid, Label: "ok"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := st.ListFlows(ctx, sid); err != nil {
		t.Fatalf("current bundle should read: %v", err)
	}
}

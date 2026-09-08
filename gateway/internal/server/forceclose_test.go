package server

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	trafficv1 "gitlab.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/objstore"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/store"
)

// TestForceCloseSessionGuards covers the guards: a missing session is NotFound, and an
// already-finalized session is refused.
func TestForceCloseSessionGuards(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	ing := &Ingest{st: st}

	if _, err := ing.ForceCloseSession(ctx, &trafficv1.CloseSessionRequest{SessionId: uuid.NewString()}); status.Code(err) != codes.NotFound {
		t.Errorf("missing session: code=%v", status.Code(err))
	}
	for _, term := range []trafficv1.SessionStatus{
		trafficv1.SessionStatus_SESSION_STATUS_CLOSED,
		trafficv1.SessionStatus_SESSION_STATUS_ERROR,
	} {
		sid := uuid.NewString()
		if err := st.CreateSession(ctx, store.NewSession{ID: sid, Source: "import", Status: term}); err != nil {
			t.Fatal(err)
		}
		if _, err := ing.ForceCloseSession(ctx, &trafficv1.CloseSessionRequest{SessionId: sid}); status.Code(err) != codes.FailedPrecondition {
			t.Errorf("already %v: code=%v", term, status.Code(err))
		}
	}
}

// TestForceCloseSessionToleratesOldBundle is the stale-session case: a session left OPEN
// whose on-disk bundle has an outdated schema must still force-close (finalization fails,
// so it falls back to marking the session closed in the catalog).
func TestForceCloseSessionToleratesOldBundle(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	sid := uuid.NewString()

	st1, err := store.Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := st1.CreateSession(ctx, store.NewSession{ID: sid, Source: "mitmproxy", Status: trafficv1.SessionStatus_SESSION_STATUS_OPEN}); err != nil {
		t.Fatal(err)
	}
	st1.Close()
	writeOldFlowsBundle(t, dir, sid) // overwrite the bundle with a pre-columns schema

	st2, err := store.Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st2.Close)
	obj, err := objstore.NewFSStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	ing := &Ingest{st: st2, obj: obj, hub: newLiveHub(false)}

	if _, err := ing.ForceCloseSession(ctx, &trafficv1.CloseSessionRequest{SessionId: sid}); err != nil {
		t.Fatalf("force close should tolerate an outdated bundle, got: %v", err)
	}
	got, err := st2.GetSession(ctx, sid)
	if err != nil {
		t.Fatal(err)
	}
	if got.GetStatus() != trafficv1.SessionStatus_SESSION_STATUS_CLOSED {
		t.Errorf("status = %v, want CLOSED", got.GetStatus())
	}
}

// writeOldFlowsBundle replaces a session's flows.sqlite with the flows table as it stood
// before the proxy_* and later columns — the read path now requires them, so opening it
// trips ErrSchemaOutdated.
func writeOldFlowsBundle(t *testing.T, dataRoot, sid string) {
	t.Helper()
	p := filepath.Join(dataRoot, "sessions", sid, "flows.sqlite")
	for _, s := range []string{p, p + "-wal", p + "-shm"} {
		_ = os.Remove(s)
	}
	db, err := sql.Open("sqlite", p)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.ExecContext(context.Background(), `CREATE TABLE flows (
		id TEXT PRIMARY KEY, session_id TEXT, analysis_id TEXT, frame_number INTEGER,
		ts_micros INTEGER, method TEXT, scheme TEXT, authority TEXT, path TEXT, query TEXT,
		protocol TEXT, status INTEGER, src_addr TEXT, dst_addr TEXT, user_agent TEXT,
		content_type TEXT, request_bytes INTEGER, tls_decrypted INTEGER NOT NULL DEFAULT 0,
		tcp_stream TEXT, h2_stream_id TEXT, req_body_ref TEXT, resp_body_ref TEXT);`); err != nil {
		t.Fatal(err)
	}
}

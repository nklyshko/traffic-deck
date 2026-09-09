package store

// The body content-encoding a decode recorded has to survive persistence: it is what a
// consumer trusts instead of the content-encoding header (which can name an encoding the
// body was not actually sent in), so a bundle that loses it leaves readers guessing.

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/google/uuid"

	trafficv1 "gitlab.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/decode"
)

// insertOneFlow stores f in a fresh session and returns the session and flow ids.
func insertOneFlow(t *testing.T, st *Store, f *decode.Flow) (sid, fid string) {
	t.Helper()
	ctx := context.Background()
	sid = uuid.NewString()
	if err := st.CreateSession(ctx, NewSession{
		ID: sid, Label: "enc", Source: "import",
		Status: trafficv1.SessionStatus_SESSION_STATUS_DECODING,
	}); err != nil {
		t.Fatalf("create session: %v", err)
	}
	aid := uuid.NewString()
	if err := st.CreateAnalysis(ctx, NewAnalysis{ID: aid, SessionID: sid, Engine: "tshark"}); err != nil {
		t.Fatalf("create analysis: %v", err)
	}
	if _, err := st.InsertFlows(ctx, sid, aid, []*decode.Flow{f}); err != nil {
		t.Fatalf("insert flows: %v", err)
	}
	listed, err := st.ListFlows(ctx, sid)
	if err != nil || len(listed) != 1 {
		t.Fatalf("list flows: n=%d err=%v", len(listed), err)
	}
	return sid, listed[0].Id
}

func TestBodyContentEncodingRoundTrip(t *testing.T) {
	st := openTestStore(t)
	sid, fid := insertOneFlow(t, st, &decode.Flow{
		Method: "GET", Authority: "example.com", Path: "/", Protocol: "HTTP/3", Status: 200,
		RequestHeaders:  []decode.Header{{Name: "content-type", Value: "application/json"}},
		ResponseHeaders: []decode.Header{{Name: "content-type", Value: "text/html"}},
		// Both bodies are stored plain; the fields say what they were on the wire.
		RequestBody:          []byte(`{"q":1}`),
		RequestBodyEncoding:  "deflate",
		ResponseBody:         []byte("<html>hi</html>"),
		ResponseBodyEncoding: "gzip",
	})

	full, err := st.GetFlow(context.Background(), sid, fid)
	if err != nil {
		t.Fatalf("get flow: %v", err)
	}
	if got := full.GetResponseBody().GetContentEncoding(); got != "gzip" {
		t.Errorf("response body content_encoding = %q, want %q", got, "gzip")
	}
	if got := full.GetRequestBody().GetContentEncoding(); got != "deflate" {
		t.Errorf("request body content_encoding = %q, want %q", got, "deflate")
	}
	if got := string(full.GetResponseBody().GetInline()); got != "<html>hi</html>" {
		t.Errorf("response body = %q, want the stored (plain) bytes", got)
	}
}

// A body that arrived plain carries no encoding — the field distinguishes "decoded from
// gzip for you" from "this is how it came", so it must stay empty rather than default to
// anything.
func TestBodyWithoutEncodingReportsNone(t *testing.T) {
	st := openTestStore(t)
	sid, fid := insertOneFlow(t, st, &decode.Flow{
		Method: "GET", Authority: "example.com", Path: "/", Protocol: "HTTP/2", Status: 200,
		ResponseHeaders: []decode.Header{{Name: "content-type", Value: "text/plain"}},
		ResponseBody:    []byte("plain"),
	})

	full, err := st.GetFlow(context.Background(), sid, fid)
	if err != nil {
		t.Fatalf("get flow: %v", err)
	}
	if got := full.GetResponseBody().GetContentEncoding(); got != "" {
		t.Errorf("content_encoding = %q, want none", got)
	}
}

// A bundle written before the encoding columns existed still opens: the columns are added
// empty, which reads as "no encoding recorded" — true of what that gateway stored, since
// it recorded none. Re-import is what gets those bodies decoded.
func TestOlderBundleGainsEncodingColumns(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	sid := uuid.NewString()
	if err := st.CreateSession(ctx, NewSession{
		ID: sid, Label: "old", Source: "import",
		Status: trafficv1.SessionStatus_SESSION_STATUS_CLOSED,
	}); err != nil {
		t.Fatalf("create session: %v", err)
	}
	// Drop the session's cached handle and the columns, leaving a pre-migration bundle.
	st.mu.Lock()
	db := st.sessions[sid]
	delete(st.sessions, sid)
	st.mu.Unlock()
	for _, col := range []string{"req_content_encoding", "resp_content_encoding"} {
		if _, err := db.ExecContext(ctx, `ALTER TABLE flows DROP COLUMN `+col); err != nil {
			t.Fatalf("drop %s: %v", col, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened, err := st.sessionDB(ctx, sid)
	if err != nil {
		t.Fatalf("reopen migrated bundle: %v", err)
	}
	for _, col := range []string{"req_content_encoding", "resp_content_encoding"} {
		var n int
		if err := reopened.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM pragma_table_info('flows') WHERE name=?`, col).Scan(&n); err != nil {
			t.Fatalf("inspect %s: %v", col, err)
		}
		if n != 1 {
			t.Errorf("column %s missing after migration", col)
		}
	}
	// Re-running the migration on an up-to-date bundle is a no-op, not an error.
	if err := migrateSession(ctx, reopened); err != nil {
		t.Errorf("migrateSession twice: %v", err)
	}
}

// The bundle file the store opens is the one the migration ran against — guard against a
// test that quietly migrates a different database.
func TestSessionBundlePath(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	sid := uuid.NewString()
	if err := st.CreateSession(ctx, NewSession{ID: sid, Label: "p", Source: "import"}); err != nil {
		t.Fatalf("create session: %v", err)
	}
	path := filepath.Join(st.dataRoot, "sessions", sid, "flows.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open bundle: %v", err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM pragma_table_info('flows') WHERE name='resp_content_encoding'`).Scan(&n); err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if n != 1 {
		t.Error("resp_content_encoding missing from a freshly created bundle")
	}
}

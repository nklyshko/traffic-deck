package store

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"

	trafficv1 "github.com/nikitak/parsing/traffic-gateway/gen/traffic/v1"
	"github.com/nikitak/parsing/traffic-gateway/internal/decode"
	"github.com/nikitak/parsing/traffic-gateway/migrations"
)

// openTestStore connects to TEST_PG_DSN or skips. Migrations are idempotent.
func openTestStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("TEST_PG_DSN")
	if dsn == "" {
		t.Skip("set TEST_PG_DSN to run store integration tests")
	}
	ctx := context.Background()
	st, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := st.Migrate(ctx, migrations.FS); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(st.Close)
	return st
}

func TestSessionFlowRoundTrip(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	sid := uuid.NewString()
	if err := st.CreateSession(ctx, NewSession{
		ID:         sid,
		Label:      "test-" + sid[:8],
		SourceKind: trafficv1.SourceKind_SOURCE_KIND_GENERIC,
		Status:     trafficv1.SessionStatus_SESSION_STATUS_DECODING,
		PcapKey:    "sessions/" + sid + "/capture.pcap",
		PcapBytes:  123,
	}); err != nil {
		t.Fatalf("create session: %v", err)
	}
	// Cascade-delete the session (and its flows/headers/analyses) when done.
	t.Cleanup(func() {
		_, _ = st.pool.Exec(context.Background(), "DELETE FROM sessions WHERE id=$1", sid)
	})

	aid := uuid.NewString()
	if err := st.CreateAnalysis(ctx, NewAnalysis{ID: aid, SessionID: sid, Engine: "tshark", TLSKeyLogUsed: true}); err != nil {
		t.Fatalf("create analysis: %v", err)
	}

	flows := []*decode.Flow{{
		FrameNumber: 7, TSUnixMicros: 1700000000000000,
		Method: "GET", Scheme: "https", Authority: "example.com", Path: "/a", Query: "x=1",
		Protocol: "HTTP/2", Status: 200, TLSDecrypted: true, TCPStream: "3", H2StreamID: "1",
		RequestHeaders:  []decode.Header{{Name: "user-agent", Value: "probe"}},
		ResponseHeaders: []decode.Header{{Name: "content-type", Value: "text/html"}},
	}}
	n, err := st.InsertFlows(ctx, sid, aid, flows)
	if err != nil || n != 1 {
		t.Fatalf("insert flows: n=%d err=%v", n, err)
	}

	if err := st.SetSessionStatus(ctx, sid, trafficv1.SessionStatus_SESSION_STATUS_CLOSED); err != nil {
		t.Fatalf("set status: %v", err)
	}

	// ListSessions must include ours with the right flow_count.
	sessions, err := st.ListSessions(ctx, 1000, 0)
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	var got *trafficv1.Session
	for _, s := range sessions {
		if s.Id == sid {
			got = s
		}
	}
	if got == nil {
		t.Fatal("created session not listed")
	}
	if got.FlowCount != 1 || got.Status != trafficv1.SessionStatus_SESSION_STATUS_CLOSED {
		t.Fatalf("session flow_count=%d status=%v", got.FlowCount, got.Status)
	}

	// ListFlows (summary, no headers).
	listed, err := st.ListFlows(ctx, sid)
	if err != nil || len(listed) != 1 {
		t.Fatalf("list flows: n=%d err=%v", len(listed), err)
	}
	if listed[0].Authority != "example.com" || listed[0].Status != 200 {
		t.Fatalf("flow mismatch: %+v", listed[0])
	}

	// GetFlow (with headers).
	full, err := st.GetFlow(ctx, listed[0].Id)
	if err != nil {
		t.Fatalf("get flow: %v", err)
	}
	if len(full.RequestHeaders) != 1 || full.RequestHeaders[0].Name != "user-agent" {
		t.Fatalf("request headers: %+v", full.RequestHeaders)
	}
	if len(full.ResponseHeaders) != 1 || full.ResponseHeaders[0].Value != "text/html" {
		t.Fatalf("response headers: %+v", full.ResponseHeaders)
	}

	// Unknown flow -> ErrNotFound.
	if _, err := st.GetFlow(ctx, uuid.NewString()); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

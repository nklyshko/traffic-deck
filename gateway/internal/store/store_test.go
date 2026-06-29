package store

import (
	"context"
	"testing"

	"github.com/google/uuid"

	trafficv1 "gitlab.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/decode"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
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
		Label:      "test",
		SourceKind: trafficv1.SourceKind_SOURCE_KIND_GENERIC,
		Status:     trafficv1.SessionStatus_SESSION_STATUS_DECODING,
		PcapBytes:  123,
	}); err != nil {
		t.Fatalf("create session: %v", err)
	}

	aid := uuid.NewString()
	if err := st.CreateAnalysis(ctx, NewAnalysis{ID: aid, SessionID: sid, Engine: "tshark", TLSKeyLogUsed: true}); err != nil {
		t.Fatalf("create analysis: %v", err)
	}

	flows := []*decode.Flow{{
		FrameNumber: 7, TSUnixMicros: 1700000000000000,
		Method: "GET", Scheme: "https", Authority: "example.com", Path: "/a", Query: "x=1",
		Protocol: "HTTP/2", Status: 200, TLSDecrypted: true, TCPStream: "3", H2StreamID: "1",
		RequestHeaders:  []decode.Header{{Name: "user-agent", Value: "probe"}, {Name: "content-type", Value: "application/json"}},
		ResponseHeaders: []decode.Header{{Name: "content-type", Value: "text/html"}},
		RequestBody:     []byte(`{"q":1}`),
		ResponseBody:    []byte("<html>hi</html>"),
		Metadata:        map[string]string{"proxy_provider": "acme", "pool": "residential"},
	}}
	n, err := st.InsertFlows(ctx, sid, aid, flows)
	if err != nil || n != 1 {
		t.Fatalf("insert flows: n=%d err=%v", n, err)
	}

	if err := st.FinishSession(ctx, sid, trafficv1.SessionStatus_SESSION_STATUS_CLOSED, n); err != nil {
		t.Fatalf("finish session: %v", err)
	}

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
	if got.ClosedAtUnixMs == 0 {
		t.Fatal("closed_at not set")
	}

	listed, err := st.ListFlows(ctx, sid)
	if err != nil || len(listed) != 1 {
		t.Fatalf("list flows: n=%d err=%v", len(listed), err)
	}
	if listed[0].Authority != "example.com" || listed[0].Status != 200 {
		t.Fatalf("flow mismatch: %+v", listed[0])
	}
	if listed[0].Metadata["proxy_provider"] != "acme" || listed[0].Metadata["pool"] != "residential" {
		t.Fatalf("list flow metadata: %+v", listed[0].Metadata)
	}

	full, err := st.GetFlow(ctx, sid, listed[0].Id)
	if err != nil {
		t.Fatalf("get flow: %v", err)
	}
	if len(full.RequestHeaders) != 2 || full.RequestHeaders[0].Name != "user-agent" {
		t.Fatalf("request headers: %+v", full.RequestHeaders)
	}
	if len(full.ResponseHeaders) != 1 || full.ResponseHeaders[0].Value != "text/html" {
		t.Fatalf("response headers: %+v", full.ResponseHeaders)
	}
	if len(full.Metadata) != 2 || full.Metadata["proxy_provider"] != "acme" {
		t.Fatalf("get flow metadata: %+v", full.Metadata)
	}

	if _, err := st.GetFlow(ctx, sid, uuid.NewString()); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	// Bodies: GetFlow inlines them; GetBodyBytes streams the raw content.
	if full.ResponseBody.GetSize() != 15 || string(full.ResponseBody.GetInline()) != "<html>hi</html>" {
		t.Fatalf("response body: %+v", full.ResponseBody)
	}
	if full.RequestBody.GetContentType() != "application/json" || string(full.RequestBody.GetInline()) != `{"q":1}` {
		t.Fatalf("request body: %+v", full.RequestBody)
	}
	rb, ct, err := st.GetBodyBytes(ctx, sid, listed[0].Id, true)
	if err != nil || string(rb) != "<html>hi</html>" || ct != "text/html" {
		t.Fatalf("GetBodyBytes resp: b=%q ct=%q err=%v", rb, ct, err)
	}
}

// TestLargeBodySpill covers the >InlineBlobMax path: body stored as a file,
// GetFlow returns an object_ref (not inline), and GetBody returns the full bytes.
func TestLargeBodySpill(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	sid := uuid.NewString()
	if err := st.CreateSession(ctx, NewSession{ID: sid, SourceKind: trafficv1.SourceKind_SOURCE_KIND_GENERIC, Status: trafficv1.SessionStatus_SESSION_STATUS_DECODING}); err != nil {
		t.Fatal(err)
	}
	aid := uuid.NewString()
	if err := st.CreateAnalysis(ctx, NewAnalysis{ID: aid, SessionID: sid, Engine: "tshark"}); err != nil {
		t.Fatal(err)
	}

	big := make([]byte, InlineBlobMax+1024)
	for i := range big {
		big[i] = byte(i)
	}
	flows := []*decode.Flow{{Method: "POST", Authority: "x", Path: "/big", Protocol: "HTTP/2",
		ResponseHeaders: []decode.Header{{Name: "content-type", Value: "application/octet-stream"}},
		ResponseBody:    big}}
	if _, err := st.InsertFlows(ctx, sid, aid, flows); err != nil {
		t.Fatal(err)
	}
	listed, _ := st.ListFlows(ctx, sid)

	full, err := st.GetFlow(ctx, sid, listed[0].Id)
	if err != nil {
		t.Fatal(err)
	}
	if full.ResponseBody.GetSize() != uint64(len(big)) {
		t.Fatalf("size = %d", full.ResponseBody.GetSize())
	}
	if full.ResponseBody.GetObjectRef() == "" {
		t.Fatalf("large body should be an object_ref, got %+v", full.ResponseBody)
	}
	if len(full.ResponseBody.GetInline()) != 0 {
		t.Fatal("large body must not be inlined in GetFlow")
	}
	got, _, err := st.GetBodyBytes(ctx, sid, listed[0].Id, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(big) || got[1024] != big[1024] {
		t.Fatalf("GetBodyBytes returned %d bytes", len(got))
	}
}

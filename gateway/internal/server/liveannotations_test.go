package server

import (
	"context"
	"testing"

	"github.com/google/uuid"

	trafficv1 "gitlab.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/decode"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/store"
)

// TestGetLiveRecordAnnotations checks that GetFlow / GetMessage surface annotations set on a
// still-open session's records — which live only in the hub (unpersisted) but whose
// annotations already live in the bundle DB. Without the live fallback these reads return
// NotFound, so a comment set during capture wouldn't show until the session was reopened.
func TestGetLiveRecordAnnotations(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)

	sid := uuid.NewString()
	if err := st.CreateSession(ctx, store.NewSession{
		ID: sid, Label: "live", SourceKind: trafficv1.SourceKind_SOURCE_KIND_GENERIC,
		Status: trafficv1.SessionStatus_SESSION_STATUS_OPEN, PcapBytes: 1,
	}); err != nil {
		t.Fatal(err)
	}

	// A live session whose flow + message exist only in the hub (not yet persisted).
	hub := newLiveHub(true)
	ls := &liveSession{
		flows:   map[string]*trafficv1.Flow{},
		dflows:  map[string]*decode.Flow{},
		subs:    map[int]chan *trafficv1.FlowEvent{},
		msgSubs: map[int]chan *trafficv1.WsMessage{},
	}
	hub.sessions[sid] = ls

	fid := uuid.NewString()
	ls.publish(&trafficv1.Flow{Id: fid, Authority: "example.com", Method: "GET"}, true)
	mid := uuid.NewString()
	ls.publishMessage(&trafficv1.WsMessage{Id: mid, FlowId: fid, Opcode: "text"})

	// Annotate both while the session is still open (comment persists to the bundle DB).
	if _, err := st.AddComment(ctx, sid, fid, "suspicious"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddComment(ctx, sid, mid, "look here"); err != nil {
		t.Fatal(err)
	}

	v := NewViewer(st, hub)

	f, err := v.GetFlow(ctx, &trafficv1.GetFlowRequest{SessionId: sid, FlowId: fid})
	if err != nil {
		t.Fatalf("GetFlow (live): %v", err)
	}
	if len(f.GetComments()) != 1 || f.GetComments()[0].GetBody() != "suspicious" {
		t.Fatalf("live flow comments = %+v, want one 'suspicious'", f.GetComments())
	}

	m, err := v.GetMessage(ctx, &trafficv1.GetMessageRequest{SessionId: sid, MessageId: mid})
	if err != nil {
		t.Fatalf("GetMessage (live): %v", err)
	}
	if len(m.GetComments()) != 1 || m.GetComments()[0].GetBody() != "look here" {
		t.Fatalf("live message comments = %+v, want one 'look here'", m.GetComments())
	}

	// The reads work on a clone of the hub proto, so re-reading must not accumulate
	// duplicate annotations onto the shared live record.
	f2, err := v.GetFlow(ctx, &trafficv1.GetFlowRequest{SessionId: sid, FlowId: fid})
	if err != nil {
		t.Fatal(err)
	}
	if len(f2.GetComments()) != 1 {
		t.Fatalf("second GetFlow comments = %d, want 1 (no accumulation)", len(f2.GetComments()))
	}
}

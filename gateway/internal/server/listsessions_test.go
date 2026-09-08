package server

import (
	"context"
	"testing"

	"github.com/google/uuid"

	trafficv1 "gitlab.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/store"
)

// sessionByID finds a session in a ListSessions result.
func sessionByID(list *trafficv1.SessionList, id string) *trafficv1.Session {
	for _, s := range list.GetSessions() {
		if s.GetId() == id {
			return s
		}
	}
	return nil
}

// TestListSessionsLiveFlowCount checks an open (pushed) session reports the live hub's
// running flow count — the catalog flow_count is only written on close, so without this
// the count would stay 0 until the session closes (the mitmproxy symptom).
func TestListSessionsLiveFlowCount(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)

	hub := newLiveHub(false)
	ing := &Ingest{st: st, hub: hub}
	viewer := NewViewer(st, hub)

	// Open a mitmproxy session (status OPEN, passive live session registered).
	handle, err := ing.OpenSession(ctx, &trafficv1.OpenSessionRequest{
		Label: "mitm", Source: "mitmproxy",
		Shape: trafficv1.SourceShape_SOURCE_SHAPE_FLOWS,
	})
	if err != nil {
		t.Fatal(err)
	}
	sid := handle.GetSessionId()

	// Before any flow: open session, count 0.
	list, err := viewer.ListSessions(ctx, &trafficv1.ListSessionsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if s := sessionByID(list, sid); s == nil || s.GetFlowCount() != 0 {
		t.Fatalf("initial: %+v", s)
	}

	// Push two flows across two batches — the count must reflect them while still open.
	push := func(flows ...*trafficv1.Flow) {
		if err := ing.PushFlows(&fakePushStream{ctx: ctx, batches: []*trafficv1.FlowBatch{
			{SessionId: sid, Flows: flows},
		}}); err != nil {
			t.Fatalf("PushFlows: %v", err)
		}
	}
	push(&trafficv1.Flow{Id: uuid.NewString(), Protocol: "HTTP/1.1", Authority: "a.test"})
	push(&trafficv1.Flow{Id: uuid.NewString(), Protocol: "HTTP/1.1", Authority: "b.test"})

	list, err = viewer.ListSessions(ctx, &trafficv1.ListSessionsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	s := sessionByID(list, sid)
	if s == nil {
		t.Fatal("session missing from list")
	}
	if s.GetStatus() != trafficv1.SessionStatus_SESSION_STATUS_OPEN {
		t.Fatalf("status = %v, want OPEN", s.GetStatus())
	}
	if s.GetFlowCount() != 2 {
		t.Fatalf("live flow_count = %d, want 2", s.GetFlowCount())
	}
}

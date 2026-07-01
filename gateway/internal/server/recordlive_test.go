package server

import (
	"context"
	"testing"

	"github.com/google/uuid"

	trafficv1 "gitlab.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/store"
)

// TestPersistLive checks that a record-live session's accumulated flows + WebSocket
// messages are persisted as a "live" analysis on close (no batch tshark pass involved).
func TestPersistLive(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)

	sid := uuid.NewString()
	if err := st.CreateSession(ctx, store.NewSession{
		ID: sid, Label: "rec", SourceKind: trafficv1.SourceKind_SOURCE_KIND_GENERIC,
		Status: trafficv1.SessionStatus_SESSION_STATUS_DECODING, PcapBytes: 10,
	}); err != nil {
		t.Fatal(err)
	}

	// Build a live session with two flows (one updated: request then response) and a WS frame.
	ls := &liveSession{
		flows:   map[string]*trafficv1.Flow{},
		subs:    map[int]chan *trafficv1.FlowEvent{},
		msgSubs: map[int]chan *trafficv1.WsMessage{},
	}
	f1 := uuid.NewString()
	ls.publish(&trafficv1.Flow{Id: f1, Authority: "example.com", Method: "GET", Protocol: "HTTP/2"}, true)
	ls.publish(&trafficv1.Flow{Id: f1, Authority: "example.com", Method: "GET", Protocol: "HTTP/2", Status: 200}, false)
	f2 := uuid.NewString()
	ls.publish(&trafficv1.Flow{Id: f2, Authority: "ws.example.com", Protocol: "HTTP/1.1", Websocket: true}, true)
	ls.publishMessage(&trafficv1.WsMessage{
		Id: uuid.NewString(), FlowId: f2, Opcode: "text",
		Payload: &trafficv1.Body{Size: 2, Content: &trafficv1.Body_Inline{Inline: []byte("hi")}},
	})

	ing := &Ingest{st: st, recordLive: true}
	if err := ing.persistLive(ctx, sid, ls); err != nil {
		t.Fatalf("persistLive: %v", err)
	}

	flows, err := st.ListFlows(ctx, sid)
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 2 {
		t.Fatalf("persisted %d flows, want 2", len(flows))
	}
	byID := map[string]*trafficv1.Flow{}
	for _, f := range flows {
		byID[f.Id] = f
	}
	if byID[f1].GetStatus() != 200 { // the response update must be the persisted state
		t.Errorf("flow1 status = %d, want 200", byID[f1].GetStatus())
	}
	if !byID[f2].GetWebsocket() {
		t.Errorf("flow2 should be a websocket flow")
	}

	msgs, err := st.ListMessages(ctx, sid, f2)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 || msgs[0].GetOpcode() != "text" {
		t.Fatalf("persisted messages = %+v, want 1 text frame", msgs)
	}

	sess, err := st.GetSession(ctx, sid)
	if err != nil {
		t.Fatal(err)
	}
	if sess.GetStatus() != trafficv1.SessionStatus_SESSION_STATUS_CLOSED {
		t.Errorf("session status = %v, want CLOSED", sess.GetStatus())
	}
}

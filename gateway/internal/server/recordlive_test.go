package server

import (
	"bytes"
	"context"
	"testing"

	"github.com/google/uuid"

	trafficv1 "gitlab.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/decode"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/store"
)

// TestPersistLiveFullBodies checks that record-live persists the live decoder's flows —
// including a response body larger than the live preview cap — in full, plus WS messages,
// as a "live" analysis on close.
func TestPersistLiveFullBodies(t *testing.T) {
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

	ls := &liveSession{
		recordLive: true,
		flows:      map[string]*trafficv1.Flow{},
		dflows:     map[string]*decode.Flow{},
		subs:       map[int]*flowSub{},
		msgSubs:    map[int]chan *trafficv1.WsMessage{},
	}

	// A response body well past the 256 KiB live preview cap — record-live must keep it all.
	bigBody := bytes.Repeat([]byte("A"), 700<<10)
	f1 := uuid.NewString()
	flow := &decode.Flow{ID: f1, Authority: "example.com", Method: "GET", Protocol: "HTTP/2"}
	ls.onFlow(flow, true)       // request seen
	flow.Status = 200           // same pointer, updated in place
	flow.ResponseBody = bigBody // response arrives
	ls.onFlow(flow, false)      // response completes

	f2 := uuid.NewString()
	ls.onFlow(&decode.Flow{ID: f2, Authority: "ws.example.com", Protocol: "HTTP/1.1", Websocket: true}, true)
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

	// The big response body must be stored in full (not truncated to the preview cap).
	body, _, err := st.GetBodyBytes(ctx, sid, f1, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != len(bigBody) {
		t.Fatalf("persisted body = %d bytes, want %d (full)", len(body), len(bigBody))
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

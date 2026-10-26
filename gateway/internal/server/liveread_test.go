package server

import (
	"bytes"
	"context"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	trafficv1 "github.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"github.com/nklyshko/traffic-deck/gateway/internal/decode"
	"github.com/nklyshko/traffic-deck/gateway/internal/store"
)

// fakeFlowStream is a minimal grpc.ServerStreamingServer[FlowEvent] collecting sent events.
type fakeFlowStream struct {
	ctx    context.Context
	events []*trafficv1.FlowEvent
}

func (f *fakeFlowStream) Send(e *trafficv1.FlowEvent) error {
	f.events = append(f.events, e)
	return nil
}
func (f *fakeFlowStream) Context() context.Context     { return f.ctx }
func (f *fakeFlowStream) SetHeader(metadata.MD) error  { return nil }
func (f *fakeFlowStream) SendHeader(metadata.MD) error { return nil }
func (f *fakeFlowStream) SetTrailer(metadata.MD)       {}
func (f *fakeFlowStream) SendMsg(any) error            { return nil }
func (f *fakeFlowStream) RecvMsg(any) error            { return nil }

// fakeBodyStream is a minimal grpc.ServerStreamingServer[BodyChunk] accumulating payloads.
type fakeBodyStream struct {
	ctx  context.Context
	data []byte
}

func (f *fakeBodyStream) Send(c *trafficv1.BodyChunk) error {
	f.data = append(f.data, c.GetPayload()...)
	return nil
}
func (f *fakeBodyStream) Context() context.Context     { return f.ctx }
func (f *fakeBodyStream) SetHeader(metadata.MD) error  { return nil }
func (f *fakeBodyStream) SendHeader(metadata.MD) error { return nil }
func (f *fakeBodyStream) SetTrailer(metadata.MD)       {}
func (f *fakeBodyStream) SendMsg(any) error            { return nil }
func (f *fakeBodyStream) RecvMsg(any) error            { return nil }

// addedFlows returns the flows carried by flow_added events, in order.
func addedFlows(evs []*trafficv1.FlowEvent) []*trafficv1.Flow {
	var out []*trafficv1.Flow
	for _, ev := range evs {
		if f := ev.GetFlowAdded(); f != nil {
			out = append(out, f)
		}
	}
	return out
}

// liveFixture opens a store with one OPEN session registered in a live hub.
func liveFixture(t *testing.T) (*store.Store, *liveHub, *liveSession, string) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)

	sid := uuid.NewString()
	if err := st.CreateSession(ctx, store.NewSession{
		ID: sid, Label: "live", Source: "import",
		Status: trafficv1.SessionStatus_SESSION_STATUS_OPEN, PcapBytes: 1,
	}); err != nil {
		t.Fatal(err)
	}

	hub := newLiveHub()
	ls := &liveSession{
		flows:   map[string]*trafficv1.Flow{},
		dflows:  map[string]*decode.Flow{},
		subs:    map[int]*flowSub{},
		msgSubs: map[int]chan *trafficv1.WsMessage{},
	}
	hub.sessions[sid] = ls
	return st, hub, ls, sid
}

// TestStreamFlowsLiveNoFollow checks that a non-following StreamFlows serves an open
// session's unpersisted flows (with their annotations) instead of an empty backfill —

// TestStreamFlowsLiveNoDuplicates checks the pushed (mitmproxy) path, where flows are

// TestListMessagesLive checks that an open session's WebSocket timeline — frames that live
// only in the hub until close — is served by ListMessages, with annotations attached.
func TestListMessagesLive(t *testing.T) {
	ctx := context.Background()
	st, hub, ls, sid := liveFixture(t)

	fid, other := uuid.NewString(), uuid.NewString()
	mid := uuid.NewString()
	ls.publish(&trafficv1.Flow{Id: fid, Authority: "ws.example.com", Websocket: true}, true)
	ls.publishMessage(&trafficv1.WsMessage{
		Id: mid, FlowId: fid, Opcode: "text",
		Payload: &trafficv1.Body{Size: 2, Content: &trafficv1.Body_Inline{Inline: []byte("hi")}},
	})
	ls.publishMessage(&trafficv1.WsMessage{Id: uuid.NewString(), FlowId: other, Opcode: "text"})
	if _, err := st.AddComment(ctx, sid, mid, "look here"); err != nil {
		t.Fatal(err)
	}

	resp, err := NewViewer(st, hub).ListMessages(ctx, &trafficv1.ListMessagesRequest{SessionId: sid, FlowId: fid})
	if err != nil {
		t.Fatalf("ListMessages: %v", err)
	}
	msgs := resp.GetMessages()
	if len(msgs) != 1 || msgs[0].GetId() != mid {
		t.Fatalf("live messages = %+v, want only flow %s's frame", msgs, fid)
	}
	if len(msgs[0].GetComments()) != 1 || msgs[0].GetComments()[0].GetBody() != "look here" {
		t.Errorf("live message comments = %+v, want one 'look here'", msgs[0].GetComments())
	}
}

// TestGetBodyLive covers the live-body outcomes: a body the hub retained is served
// whole; a flow that carries none of its body, and one with no body at all, are NotFound.
func TestGetBodyLive(t *testing.T) {
	ctx := context.Background()
	st, hub, ls, sid := liveFixture(t)

	// The hub retains the full decode flow, so even a body past the inline cap is
	// served whole.
	big := bytes.Repeat([]byte("A"), 2<<20)
	recorded := uuid.NewString()
	ls.onFlow(&decode.Flow{ID: recorded, Authority: "example.com", Method: "GET", ResponseBody: big}, true)

	// A flow that knows its body's size but carries none of the bytes: there is nothing
	// to serve, and an empty stream would read as a body that is empty.
	none := uuid.NewString()
	ls.publish(&trafficv1.Flow{
		Id: none, Authority: "example.com", Method: "GET",
		ResponseBody: &trafficv1.Body{Size: 900 << 10},
	}, true)

	// A flow with no response body at all.
	empty := uuid.NewString()
	ls.publish(&trafficv1.Flow{Id: empty, Authority: "example.com", Method: "GET"}, true)

	v := NewViewer(st, hub)
	get := func(fid string) (*fakeBodyStream, error) {
		srv := &fakeBodyStream{ctx: ctx}
		return srv, v.GetBody(&trafficv1.GetBodyRequest{SessionId: sid, FlowId: fid, Response: true}, srv)
	}

	srv, err := get(recorded)
	if err != nil {
		t.Fatalf("GetBody (live, retained): %v", err)
	}
	if !bytes.Equal(srv.data, big) {
		t.Fatalf("retained body = %d bytes, want %d whole", len(srv.data), len(big))
	}

	if _, err := get(none); status.Code(err) != codes.NotFound {
		t.Fatalf("GetBody (live, no bytes held) = %v, want NotFound", err)
	}

	if _, err := get(empty); status.Code(err) != codes.NotFound {
		t.Fatalf("GetBody (live, body-less) = %v, want NotFound", err)
	}
}

// TestGetMessageBodyLive checks that a live frame's payload and its original undecoded
// bytes are both readable before the session closes.
func TestGetMessageBodyLive(t *testing.T) {
	ctx := context.Background()
	st, hub, ls, sid := liveFixture(t)

	mid := uuid.NewString()
	ls.publishMessage(&trafficv1.WsMessage{
		Id: mid, FlowId: uuid.NewString(), Opcode: "text",
		Payload: &trafficv1.Body{Size: 7, Content: &trafficv1.Body_Inline{Inline: []byte("decoded")}},
		Raw:     &trafficv1.Body{Size: 3, Content: &trafficv1.Body_Inline{Inline: []byte("raw")}},
	})

	v := NewViewer(st, hub)
	for _, tc := range []struct {
		name string
		raw  bool
		want string
	}{
		{"payload", false, "decoded"},
		{"raw", true, "raw"},
	} {
		srv := &fakeBodyStream{ctx: ctx}
		if err := v.GetMessageBody(&trafficv1.GetMessageBodyRequest{
			SessionId: sid, MessageId: mid, Raw: tc.raw,
		}, srv); err != nil {
			t.Fatalf("GetMessageBody (%s): %v", tc.name, err)
		}
		if string(srv.data) != tc.want {
			t.Errorf("GetMessageBody (%s) = %q, want %q", tc.name, srv.data, tc.want)
		}
	}

	err := v.GetMessageBody(&trafficv1.GetMessageBodyRequest{
		SessionId: sid, MessageId: uuid.NewString(),
	}, &fakeBodyStream{ctx: ctx})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("GetMessageBody (unknown id) = %v, want NotFound", err)
	}
}

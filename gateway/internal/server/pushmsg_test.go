package server

import (
	"context"
	"io"
	"testing"

	"google.golang.org/grpc/metadata"

	"github.com/google/uuid"

	"gitlab.com/nklyshko/traffic-deck/gateway/decoders"
	trafficv1 "gitlab.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
	"gitlab.com/nklyshko/traffic-deck/gateway/internal/store"
)

// pushWSDecoder is a WSDecoder claiming only the test host, so it can't affect other tests.
type pushWSDecoder struct{}

func (pushWSDecoder) Name() string                     { return "pushws-test" }
func (pushWSDecoder) MatchesWS(m decoders.WSMeta) bool { return m.Host == "ws.custom.test" }
func (pushWSDecoder) NewSession() decoders.Session     { return pushWSSession{} }

type pushWSSession struct{}

func (pushWSSession) Feed(fromClient bool, data []byte) []decoders.Message {
	return []decoders.Message{{FromClient: fromClient, Opcode: "decoded", Payload: append([]byte("D:"), data...)}}
}

// fakePushStream is a minimal grpc.ClientStreamingServer[FlowBatch, PushAck] that replays
// a fixed set of batches, then EOF.
type fakePushStream struct {
	ctx     context.Context
	batches []*trafficv1.FlowBatch
	i       int
	ack     *trafficv1.PushAck
}

func (f *fakePushStream) Recv() (*trafficv1.FlowBatch, error) {
	if f.i >= len(f.batches) {
		return nil, io.EOF
	}
	b := f.batches[f.i]
	f.i++
	return b, nil
}
func (f *fakePushStream) SendAndClose(a *trafficv1.PushAck) error { f.ack = a; return nil }
func (f *fakePushStream) Context() context.Context                { return f.ctx }
func (f *fakePushStream) SetHeader(metadata.MD) error             { return nil }
func (f *fakePushStream) SendHeader(metadata.MD) error            { return nil }
func (f *fakePushStream) SetTrailer(metadata.MD)                  {}
func (f *fakePushStream) SendMsg(any) error                       { return nil }
func (f *fakePushStream) RecvMsg(any) error                       { return nil }

// TestPushFlowsWithMessages checks the mitmproxy push path persists WebSocket/raw-TCP
// messages carried alongside their parent flow (all connection types).
func TestPushFlowsWithMessages(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)

	sid := uuid.NewString()
	if err := st.CreateSession(ctx, store.NewSession{
		ID: sid, SourceKind: trafficv1.SourceKind_SOURCE_KIND_MITMPROXY,
		Status: trafficv1.SessionStatus_SESSION_STATUS_DECODING,
	}); err != nil {
		t.Fatal(err)
	}

	fid := uuid.NewString()
	ing := &Ingest{st: st, hub: newLiveHub(false)}
	stream := &fakePushStream{
		ctx: ctx,
		batches: []*trafficv1.FlowBatch{
			// Batch 1: the WebSocket upgrade flow.
			{SessionId: sid, Flows: []*trafficv1.Flow{
				{Id: fid, Protocol: "HTTP/1.1", Authority: "ws.example.com", Websocket: true},
			}},
			// Batch 2: two frames on that flow (client binary, server binary).
			{SessionId: sid, Messages: []*trafficv1.WsMessage{
				{Id: uuid.NewString(), FlowId: fid, FromClient: true, Opcode: "binary",
					Payload: &trafficv1.Body{Size: 3, Content: &trafficv1.Body_Inline{Inline: []byte("req")}}},
				{Id: uuid.NewString(), FlowId: fid, FromClient: false, Opcode: "binary",
					Payload: &trafficv1.Body{Size: 4, Content: &trafficv1.Body_Inline{Inline: []byte("resp")}}},
			}},
		},
	}

	if err := ing.PushFlows(stream); err != nil {
		t.Fatalf("PushFlows: %v", err)
	}
	if stream.ack.GetAccepted() != 3 { // 1 flow + 2 messages
		t.Errorf("accepted = %d, want 3", stream.ack.GetAccepted())
	}

	msgs, err := st.ListMessages(ctx, sid, fid)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 {
		t.Fatalf("persisted %d messages, want 2", len(msgs))
	}
	if string(msgs[0].GetPayload().GetInline()) != "req" || !msgs[0].GetFromClient() {
		t.Errorf("msg0 = %+v", msgs[0])
	}
	if string(msgs[1].GetPayload().GetInline()) != "resp" || msgs[1].GetFromClient() {
		t.Errorf("msg1 = %+v", msgs[1])
	}
}

// TestPushFlowsCustomWSDecode checks a registered WSDecoder reframes pushed binary frames,
// storing the decoded payload with the original bytes in raw.
func TestPushFlowsCustomWSDecode(t *testing.T) {
	decoders.RegisterWS(pushWSDecoder{})
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)

	sid := uuid.NewString()
	if err := st.CreateSession(ctx, store.NewSession{
		ID: sid, SourceKind: trafficv1.SourceKind_SOURCE_KIND_MITMPROXY,
		Status: trafficv1.SessionStatus_SESSION_STATUS_DECODING,
	}); err != nil {
		t.Fatal(err)
	}

	fid := uuid.NewString()
	ing := &Ingest{st: st, hub: newLiveHub(false)}
	stream := &fakePushStream{ctx: ctx, batches: []*trafficv1.FlowBatch{
		{SessionId: sid, Flows: []*trafficv1.Flow{
			{Id: fid, Protocol: "HTTP/1.1", Authority: "ws.custom.test", Websocket: true},
		}},
		{SessionId: sid, Messages: []*trafficv1.WsMessage{
			{Id: uuid.NewString(), FlowId: fid, FromClient: true, Opcode: "binary",
				Payload: &trafficv1.Body{Size: 5, Content: &trafficv1.Body_Inline{Inline: []byte("hello")}}},
		}},
	}}
	if err := ing.PushFlows(stream); err != nil {
		t.Fatal(err)
	}

	msgs, err := st.ListMessages(ctx, sid, fid)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("got %d messages, want 1 (decoded): %+v", len(msgs), msgs)
	}
	if msgs[0].GetOpcode() != "decoded" || string(msgs[0].GetPayload().GetInline()) != "D:hello" {
		t.Errorf("decoded message = %+v", msgs[0])
	}
	if string(msgs[0].GetRaw().GetInline()) != "hello" {
		t.Errorf("raw original bytes = %q, want hello", msgs[0].GetRaw().GetInline())
	}
}
